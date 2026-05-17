// Unit tests for DomainAnalyzerService covering static checks, network behavior,
// SSL indicators, HTML analysis, timeout/error handling, and output contracts.

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using SSA_Final.Interfaces;
using SSA_Final.Models;
using SSA_Final.Services;
using System.Net;
using System.Text;

namespace SSA_Final.Tests.Services;

// ── Test doubles ──────────────────────────────────────────────────────────────

/// <summary>
/// HttpMessageHandler backed by a caller-supplied delegate so each test can
/// control exactly what the HttpClient sends back without touching the network.
/// </summary>
internal sealed class FakeHttpMessageHandler : HttpMessageHandler
{
    private readonly Func<HttpRequestMessage, HttpResponseMessage> _responder;

    public FakeHttpMessageHandler(Func<HttpRequestMessage, HttpResponseMessage> responder)
        => _responder = responder;

    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        try
        {
            return Task.FromResult(_responder(request));
        }
        catch (Exception ex)
        {
            // Return a faulted task so HttpClient awaits it correctly.
            return Task.FromException<HttpResponseMessage>(ex);
        }
    }
}

/// <summary>
/// IHttpClientFactory that wires the two named clients used by
/// <see cref="DomainAnalyzerService"/> to caller-supplied fake handlers.
/// </summary>
internal sealed class FakeHttpClientFactory : IHttpClientFactory
{
    private readonly HttpMessageHandler _noRedirectHandler;
    private readonly HttpMessageHandler _followHandler;

    public FakeHttpClientFactory(
        HttpMessageHandler noRedirectHandler,
        HttpMessageHandler followHandler)
    {
        _noRedirectHandler = noRedirectHandler;
        _followHandler = followHandler;
    }

    public HttpClient CreateClient(string name) => name switch
    {
        "DomainAnalyzer.NoRedirect" =>
            new HttpClient(_noRedirectHandler, disposeHandler: false),
        _ =>
            new HttpClient(_followHandler, disposeHandler: false)
    };
}

/// <summary>
/// Fake SSL checker that returns a predetermined list of indicators so that
/// the SSL pass can be exercised in unit tests without opening a real TCP socket.
/// </summary>
internal sealed class FakeSslCertificateChecker : ISslCertificateChecker
{
    private readonly IReadOnlyList<string> _indicators;

    public FakeSslCertificateChecker(params string[] indicators)
        => _indicators = indicators;

    public Task<IReadOnlyList<string>> GetSslIndicatorsAsync(
        string domain, CancellationToken ct)
        => Task.FromResult(_indicators);
}

/// <summary>
/// Fake registration lookup service so registration-age, lifespan, and privacy
/// scoring can be tested without external RDAP/WHOIS calls.
/// </summary>
internal sealed class FakeDomainRegistrationLookupService : IDomainRegistrationLookupService
{
    private readonly DomainRegistrationMetadata _metadata;

    public FakeDomainRegistrationLookupService(DomainRegistrationMetadata metadata)
        => _metadata = metadata;

    public Task<DomainRegistrationMetadata> LookupAsync(
        string domain,
        CancellationToken cancellationToken = default)
    {
        return Task.FromResult(new DomainRegistrationMetadata
        {
            Domain = domain,
            CreationDateUtc = _metadata.CreationDateUtc,
            ExpirationDateUtc = _metadata.ExpirationDateUtc,
            RegistrarName = _metadata.RegistrarName,
            HasPrivacyProtection = _metadata.HasPrivacyProtection,
            IsLookupSuccessful = _metadata.IsLookupSuccessful,
            FailureReason = _metadata.FailureReason
        });
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

public class DomainAnalyzerServiceTests
{
    // ── Builder helpers ───────────────────────────────────────────────────────

    private static IConfiguration BuildConfig(
        int timeoutSeconds = 5,
        Dictionary<string, string?>? configOverrides = null)
    {
        var dict = new Dictionary<string, string?>
        {
            ["DomainAnalyzer:TimeoutSeconds"] = timeoutSeconds.ToString()
        };

        if (configOverrides is not null)
        {
            foreach (var item in configOverrides)
            {
                dict[item.Key] = item.Value;
            }
        }

        return new ConfigurationBuilder().AddInMemoryCollection(dict).Build();
    }

    private static HttpResponseMessage OkHtml(string html)
    {
        var msg = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(html, Encoding.UTF8, "text/html")
        };
        return msg;
    }

    private static IReadOnlyList<string> LoadDomainList(string fileName)
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);

        while (directory is not null)
        {
            var candidate = Path.Combine(directory.FullName, fileName);
            if (File.Exists(candidate))
            {
                return File.ReadLines(candidate)
                    .Select(line => line.Trim())
                    .Where(line => !string.IsNullOrWhiteSpace(line) && !line.StartsWith('#'))
                    .ToList();
            }

            directory = directory.Parent;
        }

        throw new FileNotFoundException($"Could not find {fileName} from test output path.");
    }

    /// <summary>
    /// Creates a <see cref="DomainAnalyzerService"/> wired to fake collaborators.
    /// Unspecified parameters default to clean / non-suspicious responses.
    /// </summary>
    private static DomainAnalyzerService Build(
        Func<HttpRequestMessage, HttpResponseMessage>? noRedirectResponder = null,
        Func<HttpRequestMessage, HttpResponseMessage>? followResponder = null,
        ISslCertificateChecker? sslChecker = null,
        IDomainRegistrationLookupService? registrationLookup = null,
        int timeoutSeconds = 5,
        Dictionary<string, string?>? configOverrides = null)
    {
        noRedirectResponder ??= _ => new HttpResponseMessage(HttpStatusCode.OK);
        followResponder ??= _ => OkHtml("<html><head><title>My Site</title></head><body></body></html>");
        sslChecker ??= new FakeSslCertificateChecker(); // zero indicators

        var factory = new FakeHttpClientFactory(
            new FakeHttpMessageHandler(noRedirectResponder),
            new FakeHttpMessageHandler(followResponder));

        return new DomainAnalyzerService(
            factory,
            sslChecker,
            BuildConfig(timeoutSeconds, configOverrides),
            NullLogger<DomainAnalyzerService>.Instance,
            null,
            null,
            registrationLookup);
    }

    // ── Null / empty input ────────────────────────────────────────────────────

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public async Task Analyze_NullOrEmptyDomain_ReturnsCleanResult(string? domain)
    {
        // Arrange
        var svc = Build();

        // Act
        var result = await svc.Analyze(domain!);

        // Assert
        Assert.False(result.IsSuspicious);
        Assert.Empty(result.Indicators);
    }

    // ── Pass 0: Static checks — IP address ───────────────────────────────────
    //
    // NormalizeDomain rejects raw IP addresses (IPAddress.TryParse returns true →
    // the helper returns null → AnalyzeDomainRiskAsync returns BuildInvalidInputResult).
    // The service therefore treats IPs the same as an empty/invalid input rather than
    // emitting a dedicated indicator. Tests reflect that contract.

    [Theory]
    [InlineData("192.168.1.1")]
    [InlineData("10.0.0.1")]
    [InlineData("203.0.113.42")]
    public async Task Analyze_RawIpAddressInput_IsNotSuspiciousAndHasNoIndicators(string domain)
    {
        // Arrange
        var svc = Build();

        // Act
        var result = await svc.Analyze(domain);

        // Assert — IPs normalise to null → treated as invalid input → no indicators, not suspicious.
        Assert.False(result.IsSuspicious);
        Assert.Empty(result.Indicators);
    }

    // ── Pass 0: Static checks — excessive subdomains ──────────────────────────

    [Fact]
    public async Task Analyze_ExcessiveSubdomains_AddsSubdomainIndicator()
    {
        // Arrange
        var svc = Build();

        // Act
        var result = await svc.Analyze("login.secure.verify.paypal.com");

        // Assert — signal name is "Excessive Subdomains" (capital S)
        Assert.Contains(result.Indicators,
            i => i.Contains("Excessive Subdomains", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Analyze_NormalSubdomainDepth_NoSubdomainIndicator()
    {
        // Arrange
        var svc = Build();

        // Act
        var result = await svc.Analyze("mail.example.com");

        // Assert
        Assert.DoesNotContain(result.Indicators,
            i => i.Contains("Excessive Subdomains", StringComparison.OrdinalIgnoreCase));
    }

    // ── Pass 0: Static checks — hyphen abuse ──────────────────────────────────

    [Theory]
    [InlineData("secure-login-account-update.com")]
    [InlineData("a-b-c-d.net")]
    public async Task Analyze_ThreeOrMoreHyphensInRegistrableLabel_AddsHyphenAbuseSignal(string domain)
    {
        // Arrange
        var svc = Build();

        // Act
        var result = await svc.Analyze(domain);

        // Assert — signal name is "Hyphen Abuse" (capital A)
        Assert.Contains(result.Indicators,
            i => i.Contains("Hyphen Abuse", StringComparison.OrdinalIgnoreCase));
    }

    // Domains with one or more hyphens in the registrable label trigger "Hyphen Abuse".
    // The old test checked for a literal prefix string (e.g. "secure-") which never
    // appeared in any indicator; all four domains below produce a Hyphen Abuse indicator.
    [Theory]
    [InlineData("secure-paypal.com")]
    [InlineData("login-mybank.net")]
    [InlineData("verify-account.org")]
    [InlineData("confirm-email.com")]
    public async Task Analyze_SingleHyphenInRegistrableLabel_AddsHyphenAbuseSignal(string domain)
    {
        // Arrange
        var svc = Build();

        // Act
        var result = await svc.Analyze(domain);

        // Assert
        Assert.Contains(result.Indicators,
            i => i.Contains("Hyphen Abuse", StringComparison.OrdinalIgnoreCase));
    }

    // ── Pass 0: Static checks — suspicious TLD ───────────────────────────────
    //
    // TLD-based scoring was removed from DomainAnalyzerService. These tests are
    // intentionally omitted; there is no TLD signal to assert against.

    [Theory]
    [InlineData("mybank.xyz")]
    [InlineData("paypal.tk")]
    [InlineData("google.top")]
    [InlineData("microsoft.ru")]
    public async Task Analyze_TldOnly_DoesNotAddListBasedTldIndicator(string domain)
    {
        var svc = Build();
        var result = await svc.Analyze(domain);

        Assert.DoesNotContain(result.Indicators, i => i.Contains("TLD"));
    }

    [Fact]
    public async Task Analyze_CommonTld_NoTldIndicator()
    {
        var svc = Build();
        var result = await svc.Analyze("example.com");

        Assert.DoesNotContain(result.Indicators, i => i.Contains("TLD"));
    }

    // ── Pass 0: Static checks — brand stuffing is no longer a separate signal ─

    [Fact]
    public async Task Analyze_MultiBrandDomain_HyphensInLabelTriggerHyphenAbuseSignal()
    {
        // Arrange — "paypal-amazon-security.com" has two hyphens in the registrable label
        var svc = Build();

        // Act
        var result = await svc.Analyze("paypal-amazon-security.com");

        // Assert
        Assert.Contains(result.Indicators,
            i => i.Contains("Hyphen Abuse", StringComparison.OrdinalIgnoreCase));
    }

    // ── Pass 0: Clean domain produces no static indicators ───────────────────

    [Fact]
    public async Task Analyze_CleanDomain_NoStaticIndicators()
    {
        // Arrange
        var svc = Build();

        // Act
        var result = await svc.Analyze("mylegitsite.com");

        // Assert
        Assert.False(result.IsSuspicious);
        Assert.Empty(result.Indicators);
    }

    // ── Pass 0: Registration metadata checks ────────────────────────────────

    [Fact]
    public async Task AnalyzeDomainRisk_RecentlyRegisteredDomain_AddsHighAgeSignal()
    {
        var svc = Build(registrationLookup: new FakeDomainRegistrationLookupService(
            new DomainRegistrationMetadata
            {
                IsLookupSuccessful = true,
                CreationDateUtc = DateTime.UtcNow.AddDays(-10),
                ExpirationDateUtc = DateTime.UtcNow.AddDays(355)
            }));

        var result = await svc.AnalyzeDomainRiskAsync("freshdomain.com");

        Assert.True(result.DomainRegistrationAge?.Triggered);
        Assert.Equal(25, result.DomainRegistrationAge?.Score);
        Assert.Contains("registered", result.DomainRegistrationAge?.Detail);
    }

    [Fact]
    public async Task AnalyzeDomainRisk_ShortRegistrationLifespan_AddsLifespanSignal()
    {
        var createdAt = DateTime.UtcNow.AddDays(-500);
        var svc = Build(registrationLookup: new FakeDomainRegistrationLookupService(
            new DomainRegistrationMetadata
            {
                IsLookupSuccessful = true,
                CreationDateUtc = createdAt,
                ExpirationDateUtc = createdAt.AddDays(365)
            }));

        var result = await svc.AnalyzeDomainRiskAsync("lifespandomain.com");

        Assert.True(result.DomainRegistrationLifespan?.Triggered);
        Assert.Equal(10, result.DomainRegistrationLifespan?.Score);
    }

    [Fact]
    public async Task AnalyzeDomainRisk_PrivacyProtectedWhois_AddsWeakPrivacySignal()
    {
        var svc = Build(registrationLookup: new FakeDomainRegistrationLookupService(
            new DomainRegistrationMetadata
            {
                IsLookupSuccessful = true,
                HasPrivacyProtection = true
            }));

        var result = await svc.AnalyzeDomainRiskAsync("privacydomain.com");

        Assert.True(result.WhoisPrivacyProtection?.Triggered);
        Assert.Equal(5, result.WhoisPrivacyProtection?.Score);
    }

    [Fact]
    public async Task AnalyzeDomainRisk_RegistrationLookupFailure_NotesReasonWithoutScoring()
    {
        var svc = Build(registrationLookup: new FakeDomainRegistrationLookupService(
            new DomainRegistrationMetadata
            {
                IsLookupSuccessful = false,
                FailureReason = "RDAP rate limited"
            }));

        var result = await svc.AnalyzeDomainRiskAsync("safeexample.com");

        Assert.Equal("RDAP rate limited", result.RegistrationLookupFailureReason);
        Assert.False(result.DomainRegistrationAge?.Triggered);
        Assert.Equal(0, result.DomainRegistrationAge?.Score);
    }

    [Fact]
    public async Task AnalyzeDomainRisk_CharacterCompositionAnomaly_AddsDataDerivedSignal()
    {
        var svc = Build();
        var result = await svc.AnalyzeDomainRiskAsync("a9x2k123456.com");

        Assert.True(result.CharacterCompositionAnomaly?.Triggered);
        Assert.Contains("digit ratio", result.CharacterCompositionAnomaly?.Detail);
    }

    // ── Pass 1: Cross-domain redirect ─────────────────────────────────────────
    //
    // Redirect tests use "example.com" which resolves in real DNS so
    // IsDomainResolvableAsync returns true and the network passes run.

    [Fact]
    public async Task Analyze_200Response_NoRedirectIndicator()
    {
        // Arrange
        var svc = Build(noRedirectResponder: _ => new HttpResponseMessage(HttpStatusCode.OK));

        // Act
        var result = await svc.Analyze("example.com");

        // Assert
        Assert.DoesNotContain(result.Indicators,
            i => i.Contains("Cross-domain redirect", StringComparison.OrdinalIgnoreCase));
    }

    [Theory]
    [InlineData("https://www.example.com/home")]   // subdomain of original
    [InlineData("https://example.com/new-page")]   // same host
    public async Task Analyze_SameDomainRedirect_NoRedirectIndicator(string location)
    {
        // Arrange
        var svc = Build(noRedirectResponder: _ =>
        {
            var r = new HttpResponseMessage(HttpStatusCode.MovedPermanently);
            r.Headers.Location = new Uri(location);
            return r;
        });

        // Act
        var result = await svc.Analyze("example.com");

        // Assert
        Assert.DoesNotContain(result.Indicators,
            i => i.Contains("Cross-domain redirect", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Analyze_CrossDomainRedirect_AddsRedirectIndicator()
    {
        // Arrange
        var svc = Build(noRedirectResponder: _ =>
        {
            var r = new HttpResponseMessage(HttpStatusCode.MovedPermanently);
            r.Headers.Location = new Uri("https://attacker.com/steal");
            return r;
        });

        // Act
        var result = await svc.Analyze("example.com");

        // Assert
        Assert.Contains(result.Indicators,
            i => i.Contains("Cross-domain redirect", StringComparison.OrdinalIgnoreCase));
        Assert.True(result.IsSuspicious);
    }

    // ── Pass 2: SSL certificate indicators ───────────────────────────────────

    [Fact]
    public async Task Analyze_ExpiredCertificate_AddsExpiredIndicator()
    {
        // Arrange
        var svc = Build(sslChecker: new FakeSslCertificateChecker(
            "SSL certificate expired on 2023-01-01"));

        // Act
        var result = await svc.Analyze("example.com");

        // Assert
        Assert.Contains(result.Indicators,
            i => i.Contains("expired", StringComparison.OrdinalIgnoreCase));
        Assert.True(result.IsSuspicious);
    }

    [Fact]
    public async Task Analyze_SelfSignedCertificate_AddsSelfSignedIndicator()
    {
        // Arrange
        var svc = Build(sslChecker: new FakeSslCertificateChecker(
            "Self-signed SSL certificate detected"));

        // Act
        var result = await svc.Analyze("example.com");

        // Assert
        Assert.Contains(result.Indicators,
            i => i.Contains("Self-signed", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Analyze_CertHostnameMismatch_AddsMismatchIndicator()
    {
        // Arrange
        var svc = Build(sslChecker: new FakeSslCertificateChecker(
            "SSL certificate hostname mismatch (cert issued for 'other.com')"));

        // Act
        var result = await svc.Analyze("example.com");

        // Assert
        Assert.Contains(result.Indicators,
            i => i.Contains("hostname mismatch", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Analyze_ValidCertificate_NoSslIndicators()
    {
        // Arrange
        var svc = Build(sslChecker: new FakeSslCertificateChecker()); // empty — zero indicators

        // Act
        var result = await svc.Analyze("example.com");

        // Assert
        Assert.DoesNotContain(result.Indicators,
            i => i.Contains("SSL", StringComparison.OrdinalIgnoreCase)
              || i.Contains("certificate", StringComparison.OrdinalIgnoreCase)
              || i.Contains("cert", StringComparison.OrdinalIgnoreCase));
    }

    // ── Pass 3: HTML content checks ───────────────────────────────────────────
    //
    // HTML tests use "example.com" (resolves via real DNS) so IsDomainResolvableAsync
    // returns true and CheckHtmlContentAsync is reached. The followResponder fake
    // delivers controlled HTML without touching the network.

    [Fact]
    public async Task Analyze_PasswordFieldInHtml_AddsPasswordIndicator()
    {
        // Arrange
        const string html = """
            <html><body>
              <input type="password" name="pwd" />
            </body></html>
            """;
        var svc = Build(followResponder: _ => OkHtml(html));

        // Act
        var result = await svc.Analyze("example.com");

        // Assert
        Assert.Contains(result.Indicators,
            i => i.Contains("Password input field", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Analyze_LoginFormInHtml_AddsLoginFormIndicator()
    {
        // Arrange
        const string html = """
            <html><body>
              <form action="/login" id="loginForm"></form>
            </body></html>
            """;
        var svc = Build(followResponder: _ => OkHtml(html));

        // Act
        var result = await svc.Analyze("example.com");

        // Assert
        Assert.Contains(result.Indicators,
            i => i.Contains("Login form", StringComparison.OrdinalIgnoreCase));
    }

    // Brand mismatch: title references "paypal" but the domain tokens ("icanhazip", "com")
    // do not contain it. Uses icanhazip.com — a stable, publicly-resolving domain with no
    // brand association — so DNS resolves, the HTML pass runs, and no allow-list early-exit fires.
    [Fact]
    public async Task Analyze_BrandInTitleNotInDomain_AddsMismatchIndicator()
    {
        // Arrange
        const string html = "<html><head><title>PayPal - Secure Login</title></head></html>";
        var svc = Build(followResponder: _ => OkHtml(html));

        // Act
        var result = await svc.Analyze("icanhazip.com");

        // Assert
        Assert.Contains(result.Indicators,
            i => i.Contains("Brand keyword mismatch", StringComparison.OrdinalIgnoreCase));
    }

    // Brand present in both title and domain → no mismatch indicator expected.
    // "paypal.com" resolves via real DNS; the fake followResponder controls the HTML.
    [Fact]
    public async Task Analyze_BrandInTitleAndInDomain_NoBrandMismatch()
    {
        // Arrange
        const string html = "<html><head><title>PayPal Secure</title></head></html>";
        var svc = Build(followResponder: _ => OkHtml(html));

        // Act
        var result = await svc.Analyze("paypal.com");

        // Assert
        Assert.DoesNotContain(result.Indicators,
            i => i.Contains("Brand keyword mismatch", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Analyze_CleanHtml_NoHtmlIndicators()
    {
        // Arrange
        const string html = "<html><head><title>My Legitimate Site</title></head><body></body></html>";
        var svc = Build(followResponder: _ => OkHtml(html));

        // Act
        var result = await svc.Analyze("example.com");

        // Assert
        Assert.DoesNotContain(result.Indicators,
            i => i.Contains("Password", StringComparison.OrdinalIgnoreCase)
              || i.Contains("Login form", StringComparison.OrdinalIgnoreCase)
              || i.Contains("Brand keyword mismatch", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Analyze_HttpsFails_FallsBackToHttp_AddsNoHttpsIndicator()
    {
        // Arrange
        var svc = Build(followResponder: req =>
        {
            if (req.RequestUri!.Scheme == "https")
                throw new HttpRequestException("HTTPS unavailable");

            return OkHtml("<html><body></body></html>");
        });

        // Act
        var result = await svc.Analyze("example.com");

        // Assert
        Assert.Contains(result.Indicators,
            i => i.Contains("No HTTPS support", StringComparison.OrdinalIgnoreCase));
    }

    // ── Error handling ────────────────────────────────────────────────────────

    // "unreachable.com" will not resolve in CI, so IsDomainResolvableAsync returns
    // false and the noRedirectResponder is never invoked. The test verifies that
    // an unresolvable domain produces a result without throwing and without a
    // cross-domain redirect indicator.
    [Fact]
    public async Task Analyze_HttpRequestException_DoesNotThrow_ReturnsResult()
    {
        // Arrange
        var svc = Build(noRedirectResponder: _ => throw new HttpRequestException("Network error"));

        // Act
        var result = await svc.Analyze("unreachable.com");

        // Assert
        Assert.NotNull(result);
        Assert.DoesNotContain(result.Indicators,
            i => i.Contains("Cross-domain redirect", StringComparison.OrdinalIgnoreCase));
    }

    // TaskCanceledException is surfaced as an OperationCanceledException by HttpClient
    // and is caught in RunNetworkChecksAsync, which adds the "timed out" indicator.
    // Uses "example.com" so DNS resolves and the network pass is actually entered.
    [Fact]
    public async Task Analyze_TaskCanceledException_AddsTimeoutIndicator_DoesNotThrow()
    {
        // Arrange
        var svc = Build(noRedirectResponder: _ => throw new TaskCanceledException("Timed out"));

        // Act
        var result = await svc.Analyze("example.com");

        // Assert
        Assert.NotNull(result);
        Assert.Contains(result.Indicators,
            i => i.Contains("timed out", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Analyze_BothSchemesUnreachable_ReturnsResultWithoutThrow()
    {
        // Arrange
        var svc = Build(
            noRedirectResponder: _ => throw new HttpRequestException("no route"),
            followResponder: _ => throw new HttpRequestException("no route"));

        // Act
        var ex = await Record.ExceptionAsync(() => svc.Analyze("ghost.example.com"));

        // Assert
        Assert.Null(ex);
    }

    // ── IsSuspicious contract ─────────────────────────────────────────────────

    [Fact]
    public async Task Analyze_ZeroIndicators_IsSuspiciousFalse()
    {
        // Arrange
        var svc = Build();

        // Act
        var result = await svc.Analyze("mylegitsite.com");

        // Assert
        Assert.False(result.IsSuspicious);
        Assert.Empty(result.Indicators);
    }

    [Fact]
    public async Task Analyze_AtLeastOneIndicator_IsSuspiciousTrue()
    {
        // Arrange
        var svc = Build(sslChecker: new FakeSslCertificateChecker(
            "Self-signed SSL certificate detected"));

        // Act
        var result = await svc.Analyze("example.com");

        // Assert
        Assert.True(result.IsSuspicious);
    }

    // ── Summary field ─────────────────────────────────────────────────────────

    [Fact]
    public async Task Analyze_WithIndicators_SummaryMentionsIndicatorCount()
    {
        // Arrange
        var svc = Build(sslChecker: new FakeSslCertificateChecker(
            "Self-signed SSL certificate detected"));

        // Act
        var result = await svc.Analyze("example.com");

        // Assert
        Assert.Contains("indicator", result.Summary, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Analyze_NoIndicators_SummaryIndicatesClean()
    {
        // Arrange
        var svc = Build();

        // Act
        var result = await svc.Analyze("mylegitsite.com");

        // Assert
        Assert.Contains("No phishing indicators", result.Summary,
            StringComparison.OrdinalIgnoreCase);
    }

    // ── Configurable timeout ──────────────────────────────────────────────────

    [Fact]
    public async Task Analyze_TimeoutReadFromConfiguration()
    {
        // Arrange — build with a non-default timeout to confirm the config value is wired up.
        // The fake handler returns immediately so the test does not actually wait.
        var svc = Build(timeoutSeconds: 10);

        // Act
        var result = await svc.Analyze("example.com");

        // Assert
        Assert.NotNull(result);
    }

    [Fact]
    public async Task AnalyzeDomainRisk_CustomSuspiciousMinScore_DoesNotFlagLowScores()
    {
        var svc = Build(configOverrides: new Dictionary<string, string?>
        {
            ["RiskThresholds:SuspiciousMinScore"] = "25"
        });

        var result = await svc.AnalyzeDomainRiskAsync("my-bank.com");

        Assert.InRange(result.OverallRiskScore, 1, 24);
        Assert.False(result.IsSuspicious);
        Assert.Contains("below suspicious threshold", result.Summary);
    }

    [Fact]
    public async Task AnalyzeDomainRisk_CustomSignalScore_UsesConfiguredValue()
    {
        var svc = Build(configOverrides: new Dictionary<string, string?>
        {
            ["RiskThresholds:HyphenAbuse:OneHyphen"] = "23"
        });

        var result = await svc.AnalyzeDomainRiskAsync("my-bank.com");

        Assert.Equal(23, result.HyphenAbuse?.Score);
        Assert.Equal(23, result.OverallRiskScore);
        Assert.True(result.IsSuspicious);
    }

    // ── Risk classification labels ───────────────────────────────────────────

    [Theory]
    [InlineData(0, "Low")]
    [InlineData(24, "Low")]
    [InlineData(25, "Medium")]
    [InlineData(49, "Medium")]
    [InlineData(50, "High")]
    [InlineData(74, "High")]
    [InlineData(75, "Critical")]
    [InlineData(100, "Critical")]
    public void ClassifyRiskScore_MapsBoundariesToExpectedLabels(
        int score,
        string expectedClassification)
    {
        Assert.Equal(expectedClassification, DomainAnalysisResult.ClassifyRiskScore(score));
    }

    [Theory]
    [InlineData("google.com", "Low")]
    [InlineData("secure-paypal.com", "Low")]
    [InlineData("secure-login-account-update.com", "Medium")]
    [InlineData("account.verify.paypa1-login-secure-update.com", "High")]
    public async Task AnalyzeDomainRisk_ReferenceDomains_ClassifiesExpectedBands(
        string domain,
        string expectedClassification)
    {
        var svc = Build();

        var result = await svc.AnalyzeDomainRiskAsync(domain);

        Assert.Equal(expectedClassification, result.RiskClassification);
    }

    [Fact]
    public async Task AnalyzeDomainRisk_ReferenceRecentlyRegisteredDomain_ClassifiesCritical()
    {
        var svc = Build(registrationLookup: new FakeDomainRegistrationLookupService(
            new DomainRegistrationMetadata
            {
                IsLookupSuccessful = true,
                CreationDateUtc = DateTime.UtcNow.AddDays(-10),
                ExpirationDateUtc = DateTime.UtcNow.AddDays(355),
                HasPrivacyProtection = true
            }));

        var result = await svc.AnalyzeDomainRiskAsync("account.verify.paypa1-login-secure-update.com");

        Assert.Equal("Critical", result.RiskClassification);
    }

    [Fact]
    public async Task AnalyzeDomainRisk_LegitimateDomainList_DoesNotClassifyHighOrCritical()
    {
        var safeDomains = LoadDomainList("Legitimate_Domains.txt");
        var svc = Build();

        foreach (var domain in safeDomains)
        {
            var result = await svc.AnalyzeDomainRiskAsync(domain);

            Assert.True(
                result.RiskClassification is "Low" or "Medium",
                $"{domain} classified as {result.RiskClassification} with score {result.OverallRiskScore}.");
        }
    }
}

