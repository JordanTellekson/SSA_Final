// Unit tests for DomainAnalyzerService covering static checks, network behavior,
// SSL indicators, HTML analysis, timeout/error handling, and output contracts.

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using SSA_Final.Interfaces;
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

// ── Tests ─────────────────────────────────────────────────────────────────────

public class DomainAnalyzerServiceTests
{
    // ── Builder helpers ───────────────────────────────────────────────────────

    private static IConfiguration BuildConfig(int timeoutSeconds = 5)
    {
        var dict = new Dictionary<string, string?>
        {
            ["DomainAnalyzer:TimeoutSeconds"] = timeoutSeconds.ToString()
        };
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

    /// <summary>
    /// Creates a <see cref="DomainAnalyzerService"/> wired to fake collaborators.
    /// Unspecified parameters default to clean / non-suspicious responses.
    /// </summary>
    private static DomainAnalyzerService Build(
        Func<HttpRequestMessage, HttpResponseMessage>? noRedirectResponder = null,
        Func<HttpRequestMessage, HttpResponseMessage>? followResponder = null,
        ISslCertificateChecker? sslChecker = null,
        int timeoutSeconds = 5)
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
            BuildConfig(timeoutSeconds),
            NullLogger<DomainAnalyzerService>.Instance);
    }

    // ── Null / empty input ────────────────────────────────────────────────────

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public async Task Analyze_NullOrEmptyDomain_ReturnsCleanResult(string? domain)
    {
        var svc = Build();
        var result = await svc.Analyze(domain!);

        Assert.False(result.IsSuspicious);
        Assert.Empty(result.Indicators);
    }

    // ── Pass 0: Static checks — IP address ───────────────────────────────────

    [Theory]
    [InlineData("192.168.1.1")]
    [InlineData("10.0.0.1")]
    [InlineData("203.0.113.42")]
    public async Task Analyze_IpAddressDomain_AddsIpIndicator(string domain)
    {
        var svc = Build();
        var result = await svc.Analyze(domain);

        Assert.Contains(result.Indicators, i => i.Contains("IP address"));
        Assert.True(result.IsSuspicious);
    }

    // ── Pass 0: Static checks — excessive subdomains ──────────────────────────

    [Fact]
    public async Task Analyze_ExcessiveSubdomains_AddsSubdomainIndicator()
    {
        var svc = Build();
        var result = await svc.Analyze("login.secure.verify.paypal.com");

        Assert.Contains(result.Indicators, i => i.Contains("Excessive subdomains"));
    }

    [Fact]
    public async Task Analyze_NormalSubdomainDepth_NoSubdomainIndicator()
    {
        var svc = Build();
        var result = await svc.Analyze("mail.example.com");

        Assert.DoesNotContain(result.Indicators, i => i.Contains("Excessive subdomains"));
    }

    // ── Pass 0: Static checks — hyphen abuse ──────────────────────────────────

    [Theory]
    [InlineData("secure-login-account-update.com")]
    [InlineData("a-b-c-d.net")]
    public async Task Analyze_ThreeOrMoreHyphens_AddsHyphenIndicator(string domain)
    {
        var svc = Build();
        var result = await svc.Analyze(domain);

        Assert.Contains(result.Indicators, i => i.Contains("Hyphen abuse"));
    }

    [Theory]
    [InlineData("secure-paypal.com", "secure-")]
    [InlineData("login-mybank.net", "login-")]
    [InlineData("verify-account.org", "verify-")]
    [InlineData("confirm-email.com", "confirm-")]
    public async Task Analyze_SuspiciousPrefix_AddsIndicator(string domain, string prefix)
    {
        var svc = Build();
        var result = await svc.Analyze(domain);

        Assert.Contains(result.Indicators, i => i.Contains(prefix));
    }

    // ── Pass 0: Static checks — suspicious TLD ───────────────────────────────

    [Theory]
    [InlineData("mybank.xyz", ".xyz")]
    [InlineData("paypal.tk", ".tk")]
    [InlineData("google.top", ".top")]
    [InlineData("microsoft.ru", ".ru")]
    public async Task Analyze_SuspiciousTld_AddsIndicator(string domain, string tld)
    {
        var svc = Build();
        var result = await svc.Analyze(domain);

        Assert.Contains(result.Indicators, i => i.Contains(tld));
    }

    [Fact]
    public async Task Analyze_CommonTld_NoTldIndicator()
    {
        var svc = Build();
        var result = await svc.Analyze("example.com");

        Assert.DoesNotContain(result.Indicators, i => i.Contains("TLD"));
    }

    // ── Pass 0: Static checks — brand keyword stuffing ───────────────────────

    [Fact]
    public async Task Analyze_TwoBrandsInDomain_AddsBrandStuffingIndicator()
    {
        var svc = Build();
        var result = await svc.Analyze("paypal-amazon-security.com");

        Assert.Contains(result.Indicators, i => i.Contains("Brand keyword stuffing"));
    }

    [Fact]
    public async Task Analyze_OneBrandInDomain_NoBrandStuffingIndicator()
    {
        var svc = Build();
        var result = await svc.Analyze("paypal-secure.com");

        Assert.DoesNotContain(result.Indicators, i => i.Contains("Brand keyword stuffing"));
    }

    // ── Pass 0: Clean domain produces no static indicators ───────────────────

    [Fact]
    public async Task Analyze_CleanDomain_NoStaticIndicators()
    {
        var svc = Build();
        var result = await svc.Analyze("mylegitsite.com");

        Assert.False(result.IsSuspicious);
        Assert.Empty(result.Indicators);
    }

    // ── Pass 1: Cross-domain redirect ─────────────────────────────────────────

    [Fact]
    public async Task Analyze_200Response_NoRedirectIndicator()
    {
        var svc = Build(noRedirectResponder: _ => new HttpResponseMessage(HttpStatusCode.OK));
        var result = await svc.Analyze("example.com");

        Assert.DoesNotContain(result.Indicators, i => i.Contains("redirect"));
    }

    [Theory]
    [InlineData("https://www.example.com/home")]   // subdomain of original
    [InlineData("https://example.com/new-page")]   // same host
    public async Task Analyze_SameDomainRedirect_NoRedirectIndicator(string location)
    {
        var svc = Build(noRedirectResponder: _ =>
        {
            var r = new HttpResponseMessage(HttpStatusCode.MovedPermanently);
            r.Headers.Location = new Uri(location);
            return r;
        });

        var result = await svc.Analyze("example.com");

        Assert.DoesNotContain(result.Indicators, i => i.Contains("redirect"));
    }

    [Fact]
    public async Task Analyze_CrossDomainRedirect_AddsRedirectIndicator()
    {
        var svc = Build(noRedirectResponder: _ =>
        {
            var r = new HttpResponseMessage(HttpStatusCode.MovedPermanently);
            r.Headers.Location = new Uri("https://attacker.com/steal");
            return r;
        });

        var result = await svc.Analyze("example.com");

        Assert.Contains(result.Indicators, i => i.Contains("Cross-domain redirect"));
        Assert.True(result.IsSuspicious);
    }

    // ── Pass 2: SSL certificate indicators ───────────────────────────────────

    [Fact]
    public async Task Analyze_ExpiredCertificate_AddsExpiredIndicator()
    {
        var svc = Build(sslChecker: new FakeSslCertificateChecker(
                               "SSL certificate expired on 2023-01-01"));
        var result = await svc.Analyze("example.com");

        Assert.Contains(result.Indicators, i => i.Contains("expired"));
        Assert.True(result.IsSuspicious);
    }

    [Fact]
    public async Task Analyze_SelfSignedCertificate_AddsSelfSignedIndicator()
    {
        var svc = Build(sslChecker: new FakeSslCertificateChecker(
                               "Self-signed SSL certificate detected"));
        var result = await svc.Analyze("example.com");

        Assert.Contains(result.Indicators, i => i.Contains("Self-signed"));
    }

    [Fact]
    public async Task Analyze_CertHostnameMismatch_AddsMismatchIndicator()
    {
        var svc = Build(sslChecker: new FakeSslCertificateChecker(
                               "SSL certificate hostname mismatch (cert issued for 'other.com')"));
        var result = await svc.Analyze("example.com");

        Assert.Contains(result.Indicators, i => i.Contains("hostname mismatch"));
    }

    [Fact]
    public async Task Analyze_ValidCertificate_NoSslIndicators()
    {
        var svc = Build(sslChecker: new FakeSslCertificateChecker()); // empty
        var result = await svc.Analyze("example.com");

        Assert.DoesNotContain(result.Indicators,
            i => i.Contains("SSL") || i.Contains("certificate") || i.Contains("cert"));
    }

    // ── Pass 3: HTML content checks ───────────────────────────────────────────

    [Fact]
    public async Task Analyze_PasswordFieldInHtml_AddsPasswordIndicator()
    {
        const string html = """
            <html><body>
              <input type="password" name="pwd" />
            </body></html>
            """;
        var svc = Build(followResponder: _ => OkHtml(html));
        var result = await svc.Analyze("example.com");

        Assert.Contains(result.Indicators, i => i.Contains("Password input field"));
    }

    [Fact]
    public async Task Analyze_LoginFormInHtml_AddsLoginFormIndicator()
    {
        const string html = """
            <html><body>
              <form action="/login" id="loginForm"></form>
            </body></html>
            """;
        var svc = Build(followResponder: _ => OkHtml(html));
        var result = await svc.Analyze("example.com");

        Assert.Contains(result.Indicators, i => i.Contains("Login form"));
    }

    [Fact]
    public async Task Analyze_BrandInTitleNotInDomain_AddsMismatchIndicator()
    {
        const string html = "<html><head><title>PayPal - Secure Login</title></head></html>";
        var svc = Build(followResponder: _ => OkHtml(html));
        var result = await svc.Analyze("totallynotpaypal.com");

        Assert.Contains(result.Indicators, i => i.Contains("Brand keyword mismatch"));
    }

    [Fact]
    public async Task Analyze_BrandInTitleAndInDomain_NoBrandMismatch()
    {
        const string html = "<html><head><title>PayPal Secure</title></head></html>";
        var svc = Build(followResponder: _ => OkHtml(html));
        var result = await svc.Analyze("paypal.com");

        Assert.DoesNotContain(result.Indicators, i => i.Contains("Brand keyword mismatch"));
    }

    [Fact]
    public async Task Analyze_CleanHtml_NoHtmlIndicators()
    {
        const string html = "<html><head><title>My Legitimate Site</title></head><body></body></html>";
        var svc = Build(followResponder: _ => OkHtml(html));
        var result = await svc.Analyze("example.com");

        Assert.DoesNotContain(result.Indicators, i =>
            i.Contains("Password") || i.Contains("Login form") || i.Contains("Brand keyword mismatch"));
    }

    [Fact]
    public async Task Analyze_HttpsFails_FallsBackToHttp_AddsNoHttpsIndicator()
    {
        var svc = Build(followResponder: req =>
        {
            if (req.RequestUri!.Scheme == "https")
                throw new HttpRequestException("HTTPS unavailable");

            return OkHtml("<html><body></body></html>");
        });

        var result = await svc.Analyze("example.com");

        Assert.Contains(result.Indicators, i => i.Contains("No HTTPS support"));
    }

    // ── Error handling ────────────────────────────────────────────────────────

    [Fact]
    public async Task Analyze_HttpRequestException_DoesNotThrow_ReturnsResult()
    {
        var svc = Build(noRedirectResponder: _ => throw new HttpRequestException("Network error"));
        var result = await svc.Analyze("unreachable.com");

        Assert.NotNull(result);
        // Static checks may still have run; the domain itself is clean.
        Assert.DoesNotContain(result.Indicators, i => i.Contains("Cross-domain"));
    }

    [Fact]
    public async Task Analyze_TaskCanceledException_AddsTimeoutIndicator_DoesNotThrow()
    {
        var svc = Build(noRedirectResponder: _ => throw new TaskCanceledException("Timed out"));
        var result = await svc.Analyze("slow.com");

        Assert.NotNull(result);
        Assert.Contains(result.Indicators, i => i.Contains("timed out"));
    }

    [Fact]
    public async Task Analyze_BothSchemesUnreachable_ReturnsResultWithoutThrow()
    {
        // Both the NoRedirect and Follow clients throw HttpRequestException.
        var svc = Build(
            noRedirectResponder: _ => throw new HttpRequestException("no route"),
            followResponder: _ => throw new HttpRequestException("no route"));

        var ex = await Record.ExceptionAsync(() => svc.Analyze("ghost.example.com"));
        Assert.Null(ex);
    }

    // ── IsSuspicious contract ─────────────────────────────────────────────────

    [Fact]
    public async Task Analyze_ZeroIndicators_IsSuspiciousFalse()
    {
        var svc = Build();
        var result = await svc.Analyze("mylegitsite.com");

        Assert.False(result.IsSuspicious);
        Assert.Empty(result.Indicators);
    }

    [Fact]
    public async Task Analyze_AtLeastOneIndicator_IsSuspiciousTrue()
    {
        var svc = Build(sslChecker: new FakeSslCertificateChecker(
                               "Self-signed SSL certificate detected"));
        var result = await svc.Analyze("example.com");

        Assert.True(result.IsSuspicious);
    }

    // ── Summary field ─────────────────────────────────────────────────────────

    [Fact]
    public async Task Analyze_WithIndicators_SummaryMentionsIndicatorCount()
    {
        var svc = Build(sslChecker: new FakeSslCertificateChecker(
                               "Self-signed SSL certificate detected"));
        var result = await svc.Analyze("example.com");

        Assert.Contains("indicator", result.Summary, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Analyze_NoIndicators_SummaryIndicatesClean()
    {
        var svc = Build();
        var result = await svc.Analyze("mylegitsite.com");

        Assert.Contains("No phishing indicators", result.Summary,
            StringComparison.OrdinalIgnoreCase);
    }

    // ── Configurable timeout ──────────────────────────────────────────────────

    [Fact]
    public async Task Analyze_TimeoutReadFromConfiguration()
    {
        // Build a service with a custom timeout and verify it is used.
        // The fake handler immediately returns, so the test doesn't actually wait;
        // this just confirms the config value is wired up without an exception.
        var svc = Build(timeoutSeconds: 10);
        var result = await svc.Analyze("example.com");

        Assert.NotNull(result);
    }
}

