using SSA_Final.Interfaces;
using SSA_Final.Models;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace SSA_Final.Services
{
    public class DomainAnalyzerService : IDomainAnalyzer
    {
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly ISslCertificateChecker _sslChecker;
        private readonly ILogger<DomainAnalyzerService> _logger;
        private readonly int _timeoutSeconds;

        // ── Static-check data ─────────────────────────────────────────────────

        private static readonly HashSet<string> SuspiciousTlds =
            new(StringComparer.OrdinalIgnoreCase)
            {
                ".xyz", ".top", ".tk", ".ru", ".pw", ".cc",
                ".buzz", ".gq", ".ml", ".cf", ".ga", ".info"
            };

        private static readonly string[] SuspiciousPrefixes =
        {
            "secure-", "login-", "account-", "verify-",
            "update-", "banking-", "confirm-", "signin-", "webscr-"
        };

        private static readonly string[] SuspiciousSuffixes =
        {
            "-secure", "-login", "-account",
            "-verify", "-update", "-confirm", "-signin"
        };

        private static readonly string[] KnownBrands =
        {
            "paypal", "amazon", "microsoft", "google", "apple",
            "facebook", "netflix", "chase", "wellsfargo",
            "bankofamerica", "instagram", "twitter"
        };

        // ── Constructor ───────────────────────────────────────────────────────

        public DomainAnalyzerService(
            IHttpClientFactory httpClientFactory,
            ISslCertificateChecker sslChecker,
            IConfiguration configuration,
            ILogger<DomainAnalyzerService> logger)
        {
            _httpClientFactory = httpClientFactory;
            _sslChecker = sslChecker;
            _logger = logger;
            _timeoutSeconds = configuration.GetValue<int>("DomainAnalyzer:TimeoutSeconds", 5);
        }

        // ── IDomainAnalyzer ───────────────────────────────────────────────────

        public async Task<DomainAnalysisResult> Analyze(string domain)
        {
            // Normalize input: trim and extract host if the caller passed a full URL
            var originalInput = domain;
            domain = domain?.Trim() ?? string.Empty;
            if (Uri.TryCreate(domain, UriKind.Absolute, out var parsed))
            {
                domain = parsed.Host;
            }

            _logger.LogInformation(
                "[DomainAnalyzerService] Analyze called for domain: {Domain}", domain);

            if (string.IsNullOrWhiteSpace(domain))
            {
                _logger.LogWarning(
                    "[DomainAnalyzerService] Analyze received null or empty domain.");

                return new DomainAnalysisResult
                {
                    Domain = domain ?? string.Empty,
                    IsSuspicious = false,
                    Summary = "No domain supplied — analysis skipped.",
                    AnalysedAt = DateTime.UtcNow
                };
            }

            var indicators = new List<string>();

            // Pass 0 — Static domain checks (no network I/O; always runs)
            RunStaticChecks(domain, indicators);

            // Passes 1–3 — Network checks (redirect, SSL, HTML content)
            await RunNetworkChecksAsync(domain, indicators);

            var isSuspicious = indicators.Count > 0;
            var summary = isSuspicious
                ? $"Domain flagged with {indicators.Count} indicator(s): {string.Join("; ", indicators)}."
                : "No phishing indicators detected.";

            _logger.LogInformation(
                "[DomainAnalyzerService] Analyze completed for {Domain}. " +
                "Suspicious={IsSuspicious}, Indicators={Count}",
                domain, isSuspicious, indicators.Count);

            return new DomainAnalysisResult
            {
                Domain = domain,
                IsSuspicious = isSuspicious,
                Summary = summary,
                Indicators = indicators,
                AnalysedAt = DateTime.UtcNow
            };
        }

        // ── Pass 0: Static checks (Phishing_Indicators.md reference) ─────────

        private static void RunStaticChecks(string domain, List<string> indicators)
        {
            // IP address used in place of a real domain name.
            if (IPAddress.TryParse(domain, out _))
            {
                indicators.Add("IP address used in place of a domain name");
                return; // Further string checks are meaningless for an IP literal.
            }

            var labels = domain.Split('.', StringSplitOptions.RemoveEmptyEntries);
            var lowerDomain = domain.ToLowerInvariant();

            // Excessive subdomains: more than 2 labels before the TLD.
            // e.g. login.secure.verify.paypal.com has 3 subdomain labels.
            if (labels.Length > 4)
                indicators.Add(
                    $"Excessive subdomains detected ({labels.Length - 2} subdomain labels)");

            // Hyphen abuse: 3+ hyphens is a blanket flag;
            // fewer hyphens are still checked for known phishing keyword patterns.
            var hyphenCount = lowerDomain.Count(c => c == '-');
            if (hyphenCount >= 3)
            {
                indicators.Add($"Hyphen abuse detected ({hyphenCount} hyphens in domain)");
            }
            else
            {
                var prefix = Array.Find(SuspiciousPrefixes,
                    p => lowerDomain.Contains(p, StringComparison.Ordinal));
                if (prefix is not null)
                    indicators.Add($"Suspicious phishing prefix detected: '{prefix}'");

                var suffix = Array.Find(SuspiciousSuffixes,
                    s => lowerDomain.Contains(s, StringComparison.Ordinal));
                if (suffix is not null)
                    indicators.Add($"Suspicious phishing suffix detected: '{suffix}'");
            }

            // Suspicious TLD.
            if (labels.Length >= 2)
            {
                var tld = $".{labels[^1]}";
                if (SuspiciousTlds.Contains(tld))
                    indicators.Add($"Suspicious TLD detected: '{tld}'");
            }

            // Brand keyword stuffing: 2+ known brand names packed into one domain.
            var matched = Array.FindAll(KnownBrands,
                b => lowerDomain.Contains(b, StringComparison.Ordinal));
            if (matched.Length >= 2)
                indicators.Add(
                    $"Brand keyword stuffing detected: {string.Join(", ", matched)}");
        }

        // ── Passes 1–3: Network checks ────────────────────────────────────────

        private async Task RunNetworkChecksAsync(string domain, List<string> indicators)
        {
            // 1. DNS Pre-flight: If the domain doesn't exist, don't bother with HTTP/SSL
            if (!await IsDomainResolvableAsync(domain))
            {
                _logger.LogInformation("[DomainAnalyzerService] Domain {Domain} has no DNS records. Skipping network checks.", domain);
                // Optional: indicators.Add("Domain appears to be inactive (no DNS records)");
                return;
            }

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(_timeoutSeconds));

            try
            {
                // Run Redirect Check
                await CheckRedirectAsync(domain, indicators, cts.Token);

                // Run SSL Check
                var sslIndicators = await _sslChecker.GetSslIndicatorsAsync(domain, cts.Token);
                indicators.AddRange(sslIndicators);

                // Run HTML Check
                await CheckHtmlContentAsync(domain, indicators, cts.Token);
            }
            catch (OperationCanceledException) // Catches both TaskCanceled and OperationCanceled
            {
                _logger.LogWarning("[DomainAnalyzerService] Timeout analyzing {Domain}", domain);
                indicators.Add("Analysis timed out — server may be tarpitting or unresponsive");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[DomainAnalyzerService] Error during network checks for {Domain}", domain);
            }
        }

        // Pass 1 — Cross-domain redirect detection ────────────────────────────

        private async Task CheckRedirectAsync(string domain, List<string> indicators, CancellationToken ct)
        {
            var client = _httpClientFactory.CreateClient("DomainAnalyzer.NoRedirect");
            var requestUri = $"https://{domain}";

            using var response = await client.GetAsync(requestUri, HttpCompletionOption.ResponseHeadersRead, ct);

            if ((int)response.StatusCode is >= 300 and < 400)
            {
                var location = response.Headers.Location;
                if (location is not null)
                {
                    var targetHost = location.IsAbsoluteUri ? location.Host : string.Empty;
                    if (!string.IsNullOrEmpty(targetHost) &&
                        !targetHost.Equals(domain, StringComparison.OrdinalIgnoreCase) &&
                        !targetHost.EndsWith($".{domain}", StringComparison.OrdinalIgnoreCase))
                    {
                        indicators.Add($"Cross-domain redirect detected → {targetHost}");
                    }
                }
            }
        }

        // Pass 3 — HTML content analysis ──────────────────────────────────────

        private async Task CheckHtmlContentAsync(
            string domain, List<string> indicators, CancellationToken ct)
        {
            var client = _httpClientFactory.CreateClient("DomainAnalyzer.Follow");
            HttpResponseMessage? response = null;

            // Try HTTPS first; fall back to HTTP and note the absence of HTTPS.
            try
            {
                response = await client.GetAsync(
                    $"https://{domain}", HttpCompletionOption.ResponseContentRead, ct);
            }
            catch (HttpRequestException)
            {
                try
                {
                    response = await client.GetAsync(
                        $"http://{domain}", HttpCompletionOption.ResponseContentRead, ct);
                    indicators.Add("No HTTPS support — domain only responds on plain HTTP");
                }
                catch
                {
                    // Domain is unreachable on both schemes; skip HTML checks.
                    _logger.LogInformation(
                        "[DomainAnalyzerService] {Domain} unreachable on HTTPS and HTTP; " +
                        "HTML checks skipped.", domain);
                    return;
                }
            }

            using (response)
            {
                if (response is null) return;

                var contentType = response.Content.Headers.ContentType?.MediaType ?? string.Empty;
                if (!contentType.Contains("html", StringComparison.OrdinalIgnoreCase)) return;

                var html = await response.Content.ReadAsStringAsync(ct);
                if (string.IsNullOrWhiteSpace(html)) return;

                // Password input field present on the page.
                if (Regex.IsMatch(html,
                    @"<input[^>]+type\s*=\s*[""']?password[""']?",
                    RegexOptions.IgnoreCase))
                {
                    indicators.Add("Password input field detected in page HTML");
                }

                // Login form identified by action, id, or class attribute keywords.
                if (Regex.IsMatch(html,
                    @"<form[^>]+(action|id|class)\s*=\s*[""'][^""']*(login|signin|logon|authenticate)[^""']*[""']",
                    RegexOptions.IgnoreCase))
                {
                    indicators.Add("Login form detected in page HTML");
                }

                // Brand keyword in <title> that does not appear in the domain itself.
                var titleMatch = Regex.Match(html,
                    @"<title[^>]*>(.*?)</title>",
                    RegexOptions.IgnoreCase | RegexOptions.Singleline);

                if (titleMatch.Success)
                {
                    var title = titleMatch.Groups[1].Value.ToLowerInvariant();

                    var brandInTitle = Array.Find(KnownBrands,
                        b => title.Contains(b, StringComparison.Ordinal));

                    if (brandInTitle is not null)
                    {
                        // Consider a brand present in the domain only when it appears
                        // as a separate token within domain labels (split on '.' and '-')
                        // to avoid false positives for domains like 'totallynotpaypal.com'.
                        var domainTokens = domain
                            .ToLowerInvariant()
                            .Split('.', StringSplitOptions.RemoveEmptyEntries)
                            .SelectMany(l => l.Split('-', StringSplitOptions.RemoveEmptyEntries));

                        if (!domainTokens.Contains(brandInTitle, StringComparer.Ordinal))
                        {
                            indicators.Add(
                                $"Brand keyword mismatch: page title references " +
                                $"'{brandInTitle}' but domain does not");
                        }
                    }
                }
            }
        }

        private async Task<bool> IsDomainResolvableAsync(string domain)
        {
            try
            {
                var addresses = await Dns.GetHostAddressesAsync(domain);
                return addresses.Length > 0;
            }
            catch
            {
                return false; // DNS lookup failed, domain doesn't exist
            }
        }
    }
}