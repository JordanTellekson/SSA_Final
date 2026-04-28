// Core analyzer implementation that combines static heuristics and network checks.
// Produces domain-level suspicion indicators and an explainable summary.

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

        // ── Structural-risk data ──────────────────────────────────────────────

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
                    DiscoveredDomain = domain ?? string.Empty,
                    IsSuspicious = false,
                    Summary = "No domain supplied — analysis skipped.",
                    AnalysedAt = DateTime.UtcNow
                };
            }

            var indicators = new List<string>();

            // Pass 0 — Structural risk checks (no network I/O; always runs)
            var riskResult = AnalyzeDomainRisk(domain);
            AddRiskIndicators(riskResult, indicators);

            // Passes 1–3 — Network checks (redirect, SSL, HTML content)
            await RunNetworkChecksAsync(domain, indicators);

            var isSuspicious = indicators.Count > 0;
            var summary = isSuspicious
                ? $"Domain flagged with {indicators.Count} indicator(s), risk score {riskResult.OverallRiskScore}: {string.Join("; ", indicators)}."
                : "No phishing indicators detected.";

            _logger.LogInformation(
                "[DomainAnalyzerService] Analyze completed for {Domain}. " +
                "Suspicious={IsSuspicious}, Indicators={Count}",
                domain, isSuspicious, indicators.Count);

            return new DomainAnalysisResult
            {
                DiscoveredDomain = domain,
                IsSuspicious = isSuspicious,
                Summary = summary,
                Indicators = indicators,
                AnalysedAt = DateTime.UtcNow
            };
        }

        // ── Pass 0: Structural risk checks ────────────────────────────────────

        public DomainRiskAnalysisResult AnalyzeDomainRisk(string domain)
        {
            var normalizedDomain = NormalizeDomain(domain);
            if (string.IsNullOrWhiteSpace(normalizedDomain))
            {
                return DomainRiskAnalysisResult.InvalidInput();
            }

            var typosquatting = CalculateTyposquattingScore(normalizedDomain);
            var subdomain = CalculateSubdomainScore(normalizedDomain);
            var hyphen = CalculateHyphenScore(normalizedDomain);
            var entropy = CalculateEntropyScore(normalizedDomain);

            var overallRisk = typosquatting.Score + subdomain.Score + hyphen.Score + entropy.Score;

            return new DomainRiskAnalysisResult(
                inputDomain: normalizedDomain,
                isKnownActiveDomain: false,
                isValidDomain: true,
                overallRiskScore: overallRisk,
                typosquattingEditDistance: typosquatting,
                excessiveSubdomains: subdomain,
                hyphenAbuse: hyphen,
                shannonEntropy: entropy,
                isBlocklistMatch: false,
                blocklistSource: null,
                usedBlocklistFallback: false);
        }

        private static void AddRiskIndicators(DomainRiskAnalysisResult riskResult, List<string> indicators)
        {
            var signals = new[]
            {
                riskResult.TyposquattingEditDistance,
                riskResult.ExcessiveSubdomains,
                riskResult.HyphenAbuse,
                riskResult.ShannonEntropy
            };

            foreach (var signal in signals)
            {
                if (signal.Triggered)
                {
                    indicators.Add($"{signal.Signal}: {signal.Detail}");
                }
            }
        }

        private static DomainRiskSignalScore CalculateTyposquattingScore(string normalizedDomain)
        {
            var rootLabel = GetRootDomainLabel(normalizedDomain);
            if (string.IsNullOrWhiteSpace(rootLabel))
            {
                return new DomainRiskSignalScore("Typosquatting/Edit Distance", 0, false, "No root label available.");
            }

            var closestBrand = string.Empty;
            var minDistance = int.MaxValue;
            foreach (var brand in KnownBrands)
            {
                if (Math.Abs(brand.Length - rootLabel.Length) > 3)
                {
                    continue;
                }

                var distance = CalculateLevenshteinDistance(rootLabel, brand, 3);
                if (distance < minDistance)
                {
                    minDistance = distance;
                    closestBrand = brand;
                }

                if (minDistance == 0)
                {
                    break;
                }
            }

            var score = minDistance switch
            {
                1 => 25,
                2 => 18,
                3 => 10,
                _ => 0
            };

            return new DomainRiskSignalScore(
                "Typosquatting/Edit Distance",
                score,
                score > 0,
                score > 0
                    ? $"Root label '{rootLabel}' is {minDistance} edit(s) from known brand '{closestBrand}'."
                    : "No suspicious root-label edit-distance match detected.");
        }

        private static DomainRiskSignalScore CalculateSubdomainScore(string normalizedDomain)
        {
            var labels = normalizedDomain.Split('.', StringSplitOptions.RemoveEmptyEntries);
            labels = labels.Concat(normalizedDomain.Split('-', StringSplitOptions.RemoveEmptyEntries)).ToArray();

            var subdomainCount = Math.Max(labels.Length - 2, 0);

            var score = subdomainCount switch
            {
                <= 1 => 0,
                2 => 8,
                3 => 16,
                _ => 25
            };

            return new DomainRiskSignalScore(
                "Excessive Subdomains",
                score,
                score > 0,
                $"Detected {subdomainCount} subdomain label(s).");
        }

        private static DomainRiskSignalScore CalculateHyphenScore(string normalizedDomain)
        {
            var hyphenCount = normalizedDomain.Count(c => c == '-');
            var repeatedPatternCount = Regex.Matches(normalizedDomain, "--").Count;

            var score = hyphenCount switch
            {
                0 => 0,
                1 => 6,
                2 => 12,
                3 => 18,
                _ => 25
            };

            if (repeatedPatternCount > 0)
            {
                score = Math.Min(25, score + repeatedPatternCount * 2);
            }

            return new DomainRiskSignalScore(
                "Hyphen Abuse",
                score,
                score > 0,
                $"Detected {hyphenCount} hyphen(s) and {repeatedPatternCount} repeated hyphen pattern(s).");
        }

        private static DomainRiskSignalScore CalculateEntropyScore(string normalizedDomain)
        {
            var sample = new string(normalizedDomain.Where(char.IsLetterOrDigit).ToArray());
            var entropy = CalculateShannonEntropy(sample);

            var score = entropy switch
            {
                < 3.0 => 0,
                < 3.4 => 8,
                < 3.8 => 16,
                _ => 25
            };

            var labels = normalizedDomain.Split('.', StringSplitOptions.RemoveEmptyEntries);
            var longestLabel = labels.Length == 0 ? 0 : labels.Max(label => label.Length);
            if (longestLabel >= 15 && entropy >= 3.5)
            {
                score = Math.Min(25, score + 4);
            }

            return new DomainRiskSignalScore(
                "Shannon Entropy",
                score,
                score > 0,
                $"Calculated entropy across alphanumeric characters is {entropy:F2}.");
        }

        private static string GetRootDomainLabel(string normalizedDomain)
        {
            var labels = normalizedDomain.Split('.', StringSplitOptions.RemoveEmptyEntries);
            if (labels.Length == 0)
            {
                return string.Empty;
            }

            if (labels.Length == 1)
            {
                return labels[0].ToLowerInvariant();
            }

            return labels[^2].ToLowerInvariant();
        }

        private static int CalculateLevenshteinDistance(string a, string b, int maxDistance)
        {
            if (Math.Abs(a.Length - b.Length) > maxDistance)
            {
                return maxDistance + 1;
            }

            var previous = new int[b.Length + 1];
            var current = new int[b.Length + 1];

            for (var j = 0; j <= b.Length; j++)
            {
                previous[j] = j;
            }

            for (var i = 1; i <= a.Length; i++)
            {
                current[0] = i;
                var rowMin = current[0];

                for (var j = 1; j <= b.Length; j++)
                {
                    var cost = a[i - 1] == b[j - 1] ? 0 : 1;
                    current[j] = Math.Min(
                        Math.Min(current[j - 1] + 1, previous[j] + 1),
                        previous[j - 1] + cost);
                    rowMin = Math.Min(rowMin, current[j]);
                }

                if (rowMin > maxDistance)
                {
                    return maxDistance + 1;
                }

                (previous, current) = (current, previous);
            }

            return previous[b.Length];
        }

        private static double CalculateShannonEntropy(string input)
        {
            if (string.IsNullOrEmpty(input))
            {
                return 0;
            }

            var counts = new Dictionary<char, int>();
            foreach (var c in input)
            {
                counts[c] = counts.TryGetValue(c, out var count) ? count + 1 : 1;
            }

            double entropy = 0;
            foreach (var count in counts.Values)
            {
                var p = (double)count / input.Length;
                entropy -= p * Math.Log2(p);
            }

            return entropy;
        }

        private static string? NormalizeDomain(string? rawDomain)
        {
            if (string.IsNullOrWhiteSpace(rawDomain))
            {
                return null;
            }

            var value = rawDomain.Trim();
            if (!value.Contains("://", StringComparison.Ordinal))
            {
                value = "http://" + value;
            }

            if (!Uri.TryCreate(value, UriKind.Absolute, out var uri))
            {
                return null;
            }

            var host = uri.Host.Trim().TrimEnd('.');
            if (host.StartsWith("www.", StringComparison.OrdinalIgnoreCase))
            {
                host = host[4..];
            }

            if (IPAddress.TryParse(host, out _))
            {
                return null;
            }

            return string.IsNullOrWhiteSpace(host) ? null : host.ToLowerInvariant();
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

