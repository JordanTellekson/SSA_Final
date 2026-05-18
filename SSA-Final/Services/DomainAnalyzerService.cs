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
        private readonly string _legitimateDomainsFilePath;
        private readonly Lazy<HashSet<string>> _knownLegitimateDomains;
        private readonly Lazy<List<string>> _knownLegitimateRootDomains;
        private readonly Lazy<Dictionary<int, List<string>>> _knownLegitimateRootsByLength;
        private readonly IPhishingBlocklistService? _blocklistService;
        private readonly IDomainRegistrationLookupService? _registrationLookupService;
        private readonly RiskThresholdOptions _riskThresholds;

        // ── Structural-risk data ──────────────────────────────────────────────

        private static readonly string[] KnownBrands =
        {
            "paypal", "amazon", "microsoft", "google", "apple",
            "facebook", "netflix", "chase", "wellsfargo",
            "bankofamerica", "instagram", "twitter"
        };

        // Keywords commonly embedded in phishing domains to impersonate legitimate services.
        private static readonly string[] PhishingKeywords =
        [
            "login", "secure", "account", "verify", "update",
            "confirm", "signin", "password", "support"
        ];

        // ── Constructor ───────────────────────────────────────────────────────

        public DomainAnalyzerService(
            IHttpClientFactory httpClientFactory,
            ISslCertificateChecker sslChecker,
            IConfiguration configuration,
            ILogger<DomainAnalyzerService> logger)
            : this(httpClientFactory, sslChecker, configuration, logger, null, null, null)
        {
        }

        public DomainAnalyzerService(
            IHttpClientFactory httpClientFactory,
            ISslCertificateChecker sslChecker,
            IConfiguration configuration,
            ILogger<DomainAnalyzerService> logger,
            IWebHostEnvironment? hostEnvironment,
            IPhishingBlocklistService? blocklistService,
            IDomainRegistrationLookupService? registrationLookupService = null)
        {
            _httpClientFactory = httpClientFactory;
            _sslChecker = sslChecker;
            _logger = logger;
            _blocklistService = blocklistService;
            _registrationLookupService = registrationLookupService;
            _timeoutSeconds = configuration.GetValue<int>("DomainAnalyzer:TimeoutSeconds", 5);
            _riskThresholds = RiskThresholdOptions.FromConfiguration(configuration);

            var contentRoot = hostEnvironment?.ContentRootPath ?? Directory.GetCurrentDirectory();
            _legitimateDomainsFilePath = Path.Combine(contentRoot, "Legitimate_Domains.txt");

            _knownLegitimateDomains = new Lazy<HashSet<string>>(LoadKnownLegitimateDomains);
            _knownLegitimateRootDomains = new Lazy<List<string>>(() =>
                _knownLegitimateDomains.Value
                    .Select(GetRootDomainLabel)
                    .Where(root => !string.IsNullOrWhiteSpace(root))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList());
            _knownLegitimateRootsByLength = new Lazy<Dictionary<int, List<string>>>(() =>
                _knownLegitimateRootDomains.Value
                    .GroupBy(root => root.Length)
                    .ToDictionary(
                        group => group.Key,
                        group => group.ToList()));
        }

        // ── IDomainAnalyzer ───────────────────────────────────────────────────

        public async Task<DomainAnalysisResult> Analyze(string domain)
        {
            try
            {
                // Normalize input: trim and extract host if the caller passed a full URL.
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

                    return BuildInvalidInputResult();
                }

                var indicators = new List<string>();

                // Pass 0 — Structural risk checks (and blocklist / allow-list checks).
                var riskResult = await AnalyzeDomainRiskAsync(domain);
                if (!riskResult.IsValidDomain)
                {
                    return riskResult;
                }

                if (riskResult.IsKnownActiveDomain)
                {
                    return riskResult;
                }

                // Early-out for blocklist hits: the result already carries IsSuspicious=true,
                // OverallRiskScore=100, and a Summary. Emit exactly one indicator and skip
                // both AddRiskIndicators (which would add 4 duplicate signal hits + 1 more
                // from the IsBlocklistMatch check) and the unnecessary network passes.
                if (riskResult.IsBlocklistMatch)
                {
                    riskResult.Indicators = new List<string>
                    {
                        $"Blocklist Match: Domain found in {riskResult.BlocklistSource} feed."
                    };
                    riskResult.AnalysedAt = DateTime.UtcNow;
                    riskResult.DiscoveredDomain = domain;
                    return riskResult;
                }

                AddRiskIndicators(domain, riskResult, indicators);
                var structuralIndicatorCount = indicators.Count;

                // Passes 1–3 — Network checks (redirect, SSL, HTML content).
                await RunNetworkChecksAsync(domain, indicators);

                riskResult.Indicators = indicators;
                var hasNetworkIndicators = indicators.Count > structuralIndicatorCount;
                riskResult.IsSuspicious = hasNetworkIndicators || IsRiskScoreSuspicious(riskResult.OverallRiskScore);
                riskResult.Summary = BuildAnalysisSummary(riskResult, indicators);
                riskResult.AnalysedAt = DateTime.UtcNow;
                riskResult.DiscoveredDomain = domain;

                _logger.LogInformation(
                    "[DomainAnalyzerService] Analyze completed for {Domain}. Suspicious={IsSuspicious}, Indicators={Count}",
                    domain, riskResult.IsSuspicious, indicators.Count);

                return riskResult;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[DomainAnalyzerService] Unexpected failure while analyzing domain.");
                return BuildServiceFailureResult(domain, "Unexpected analyzer error. Returned structural fallback.");
            }
        }

        public bool IsKnownActiveDomain(string? domainInput)
        {
            try
            {
                var normalizedInput = NormalizeDomain(domainInput);
                if (string.IsNullOrWhiteSpace(normalizedInput))
                {
                    return false;
                }

                return _knownLegitimateDomains.Value.Contains(normalizedInput);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[DomainAnalyzerService] Failed checking active-domain match.");
                return false;
            }
        }

        public async Task<DomainAnalysisResult> AnalyzeDomainRiskAsync(string? domainInput)
        {
            try
            {
                var normalizedInput = NormalizeDomain(domainInput);
                if (string.IsNullOrWhiteSpace(normalizedInput))
                {
                    return BuildInvalidInputResult();
                }

                _logger.LogInformation(
                    "[DomainAnalyzerService] Structural risk analysis started for {Domain}.",
                    normalizedInput);

                if (_knownLegitimateDomains.Value.Contains(normalizedInput))
                {
                    return BuildKnownActiveDomainResult(normalizedInput);
                }

                var blocklistResult = await CheckBlocklistAsync(normalizedInput);
                if (blocklistResult.IsMatch)
                {
                    _logger.LogWarning(
                        "Domain {Domain} matched phishing blocklist ({Source})",
                        normalizedInput,
                        blocklistResult.Source);

                    var blocklistSignal = new DomainRiskSignalScore(
                        "Blocklist Match",
                        _riskThresholds.BlocklistMatchScore,
                        true,
                        $"Domain found in {blocklistResult.Source} feed.");

                    var emptySignal = new DomainRiskSignalScore("N/A", 0, false, "Domain matched phishing blocklist.");

                    return new DomainAnalysisResult
                    {
                        InputDomain = normalizedInput,
                        DiscoveredDomain = normalizedInput,
                        IsKnownActiveDomain = false,
                        IsValidDomain = true,
                        OverallRiskScore = _riskThresholds.BlocklistMatchScore,
                        RiskClassification = DomainAnalysisResult.ClassifyRiskScore(_riskThresholds.BlocklistMatchScore),
                        TopRiskSignal = blocklistSignal.Signal,
                        TopRiskSignalScore = blocklistSignal.Score,
                        TopRiskSignalDetail = blocklistSignal.Detail,
                        TyposquattingEditDistance = blocklistSignal,
                        ExcessiveSubdomains = blocklistSignal,
                        HyphenAbuse = blocklistSignal,
                        ShannonEntropy = blocklistSignal,
                        RepeatedSegment = emptySignal,
                        KeywordAbuse = emptySignal,
                        DomainRegistrationAge = emptySignal,
                        DomainRegistrationLifespan = emptySignal,
                        WhoisPrivacyProtection = emptySignal,
                        CharacterCompositionAnomaly = emptySignal,
                        IsBlocklistMatch = true,
                        BlocklistSource = blocklistResult.Source,
                        UsedBlocklistFallback = blocklistResult.IsStale,
                        IsSuspicious = true,
                        Summary = $"Domain matches phishing blocklist source {blocklistResult.Source}.",
                        AnalysedAt = DateTime.UtcNow
                    };
                }

                var typosquatting = CalculateTyposquattingScore(normalizedInput);
                LogSignal(normalizedInput, typosquatting);

                var subdomain = CalculateSubdomainScore(normalizedInput);
                LogSignal(normalizedInput, subdomain);

                var hyphen = CalculateHyphenScore(normalizedInput);
                LogSignal(normalizedInput, hyphen);

                var entropy = CalculateEntropyScore(normalizedInput);
                LogSignal(normalizedInput, entropy);

                var repeatedSegment = CalculateRepeatedSegmentScore(normalizedInput);
                LogSignal(normalizedInput, repeatedSegment);

                var keywordAbuse = CalculateKeywordAbuseScore(normalizedInput);
                LogSignal(normalizedInput, keywordAbuse);

                var registrationMetadata = await LookupRegistrationMetadataAsync(normalizedInput);

                var registrationAge = CalculateRegistrationAgeScore(registrationMetadata);
                LogSignal(normalizedInput, registrationAge);

                var registrationLifespan = CalculateRegistrationLifespanScore(registrationMetadata);
                LogSignal(normalizedInput, registrationLifespan);

                var whoisPrivacy = CalculateWhoisPrivacyScore(registrationMetadata);
                LogSignal(normalizedInput, whoisPrivacy);

                var characterComposition = CalculateCharacterCompositionScore(normalizedInput);
                LogSignal(normalizedInput, characterComposition);

                var signals = new[]
                {
                    typosquatting,
                    subdomain,
                    hyphen,
                    entropy,
                    repeatedSegment,
                    keywordAbuse,
                    registrationAge,
                    registrationLifespan,
                    whoisPrivacy,
                    characterComposition
                };

                // Cap at 100 so additive heuristic signals share the same ceiling
                // as a high-confidence blocklist match.
                var overallRisk = Math.Min(100, signals.Sum(signal => signal.Score));

                var triggeredSignals = signals
                    .Where(signal => signal.Triggered)
                    .Select(signal => signal.Signal)
                    .ToArray();

                _logger.LogInformation(
                    "[DomainAnalyzerService] Structural risk analysis completed for {Domain}. OverallRiskScore={Score} TriggeredSignals={TriggeredSignals}",
                    normalizedInput,
                    overallRisk,
                    triggeredSignals);

                if (blocklistResult.IsStale)
                {
                    _logger.LogWarning(
                        "Blocklist unavailable. Structural-only analysis used for {Domain}.",
                        normalizedInput);
                }

                var isSuspicious = IsRiskScoreSuspicious(overallRisk);

                var result = new DomainAnalysisResult
                {
                    InputDomain = normalizedInput,
                    DiscoveredDomain = normalizedInput,
                    IsKnownActiveDomain = false,
                    IsValidDomain = true,
                    OverallRiskScore = overallRisk,
                    RiskClassification = DomainAnalysisResult.ClassifyRiskScore(overallRisk),
                    TyposquattingEditDistance = typosquatting,
                    ExcessiveSubdomains = subdomain,
                    HyphenAbuse = hyphen,
                    ShannonEntropy = entropy,
                    RepeatedSegment = repeatedSegment,
                    KeywordAbuse = keywordAbuse,
                    DomainRegistrationAge = registrationAge,
                    DomainRegistrationLifespan = registrationLifespan,
                    WhoisPrivacyProtection = whoisPrivacy,
                    CharacterCompositionAnomaly = characterComposition,
                    RegistrationLookupFailureReason = registrationMetadata.FailureReason,
                    IsBlocklistMatch = false,
                    BlocklistSource = null,
                    UsedBlocklistFallback = blocklistResult.IsStale,
                    IsSuspicious = isSuspicious,
                    Summary = isSuspicious
                        ? "Structural risk indicators detected."
                        : overallRisk > 0
                        ? $"Structural risk score {overallRisk} is below suspicious threshold {_riskThresholds.EffectiveSuspiciousMinScore}."
                        : "No structural risk indicators detected.",
                    AnalysedAt = DateTime.UtcNow
                };

                result.ApplyTopRiskSignal(signals);
                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[DomainAnalyzerService] Risk analysis failed for domain input: {DomainInput}", domainInput);
                return BuildServiceFailureResult(domainInput, "Risk analysis failed; returning safe fallback.");
            }
        }

        private Task<BlocklistCheckResult> CheckBlocklistAsync(string domain)
        {
            if (_blocklistService is null)
            {
                return Task.FromResult(new BlocklistCheckResult
                {
                    IsMatch = false,
                    Source = "Unavailable",
                    LastUpdated = DateTime.UtcNow,
                    IsStale = true
                });
            }

            return _blocklistService.CheckAsync(domain);
        }

        private bool IsRiskScoreSuspicious(int overallRiskScore)
        {
            return overallRiskScore >= _riskThresholds.EffectiveSuspiciousMinScore;
        }

        private string BuildAnalysisSummary(
            DomainAnalysisResult riskResult,
            IReadOnlyCollection<string> indicators)
        {
            if (riskResult.IsSuspicious)
            {
                return $"Domain flagged with {indicators.Count} indicator(s), risk score {riskResult.OverallRiskScore}: {string.Join("; ", indicators)}.";
            }

            if (indicators.Count > 0)
            {
                return $"Domain has {indicators.Count} structural indicator(s), but risk score {riskResult.OverallRiskScore} is below suspicious threshold {_riskThresholds.EffectiveSuspiciousMinScore}: {string.Join("; ", indicators)}.";
            }

            return "No phishing indicators detected.";
        }

        // ── Pass 0: Structural risk checks ────────────────────────────────────

        private void AddRiskIndicators(string domain, DomainAnalysisResult riskResult, List<string> indicators)
        {
            var signals = new[]
            {
                riskResult.TyposquattingEditDistance,
                riskResult.ExcessiveSubdomains,
                riskResult.HyphenAbuse,
                riskResult.ShannonEntropy,
                riskResult.RepeatedSegment,
                riskResult.KeywordAbuse,
                riskResult.DomainRegistrationAge,
                riskResult.DomainRegistrationLifespan,
                riskResult.WhoisPrivacyProtection,
                riskResult.CharacterCompositionAnomaly
            };

            foreach (var signal in signals)
            {
                if (signal is not null && signal.Triggered)
                {
                    var indicator = $"{signal.Signal}: {signal.Detail}";
                    indicators.Add(indicator);
                    _logger.LogDebug(
                        "[DomainAnalyzerService] Static indicator added for {Domain}: {Signal} Indicator={Indicator}",
                        domain,
                        signal.Signal,
                        indicator);
                }
            }

            if (riskResult.IsBlocklistMatch)
            {
                var indicator = $"Blocklist Match: Domain found in {riskResult.BlocklistSource} feed.";
                indicators.Add(indicator);
                _logger.LogDebug(
                    "[DomainAnalyzerService] Static indicator added for {Domain}: {Signal} Indicator={Indicator}",
                    domain,
                    "Blocklist Match",
                    indicator);
            }
        }

        private DomainRiskSignalScore CalculateTyposquattingScore(string normalizedDomain)
        {
            var rootLabel = GetRootDomainLabel(normalizedDomain);
            if (string.IsNullOrWhiteSpace(rootLabel))
            {
                return new DomainRiskSignalScore("Typosquatting/Edit Distance", 0, false, "No root label available.");
            }

            IEnumerable<string> candidates = BuildTyposquattingCandidates(rootLabel);

            var closestBrand = string.Empty;
            var minDistance = int.MaxValue;
            foreach (var brand in candidates)
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
                1 => _riskThresholds.Typosquatting.EditDistanceOne,
                2 => _riskThresholds.Typosquatting.EditDistanceTwo,
                3 => _riskThresholds.Typosquatting.EditDistanceThree,
                _ => 0
            };

            return new DomainRiskSignalScore(
                "Typosquatting/Edit Distance",
                score,
                score > 0,
                score > 0
                    ? $"Root label '{rootLabel}' is {minDistance} edit(s) from known root '{closestBrand}'."
                    : "No suspicious root-label edit-distance match detected.");
        }

        private DomainRiskSignalScore CalculateSubdomainScore(string normalizedDomain)
        {
            var labels = normalizedDomain.Split('.', StringSplitOptions.RemoveEmptyEntries);
            var subdomainCount = Math.Max(labels.Length - 2, 0);

            var score = subdomainCount switch
            {
                <= 1 => 0,
                2 => _riskThresholds.Subdomains.TwoSubdomains,
                3 => _riskThresholds.Subdomains.ThreeSubdomains,
                _ => _riskThresholds.Subdomains.FourOrMoreSubdomains
            };

            return new DomainRiskSignalScore(
                "Excessive Subdomains",
                score,
                score > 0,
                $"Detected {subdomainCount} subdomain label(s).");
        }

        // Counts hyphens in the registrable label only. Hyphens that appear in subdomain prefixes
        // are covered by the KeywordAbuse signal and should not inflate the hyphen score.
        private DomainRiskSignalScore CalculateHyphenScore(string normalizedDomain)
        {
            var rootLabel = GetRootDomainLabel(normalizedDomain);

            var hyphenCount = rootLabel.Count(c => c == '-');
            var repeatedPatternCount = Regex.Matches(rootLabel, "--").Count;

            var score = hyphenCount switch
            {
                0 => 0,
                1 => _riskThresholds.HyphenAbuse.OneHyphen,
                2 => _riskThresholds.HyphenAbuse.TwoHyphens,
                3 => _riskThresholds.HyphenAbuse.ThreeHyphens,
                _ => _riskThresholds.HyphenAbuse.FourOrMoreHyphens
            };

            if (repeatedPatternCount > 0)
            {
                score = Math.Min(
                    _riskThresholds.HyphenAbuse.MaxScore,
                    score + repeatedPatternCount * _riskThresholds.HyphenAbuse.RepeatedHyphenBonus);
            }

            return new DomainRiskSignalScore(
                "Hyphen Abuse",
                score,
                score > 0,
                $"Detected {hyphenCount} hyphen(s) and {repeatedPatternCount} repeated hyphen pattern(s) in registrable label.");
        }

        // Computes Shannon entropy on the registrable label only. Using the full domain string
        // (including TLD characters) inflates low-entropy scores and dilutes genuine DGA signals.
        private DomainRiskSignalScore CalculateEntropyScore(string normalizedDomain)
        {
            var rootLabel = GetRootDomainLabel(normalizedDomain);
            var sample = new string(rootLabel.Where(char.IsLetterOrDigit).ToArray());
            var entropy = CalculateShannonEntropy(sample);

            var score = entropy switch
            {
                < 3.0 => 0,
                < 3.4 => _riskThresholds.ShannonEntropy.ModerateEntropy,
                < 3.8 => _riskThresholds.ShannonEntropy.HighEntropy,
                _ => _riskThresholds.ShannonEntropy.VeryHighEntropy
            };

            // Long, high-entropy labels are a strong DGA signal.
            if (rootLabel.Length >= 15 && entropy >= 3.5)
            {
                score = Math.Min(
                    _riskThresholds.ShannonEntropy.MaxScore,
                    score + _riskThresholds.ShannonEntropy.LongLabelBonus);
            }

            return new DomainRiskSignalScore(
                "Shannon Entropy",
                score,
                score > 0,
                $"Registrable label entropy is {entropy:F2}.");
        }

        // Detects consecutive repeated tokens in the subdomain chain (e.g., login.login.paypal.com)
        // or in the hyphen-delimited registrable label (e.g., login-login-paypal.com).
        // These patterns are almost exclusively machine-generated noise or low-effort spam.
        private DomainRiskSignalScore CalculateRepeatedSegmentScore(string normalizedDomain)
        {
            var labels = normalizedDomain.Split('.', StringSplitOptions.RemoveEmptyEntries);
            var consecutiveRepeatCount = 0;

            // Check for consecutive repeated labels in the subdomain chain.
            for (var i = 0; i < labels.Length - 1; i++)
            {
                if (labels[i].Equals(labels[i + 1], StringComparison.OrdinalIgnoreCase))
                {
                    consecutiveRepeatCount++;
                }
            }

            // Check for consecutive repeated tokens in the registrable label.
            if (labels.Length >= 2)
            {
                var rootLabel = labels[^2];
                var hyphenTokens = rootLabel.Split('-', StringSplitOptions.RemoveEmptyEntries);
                for (var i = 0; i < hyphenTokens.Length - 1; i++)
                {
                    if (hyphenTokens[i].Equals(hyphenTokens[i + 1], StringComparison.OrdinalIgnoreCase))
                    {
                        consecutiveRepeatCount++;
                    }
                }
            }

            var score = consecutiveRepeatCount switch
            {
                0 => 0,
                1 => _riskThresholds.RepeatedSegment.OneRepeatedSegment,
                _ => _riskThresholds.RepeatedSegment.MultipleRepeatedSegments
            };

            return new DomainRiskSignalScore(
                "Repeated Segment",
                score,
                score > 0,
                score > 0
                    ? $"Detected {consecutiveRepeatCount} consecutive repeated token(s)."
                    : "No repeated segment patterns detected.");
        }

        // Detects known phishing keywords embedded in the registrable label or any subdomain label.
        // Keyword presence in the registrable label (e.g., loginpaypal.com, paypal-login.com) is
        // scored higher than keywords appearing only in subdomain prefixes (e.g., login.paypal.com).
        private DomainRiskSignalScore CalculateKeywordAbuseScore(string normalizedDomain)
        {
            var labels = normalizedDomain.Split('.', StringSplitOptions.RemoveEmptyEntries);
            if (labels.Length < 2)
            {
                return new DomainRiskSignalScore("Keyword Abuse", 0, false, "No label available for keyword check.");
            }

            var rootLabel = labels[^2];
            var subdomainLabels = labels.Length > 2
                ? labels.Take(labels.Length - 2).ToArray()
                : Array.Empty<string>();

            var score = 0;
            var matchedKeywords = new List<string>();

            // Check if a phishing keyword is embedded in the registrable label itself.
            foreach (var keyword in PhishingKeywords)
            {
                if (rootLabel.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                {
                    score += _riskThresholds.KeywordAbuse.RootLabelKeyword;
                    matchedKeywords.Add($"'{keyword}' in label");
                    break; // One label-level keyword match is sufficient.
                }
            }

            // Check if any subdomain label is or contains a phishing keyword.
            foreach (var subLabel in subdomainLabels)
            {
                foreach (var keyword in PhishingKeywords)
                {
                    if (subLabel.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                    {
                        score += _riskThresholds.KeywordAbuse.SubdomainKeyword;
                        matchedKeywords.Add($"'{keyword}' in subdomain");
                        break; // One keyword per subdomain label is sufficient.
                    }
                }
            }

            score = Math.Min(_riskThresholds.KeywordAbuse.MaxScore, score);

            return new DomainRiskSignalScore(
                "Keyword Abuse",
                score,
                score > 0,
                score > 0
                    ? $"Phishing keyword(s) detected: {string.Join(", ", matchedKeywords)}."
                    : "No phishing keyword patterns detected.");
        }

        private async Task<DomainRegistrationMetadata> LookupRegistrationMetadataAsync(string normalizedDomain)
        {
            if (_registrationLookupService is null)
            {
                return new DomainRegistrationMetadata
                {
                    Domain = normalizedDomain,
                    IsLookupSuccessful = false,
                    FailureReason = "Registration lookup service is not configured."
                };
            }

            var metadata = await _registrationLookupService.LookupAsync(normalizedDomain);
            if (!metadata.IsLookupSuccessful)
            {
                _logger.LogInformation(
                    "[DomainAnalyzerService] Registration lookup unavailable for {Domain}: {Reason}",
                    normalizedDomain,
                    metadata.FailureReason);
            }

            return metadata;
        }

        // New domains are a strong phishing signal, but the lookup can be unavailable
        // for some TLDs. Missing registration data is recorded, not scored as risk.
        private DomainRiskSignalScore CalculateRegistrationAgeScore(
            DomainRegistrationMetadata metadata)
        {
            if (!metadata.IsLookupSuccessful)
            {
                return new DomainRiskSignalScore(
                    "Domain Registration Age",
                    0,
                    false,
                    $"Registration lookup unavailable: {metadata.FailureReason ?? "unknown reason"}");
            }

            if (!metadata.CreationDateUtc.HasValue)
            {
                return new DomainRiskSignalScore(
                    "Domain Registration Age",
                    0,
                    false,
                    "Creation date unavailable in registration data.");
            }

            var createdAt = metadata.CreationDateUtc.Value;
            var ageDays = Math.Floor((DateTime.UtcNow - createdAt).TotalDays);
            if (ageDays < 0)
            {
                return new DomainRiskSignalScore(
                    "Domain Registration Age",
                    0,
                    false,
                    $"Creation date {createdAt:yyyy-MM-dd} appears to be in the future.");
            }

            var score = ageDays switch
            {
                <= 30 => _riskThresholds.DomainRegistrationAge.ThirtyDaysOrLess,
                <= 90 => _riskThresholds.DomainRegistrationAge.NinetyDaysOrLess,
                _ => 0
            };

            return new DomainRiskSignalScore(
                "Domain Registration Age",
                score,
                score > 0,
                score > 0
                    ? $"Domain was registered {ageDays:N0} day(s) ago on {createdAt:yyyy-MM-dd}."
                    : $"Domain registration age is {ageDays:N0} day(s); no recent-registration signal.");
        }

        // Short registration windows are a weaker signal than creation age because
        // many legitimate domains renew annually. It still adds context when paired
        // with stronger structural or registration-age evidence.
        private DomainRiskSignalScore CalculateRegistrationLifespanScore(
            DomainRegistrationMetadata metadata)
        {
            if (!metadata.IsLookupSuccessful)
            {
                return new DomainRiskSignalScore(
                    "Domain Registration Lifespan",
                    0,
                    false,
                    $"Registration lookup unavailable: {metadata.FailureReason ?? "unknown reason"}");
            }

            if (!metadata.CreationDateUtc.HasValue || !metadata.ExpirationDateUtc.HasValue)
            {
                return new DomainRiskSignalScore(
                    "Domain Registration Lifespan",
                    0,
                    false,
                    "Creation or expiration date unavailable in registration data.");
            }

            var lifespanDays = Math.Floor(
                (metadata.ExpirationDateUtc.Value - metadata.CreationDateUtc.Value).TotalDays);
            if (lifespanDays <= 0)
            {
                return new DomainRiskSignalScore(
                    "Domain Registration Lifespan",
                    0,
                    false,
                    "Registration dates are incomplete or inconsistent.");
            }

            var score = lifespanDays switch
            {
                <= 370 => _riskThresholds.DomainRegistrationLifespan.OneYearOrLess,
                <= 730 => _riskThresholds.DomainRegistrationLifespan.TwoYearsOrLess,
                _ => 0
            };

            return new DomainRiskSignalScore(
                "Domain Registration Lifespan",
                score,
                score > 0,
                score > 0
                    ? $"Registration lifespan is approximately {lifespanDays:N0} day(s)."
                    : $"Registration lifespan is approximately {lifespanDays:N0} day(s); no short-lifespan signal.");
        }

        // Privacy protection is common and not malicious by itself, so it is kept as
        // a small signal that can reinforce stronger evidence without dominating it.
        private DomainRiskSignalScore CalculateWhoisPrivacyScore(
            DomainRegistrationMetadata metadata)
        {
            if (!metadata.IsLookupSuccessful)
            {
                return new DomainRiskSignalScore(
                    "WHOIS Privacy Protection",
                    0,
                    false,
                    $"Registration lookup unavailable: {metadata.FailureReason ?? "unknown reason"}");
            }

            return new DomainRiskSignalScore(
                "WHOIS Privacy Protection",
                metadata.HasPrivacyProtection ? _riskThresholds.WhoisPrivacyProtection.PrivacyProtected : 0,
                metadata.HasPrivacyProtection,
                metadata.HasPrivacyProtection
                    ? "Registration data appears redacted, withheld, or privacy-protected."
                    : "No privacy-protection marker detected in registration data.");
        }

        // Looks at measurable character ratios instead of curated keyword or TLD lists.
        // This complements Shannon entropy by explaining why a label looks unnatural.
        private DomainRiskSignalScore CalculateCharacterCompositionScore(
            string normalizedDomain)
        {
            var rootLabel = GetRootDomainLabel(normalizedDomain);
            if (string.IsNullOrWhiteSpace(rootLabel))
            {
                return new DomainRiskSignalScore(
                    "Character Composition Anomaly",
                    0,
                    false,
                    "No root label available for character composition analysis.");
            }

            var alphanumeric = rootLabel.Where(char.IsLetterOrDigit).ToArray();
            if (alphanumeric.Length == 0)
            {
                return new DomainRiskSignalScore(
                    "Character Composition Anomaly",
                    0,
                    false,
                    "No alphanumeric characters available for character composition analysis.");
            }

            var digitRatio = (double)alphanumeric.Count(char.IsDigit) / alphanumeric.Length;
            var letters = alphanumeric.Where(char.IsLetter).ToArray();
            var consonantRatio = letters.Length == 0
                ? 0
                : (double)letters.Count(IsConsonant) / letters.Length;
            var longestRepeatedRun = GetLongestRepeatedRun(rootLabel);

            var score = 0;
            var reasons = new List<string>();

            if (digitRatio >= 0.50)
            {
                score += _riskThresholds.CharacterCompositionAnomaly.HighDigitRatio;
                reasons.Add($"digit ratio {digitRatio:P0}");
            }
            else if (digitRatio >= 0.30)
            {
                score += _riskThresholds.CharacterCompositionAnomaly.ModerateDigitRatio;
                reasons.Add($"digit ratio {digitRatio:P0}");
            }

            if (letters.Length >= 6 && consonantRatio >= 0.85)
            {
                score += _riskThresholds.CharacterCompositionAnomaly.HighConsonantRatio;
                reasons.Add($"consonant ratio {consonantRatio:P0}");
            }

            if (longestRepeatedRun >= 5)
            {
                score += _riskThresholds.CharacterCompositionAnomaly.LongRepeatedRun;
                reasons.Add($"repeated character run of {longestRepeatedRun}");
            }
            else if (longestRepeatedRun >= 4)
            {
                score += _riskThresholds.CharacterCompositionAnomaly.ModerateRepeatedRun;
                reasons.Add($"repeated character run of {longestRepeatedRun}");
            }

            if (rootLabel.Length >= 24)
            {
                score += _riskThresholds.CharacterCompositionAnomaly.LongLabel;
                reasons.Add($"root label length {rootLabel.Length}");
            }

            score = Math.Min(_riskThresholds.CharacterCompositionAnomaly.MaxScore, score);

            return new DomainRiskSignalScore(
                "Character Composition Anomaly",
                score,
                score > 0,
                score > 0
                    ? $"Composition anomaly detected: {string.Join(", ", reasons)}."
                    : "No character composition anomaly detected.");
        }

        private static bool IsConsonant(char value)
        {
            var c = char.ToLowerInvariant(value);
            return c is >= 'a' and <= 'z' && !"aeiou".Contains(c);
        }

        private static int GetLongestRepeatedRun(string value)
        {
            var longest = 0;
            var current = 0;
            char? previous = null;

            foreach (var c in value)
            {
                if (previous.HasValue && c == previous.Value)
                {
                    current++;
                }
                else
                {
                    current = 1;
                    previous = c;
                }

                longest = Math.Max(longest, current);
            }

            return longest;
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

        private IEnumerable<string> BuildTyposquattingCandidates(string rootLabel)
        {
            if (_knownLegitimateRootDomains.Value.Count == 0)
            {
                return KnownBrands;
            }

            var matches = new List<string>();
            for (var length = rootLabel.Length - 3; length <= rootLabel.Length + 3; length++)
            {
                if (_knownLegitimateRootsByLength.Value.TryGetValue(length, out var roots))
                {
                    matches.AddRange(roots);
                }
            }

            return matches.Count > 0 ? matches : _knownLegitimateRootDomains.Value;
        }

        private HashSet<string> LoadKnownLegitimateDomains()
        {
            try
            {
                if (!File.Exists(_legitimateDomainsFilePath))
                {
                    _logger.LogWarning("Legitimate domain list not found at path: {Path}", _legitimateDomainsFilePath);
                    return new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                }

                var domains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                foreach (var line in File.ReadLines(_legitimateDomainsFilePath))
                {
                    var normalized = NormalizeDomain(line);
                    if (!string.IsNullOrWhiteSpace(normalized))
                    {
                        domains.Add(normalized);
                    }
                }

                _logger.LogInformation("Loaded {Count} legitimate domains for risk analysis.", domains.Count);
                return domains;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to load legitimate domain list from path: {Path}", _legitimateDomainsFilePath);
                return new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            }
        }

        private void LogSignal(string domain, DomainRiskSignalScore signal)
        {
            _logger.LogDebug(
                "[DomainAnalyzerService] Signal calculated for {Domain}: {Signal} Score={Score} Triggered={Triggered} Detail={Detail}",
                domain,
                signal.Signal,
                signal.Score,
                signal.Triggered,
                signal.Detail);
        }

        // ── Result builders ───────────────────────────────────────────────────

        private static DomainAnalysisResult BuildServiceFailureResult(string? domainInput, string message)
        {
            var safeDomain = NormalizeDomain(domainInput) ?? string.Empty;
            var emptySignal = new DomainRiskSignalScore("N/A", 0, false, "Analyzer fallback due to internal error.");
            return new DomainAnalysisResult
            {
                InputDomain = safeDomain,
                DiscoveredDomain = safeDomain,
                IsKnownActiveDomain = false,
                IsValidDomain = !string.IsNullOrWhiteSpace(safeDomain),
                OverallRiskScore = 0,
                RiskClassification = DomainAnalysisResult.ClassifyRiskScore(0),
                TyposquattingEditDistance = emptySignal,
                ExcessiveSubdomains = emptySignal,
                HyphenAbuse = emptySignal,
                ShannonEntropy = emptySignal,
                RepeatedSegment = emptySignal,
                KeywordAbuse = emptySignal,
                DomainRegistrationAge = emptySignal,
                DomainRegistrationLifespan = emptySignal,
                WhoisPrivacyProtection = emptySignal,
                CharacterCompositionAnomaly = emptySignal,
                RegistrationLookupFailureReason = "Analyzer fallback due to internal error.",
                IsBlocklistMatch = false,
                UsedBlocklistFallback = true,
                IsSuspicious = false,
                Summary = message,
                AnalysedAt = DateTime.UtcNow,
                Indicators = new List<string>()
            };
        }

        private static DomainAnalysisResult BuildInvalidInputResult()
        {
            var emptySignal = new DomainRiskSignalScore("N/A", 0, false, "Invalid input.");
            return new DomainAnalysisResult
            {
                InputDomain = string.Empty,
                DiscoveredDomain = string.Empty,
                IsKnownActiveDomain = false,
                IsValidDomain = false,
                OverallRiskScore = 0,
                RiskClassification = DomainAnalysisResult.ClassifyRiskScore(0),
                TyposquattingEditDistance = emptySignal,
                ExcessiveSubdomains = emptySignal,
                HyphenAbuse = emptySignal,
                ShannonEntropy = emptySignal,
                RepeatedSegment = emptySignal,
                KeywordAbuse = emptySignal,
                DomainRegistrationAge = emptySignal,
                DomainRegistrationLifespan = emptySignal,
                WhoisPrivacyProtection = emptySignal,
                CharacterCompositionAnomaly = emptySignal,
                RegistrationLookupFailureReason = "Invalid input.",
                IsBlocklistMatch = false,
                IsSuspicious = false,
                Summary = "No domain supplied - analysis skipped.",
                AnalysedAt = DateTime.UtcNow,
                Indicators = new List<string>()
            };
        }

        private static DomainAnalysisResult BuildKnownActiveDomainResult(string domain)
        {
            var noRisk = new DomainRiskSignalScore("N/A", 0, false, "Domain is already in Legitimate_Domains.txt.");
            return new DomainAnalysisResult
            {
                InputDomain = domain,
                DiscoveredDomain = domain,
                IsKnownActiveDomain = true,
                IsValidDomain = true,
                OverallRiskScore = 0,
                RiskClassification = DomainAnalysisResult.ClassifyRiskScore(0),
                TyposquattingEditDistance = noRisk,
                ExcessiveSubdomains = noRisk,
                HyphenAbuse = noRisk,
                ShannonEntropy = noRisk,
                RepeatedSegment = noRisk,
                KeywordAbuse = noRisk,
                DomainRegistrationAge = noRisk,
                DomainRegistrationLifespan = noRisk,
                WhoisPrivacyProtection = noRisk,
                CharacterCompositionAnomaly = noRisk,
                IsBlocklistMatch = false,
                IsSuspicious = false,
                Summary = "Domain found in active-domain list.",
                AnalysedAt = DateTime.UtcNow,
                Indicators = new List<string>()
            };
        }

        // ── Passes 1–3: Network checks ────────────────────────────────────────

        private async Task RunNetworkChecksAsync(string domain, List<string> indicators)
        {
            // 1. DNS Pre-flight: If the domain doesn't exist, don't bother with HTTP/SSL.
            if (!await IsDomainResolvableAsync(domain))
            {
                _logger.LogInformation("[DomainAnalyzerService] Domain {Domain} has no DNS records. Skipping network checks.", domain);
                return;
            }

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(_timeoutSeconds));

            try
            {
                await CheckRedirectAsync(domain, indicators, cts.Token);

                var sslIndicators = await _sslChecker.GetSslIndicatorsAsync(domain, cts.Token);
                indicators.AddRange(sslIndicators);

                await CheckHtmlContentAsync(domain, indicators, cts.Token);
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("[DomainAnalyzerService] Timeout analyzing {Domain}", domain);
                indicators.Add("Analysis timed out - server may be tarpitting or unresponsive");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[DomainAnalyzerService] Error during network checks for {Domain}", domain);
            }
        }

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
                        indicators.Add($"Cross-domain redirect detected -> {targetHost}");
                        _logger.LogInformation(
                            "[DomainAnalyzerService] Cross-domain redirect detected for {Domain} -> {RedirectTarget}",
                            domain,
                            targetHost);
                    }
                }
            }
        }

        private async Task CheckHtmlContentAsync(string domain, List<string> indicators, CancellationToken ct)
        {
            var client = _httpClientFactory.CreateClient("DomainAnalyzer.Follow");
            HttpResponseMessage? response = null;

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
                    indicators.Add("No HTTPS support - domain only responds on plain HTTP");
                }
                catch
                {
                    _logger.LogInformation(
                        "[DomainAnalyzerService] {Domain} unreachable on HTTPS and HTTP; HTML checks skipped.",
                        domain);
                    return;
                }
            }

            using (response)
            {
                if (response is null)
                {
                    return;
                }

                var contentType = response.Content.Headers.ContentType?.MediaType ?? string.Empty;
                if (!contentType.Contains("html", StringComparison.OrdinalIgnoreCase))
                {
                    return;
                }

                var html = await response.Content.ReadAsStringAsync(ct);
                if (string.IsNullOrWhiteSpace(html))
                {
                    return;
                }

                // Pre-compute domain tokens once so all brand-mismatch checks can reuse them.
                var domainTokens = domain
                    .ToLowerInvariant()
                    .Split('.', StringSplitOptions.RemoveEmptyEntries)
                    .SelectMany(l => l.Split('-', StringSplitOptions.RemoveEmptyEntries))
                    .ToHashSet(StringComparer.Ordinal);

                if (Regex.IsMatch(html,
                    @"<input[^>]+type\s*=\s*[""']?password[""']?",
                    RegexOptions.IgnoreCase))
                {
                    indicators.Add("Password input field detected in page HTML");
                }

                if (Regex.IsMatch(html,
                    @"<form[^>]+(action|id|class)\s*=\s*[""'][^""']*(login|signin|logon|authenticate)[^""']*[""']",
                    RegexOptions.IgnoreCase))
                {
                    indicators.Add("Login form detected in page HTML");
                }

                // Iframes are commonly used in phishing pages to load legitimate-looking
                // content while credential harvesting happens in the background.
                if (Regex.IsMatch(html, @"<iframe\s", RegexOptions.IgnoreCase))
                {
                    indicators.Add("Iframe element detected in page HTML");
                }

                var titleMatch = Regex.Match(html,
                    @"<title[^>]*>(.*?)</title>",
                    RegexOptions.IgnoreCase | RegexOptions.Singleline);

                if (titleMatch.Success)
                {
                    var title = titleMatch.Groups[1].Value.ToLowerInvariant();
                    var brandInTitle = Array.Find(KnownBrands,
                        b => title.Contains(b, StringComparison.Ordinal));

                    if (brandInTitle is not null && !domainTokens.Contains(brandInTitle))
                    {
                        indicators.Add(
                            $"Brand keyword mismatch: page title references '{brandInTitle}' but domain does not");
                    }
                }

                CheckMetaBrandMismatch(html, domainTokens, indicators);
            }
        }

        // Scans <meta name="description"> and <meta name="keywords"> tags for brand names that
        // don't appear in the domain itself — a strong signal that a page is impersonating a brand.
        private static void CheckMetaBrandMismatch(
            string html,
            HashSet<string> domainTokens,
            List<string> indicators)
        {
            foreach (Match metaTag in Regex.Matches(html, @"<meta\s[^>]*>", RegexOptions.IgnoreCase))
            {
                var tag = metaTag.Value;

                // Only inspect description and keywords meta tags.
                if (!Regex.IsMatch(tag,
                    @"name\s*=\s*[""']?\s*(description|keywords)\s*[""']?",
                    RegexOptions.IgnoreCase))
                {
                    continue;
                }

                var contentMatch = Regex.Match(tag,
                    @"content\s*=\s*[""']([^""']*)[""']",
                    RegexOptions.IgnoreCase);

                if (!contentMatch.Success)
                {
                    continue;
                }

                var content = contentMatch.Groups[1].Value.ToLowerInvariant();
                var brandInMeta = Array.Find(KnownBrands,
                    b => content.Contains(b, StringComparison.Ordinal));

                if (brandInMeta is not null && !domainTokens.Contains(brandInMeta))
                {
                    indicators.Add(
                        $"Brand keyword mismatch: meta tag references '{brandInMeta}' but domain does not");
                    return; // One meta mismatch indicator is sufficient.
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
                return false;
            }
        }
    }
}
