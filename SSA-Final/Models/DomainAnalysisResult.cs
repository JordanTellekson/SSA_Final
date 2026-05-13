// Entity/model representing the analysis outcome for a generated domain variant.

using System.ComponentModel.DataAnnotations.Schema;

namespace SSA_Final.Models
{
    public class DomainAnalysisResult
    {
        public Guid Id { get; set; } = Guid.NewGuid();

        public Guid DomainScanId { get; set; }

        /// <summary>The discovered domain that was analysed.</summary>
        public string DiscoveredDomain { get; set; } = string.Empty;

        /// <summary>
        /// Indicates whether the domain was flagged as potentially malicious.
        /// </summary>
        public bool IsSuspicious { get; set; }

        /// <summary>
        /// Named classification for the numeric risk score.
        /// </summary>
        public string RiskClassification { get; set; } = ClassifyRiskScore(0);

        /// <summary>
        /// A human-readable summary produced by the analyser.
        /// Empty when no issues are detected.
        /// </summary>
        public string Summary { get; set; } = string.Empty;

        /// <summary>UTC timestamp at which the analysis completed.</summary>
        public DateTime AnalysedAt { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// Individual indicator findings (e.g. "Homoglyph detected", "Newly registered").
        /// May be empty.
        /// </summary>
        public IList<string> Indicators { get; set; } = new List<string>();

        /// <summary>
        /// Normalized input domain used by the risk analyzer after URL parsing
        /// and host cleanup.
        /// </summary>
        [NotMapped]
        public string InputDomain { get; set; } = string.Empty;

        /// <summary>
        /// True when the domain is present in the configured legitimate-domain
        /// allow list and should bypass heuristic scoring.
        /// </summary>
        [NotMapped]
        public bool IsKnownActiveDomain { get; set; }

        /// <summary>
        /// False when the supplied value could not be normalized into a domain
        /// that the analyzer can score.
        /// </summary>
        [NotMapped]
        public bool IsValidDomain { get; set; } = true;

        /// <summary>
        /// Additive risk score from all triggered risk signals. The analyzer
        /// caps this at 100 so it stays aligned with the risk classification scale.
        /// </summary>
        public int OverallRiskScore { get; set; }

        /// <summary>
        /// Highest-scoring signal captured for persisted alert reports.
        /// </summary>
        public string? TopRiskSignal { get; set; }

        /// <summary>
        /// Score contribution from <see cref="TopRiskSignal"/>.
        /// </summary>
        public int TopRiskSignalScore { get; set; }

        /// <summary>
        /// Human-readable detail for the highest-scoring signal.
        /// </summary>
        public string? TopRiskSignalDetail { get; set; }

        /// <summary>
        /// Score for edit-distance similarity between the domain root label and
        /// known legitimate roots or brands.
        /// </summary>
        [NotMapped]
        public DomainRiskSignalScore? TyposquattingEditDistance { get; set; }

        /// <summary>
        /// Score for excessive subdomain depth, such as login.secure.verify.example.com.
        /// </summary>
        [NotMapped]
        public DomainRiskSignalScore? ExcessiveSubdomains { get; set; }

        /// <summary>
        /// Score for unusual hyphen density in the registrable label.
        /// </summary>
        [NotMapped]
        public DomainRiskSignalScore? HyphenAbuse { get; set; }

        /// <summary>
        /// Score for high Shannon entropy in the registrable label.
        /// </summary>
        [NotMapped]
        public DomainRiskSignalScore? ShannonEntropy { get; set; }

        /// <summary>
        /// Score for repeated labels or repeated hyphen-delimited segments.
        /// </summary>
        [NotMapped]
        public DomainRiskSignalScore? RepeatedSegment { get; set; }

        /// <summary>
        /// Score for phishing-oriented keywords already supported by the analyzer.
        /// This remains a weak, list-derived signal and is balanced below the
        /// registration-derived signals.
        /// </summary>
        [NotMapped]
        public DomainRiskSignalScore? KeywordAbuse { get; set; }

        /// <summary>
        /// Score for domains whose RDAP/WHOIS creation date indicates very recent
        /// registration.
        /// </summary>
        [NotMapped]
        public DomainRiskSignalScore? DomainRegistrationAge { get; set; }

        /// <summary>
        /// Score for domains whose RDAP/WHOIS dates indicate a short registration
        /// lifespan.
        /// </summary>
        [NotMapped]
        public DomainRiskSignalScore? DomainRegistrationLifespan { get; set; }

        /// <summary>
        /// Score for privacy-protected, redacted, or withheld registrant metadata
        /// found in RDAP/WHOIS data. This is intentionally weak because privacy
        /// protection is common for legitimate domains too.
        /// </summary>
        [NotMapped]
        public DomainRiskSignalScore? WhoisPrivacyProtection { get; set; }

        /// <summary>
        /// Score for data-derived character composition anomalies such as high
        /// digit density, long labels, consonant-heavy labels, or repeated runs.
        /// </summary>
        [NotMapped]
        public DomainRiskSignalScore? CharacterCompositionAnomaly { get; set; }

        /// <summary>
        /// Non-empty when registration lookup failed or returned insufficient
        /// metadata. This keeps lookup failures visible without treating them as
        /// phishing evidence.
        /// </summary>
        [NotMapped]
        public string? RegistrationLookupFailureReason { get; set; }

        /// <summary>
        /// True when the domain matched a high-confidence external phishing feed.
        /// </summary>
        public bool IsBlocklistMatch { get; set; }

        /// <summary>
        /// Name of the external feed that produced the blocklist match.
        /// </summary>
        public string? BlocklistSource { get; set; }

        /// <summary>
        /// True when the analyzer had to continue with stale or unavailable
        /// blocklist data.
        /// </summary>
        [NotMapped]
        public bool UsedBlocklistFallback { get; set; }

        public static string ClassifyRiskScore(int riskScore)
        {
            var normalizedScore = Math.Clamp(riskScore, 0, 100);

            return normalizedScore switch
            {
                <= 24 => "Low",
                <= 49 => "Medium",
                <= 74 => "High",
                _ => "Critical"
            };
        }

        public static string NormalizeRiskClassification(string? riskClassification)
        {
            return riskClassification switch
            {
                "Medium" => "Medium",
                "High" => "High",
                "Critical" => "Critical",
                _ => "Low"
            };
        }

        public void ApplyTopRiskSignal(IEnumerable<DomainRiskSignalScore?> signals)
        {
            var topSignal = signals
                .Where(signal => signal is not null)
                .Select(signal => signal!)
                .Where(signal => signal.Score > 0 || signal.Triggered)
                .OrderByDescending(signal => signal.Score)
                .ThenBy(signal => signal.Signal)
                .FirstOrDefault();

            TopRiskSignal = topSignal?.Signal;
            TopRiskSignalScore = topSignal?.Score ?? 0;
            TopRiskSignalDetail = topSignal?.Detail;
        }
    }
}

