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

        // Risk-analysis fields merged from DomainRiskAnalysisResult.
        [NotMapped]
        public string InputDomain { get; set; } = string.Empty;

        [NotMapped]
        public bool IsKnownActiveDomain { get; set; }

        [NotMapped]
        public bool IsValidDomain { get; set; } = true;

        [NotMapped]
        public int OverallRiskScore { get; set; }

        [NotMapped]
        public DomainRiskSignalScore? TyposquattingEditDistance { get; set; }

        [NotMapped]
        public DomainRiskSignalScore? ExcessiveSubdomains { get; set; }

        [NotMapped]
        public DomainRiskSignalScore? HyphenAbuse { get; set; }

        [NotMapped]
        public DomainRiskSignalScore? ShannonEntropy { get; set; }

        [NotMapped]
        public bool IsBlocklistMatch { get; set; }

        [NotMapped]
        public string? BlocklistSource { get; set; }

        [NotMapped]
        public bool UsedBlocklistFallback { get; set; }
    }
}

