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
    }
}