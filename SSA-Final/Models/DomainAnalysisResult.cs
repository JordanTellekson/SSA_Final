namespace SSA_Final.Models
{
    public class DomainAnalysisResult
    {
        /// <summary>The domain name that was analysed.</summary>
        public string DomainName { get; set; } = string.Empty;

        /// <summary>
        /// Indicates whether the domain was flagged as potentially malicious.
        /// </summary>
        public bool IsSuspicious { get; set; }

        /// <summary>Main reason for the suspicious/non-suspicious classification.</summary>
        public string Reason { get; set; } = string.Empty;

        /// <summary>Additional analyst or system notes related to this result.</summary>
        public string Notes { get; set; } = string.Empty;

        /// <summary>UTC timestamp at which the analysis completed.</summary>
        public DateTime AnalysedAt { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// Individual indicator findings (e.g. "Homoglyph detected", "Newly registered").
        /// May be empty.
        /// </summary>
        public IList<string> Indicators { get; set; } = new List<string>();

        // Backward-compatible alias for older code paths.
        public string Domain
        {
            get => DomainName;
            set => DomainName = value ?? string.Empty;
        }

        // Backward-compatible alias for older code paths.
        public string Summary
        {
            get => Reason;
            set => Reason = value ?? string.Empty;
        }
    }
}
