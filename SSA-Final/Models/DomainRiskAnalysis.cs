namespace SSA_Final.Models
{
    /// <summary>
    /// Simplified risk record for one domain variant.
    /// </summary>
    public class DomainRiskAnalysis
    {
        /// <summary>
        /// Domain that was evaluated.
        /// </summary>
        public string DomainName { get; set; } = string.Empty;

        /// <summary>
        /// Whether the variant was flagged as suspicious.
        /// </summary>
        public bool IsSuspicious { get; set; }

        /// <summary>
        /// Primary reason for the suspiciousness decision.
        /// </summary>
        public string Reason { get; set; } = string.Empty;

        /// <summary>
        /// Additional human-readable investigation notes.
        /// </summary>
        public string Notes { get; set; } = string.Empty;
    }
}
