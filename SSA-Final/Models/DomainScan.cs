namespace SSA_Final.Models
{
    /// <summary>
    /// Represents one scan job for a base domain and its generated variant analyses.
    /// </summary>
    public class DomainScan
    {
        /// <summary>
        /// Unique scan identifier.
        /// </summary>
        public Guid Id { get; set; } = Guid.NewGuid();

        /// <summary>
        /// Base domain submitted by the user (for example, <c>example.com</c>).
        /// </summary>
        public string BaseDomain { get; set; } = string.Empty;

        /// <summary>
        /// UTC timestamp when the scan started.
        /// </summary>
        public DateTime ScanDate { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// Per-variant analysis results produced by the analyzer.
        /// </summary>
        public IList<DomainAnalysisResult> Results { get; set; } = new List<DomainAnalysisResult>();

        /// <summary>
        /// Normalized risk-analysis projections used by risk-focused views.
        /// </summary>
        public IList<DomainRiskAnalysis> RiskAnalyses { get; set; } = new List<DomainRiskAnalysis>();

        /// <summary>
        /// UTC timestamp when the scan processing completed.
        /// </summary>
        public DateTime TimeFinished { get; set; }

        /// <summary>
        /// High-level lifecycle state of the scan.
        /// </summary>
        public DomainScanStatus Status { get; set; } = DomainScanStatus.Pending;

        /// <summary>
        /// Number of suspicious results in the scan.
        /// </summary>
        public int NumMaliciousDomains
        {
            get => RiskAnalyses.Count != 0
                ? RiskAnalyses.Count(r => r.IsSuspicious)
                : Results.Count(r => r.IsSuspicious);
            set { /* computed from Results */ }
        }
    }
}
