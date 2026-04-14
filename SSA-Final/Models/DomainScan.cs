namespace SSA_Final.Models
{
    public class DomainScan
    {
        public Guid Id { get; set; } = Guid.NewGuid();

        // User-story canonical fields
        public string BaseDomain { get; set; } = string.Empty;

        public DateTime ScanDate { get; set; } = DateTime.UtcNow;

        public IList<DomainAnalysisResult> Results { get; set; } = new List<DomainAnalysisResult>();

        public IList<DomainRiskAnalysis> RiskAnalyses { get; set; } = new List<DomainRiskAnalysis>();

        // Existing app fields
        public DateTime TimeFinished { get; set; }

        public DomainScanStatus Status { get; set; } = DomainScanStatus.Pending;

        // Backward-compatible aliases used by existing controllers/views
        public string Domain
        {
            get => BaseDomain;
            set => BaseDomain = value ?? string.Empty;
        }

        public DateTime CreatedAt
        {
            get => ScanDate;
            set => ScanDate = value;
        }

        public int NumMaliciousDomains
        {
            get => RiskAnalyses.Count != 0
                ? RiskAnalyses.Count(r => r.IsSuspicious)
                : Results.Count(r => r.IsSuspicious);
            set { /* computed from Results */ }
        }
    }
}
