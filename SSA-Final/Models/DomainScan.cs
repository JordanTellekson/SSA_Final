namespace SSA_Final.Models
{
    public class DomainScan
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public string BaseDomain { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime? TimeFinished { get; set; }
        public DomainScanStatus Status { get; set; } = DomainScanStatus.Pending;
        public int NumMaliciousDomains { get; set; }
        public List<DomainAnalysisResult> Variants { get; set; } = new();
    }
}