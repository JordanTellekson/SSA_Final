namespace SSA_Final.Models
{
    public class DomainScan
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public string BaseDomain { get; set; } = string.Empty;
        public DateTime ScannedAt { get; set; } = DateTime.UtcNow;
        public DomainScanStatus Status { get; set; } = DomainScanStatus.Complete;
        public List<DomainAnalysisResult> Variants { get; set; } = new();
        public int MaliciousCount => Variants.Count(v => v.IsSuspicious);
    }
}