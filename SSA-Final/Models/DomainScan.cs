namespace SSA_Final.Models
{
    public class DomainScan
    {
        public string Domain { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime TimeFinished { get; set; }
        public int NumMaliciousDomains { get; set; }
        public DomainScanStatus Status { get; set; }
    }
}
