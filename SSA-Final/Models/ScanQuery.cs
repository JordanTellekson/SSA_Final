namespace SSA_Final.Models
{
    public class ScanQuery
    {
        public string? Query { get; set; }
        public int Page { get; set; } = 1;
        public int PageSize { get; set; } = 25;
        public DomainScanStatus? Status { get; set; }
        public bool? HasMalicious { get; set; }
    }
}
