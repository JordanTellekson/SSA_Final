namespace SSA_Final.Models
{
    public class LegitimateDomainBatch
    {
        public int StartIndex { get; set; }
        public int NextStartIndex { get; set; }
        public int TotalCount { get; set; }
        public int BatchSize { get; set; }
        public List<string> Domains { get; set; } = new();

        public bool HasDomains => Domains.Count > 0;
        public bool HasMore => NextStartIndex < TotalCount;
    }
}
