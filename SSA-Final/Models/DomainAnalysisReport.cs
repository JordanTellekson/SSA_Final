namespace SSA_Final.Models
{
    public class DomainAnalysisReport
    {
        public DateTime GeneratedAtUtc { get; set; } = DateTime.UtcNow;

        public DateTime LookbackStartUtc { get; set; }

        public DateTime LookbackEndUtc { get; set; } = DateTime.UtcNow;

        public double LookbackHours { get; set; }

        public bool SuspiciousOnly { get; set; }

        public IReadOnlyList<DomainAnalysisReportItem> Items { get; set; } =
            Array.Empty<DomainAnalysisReportItem>();
    }
}
