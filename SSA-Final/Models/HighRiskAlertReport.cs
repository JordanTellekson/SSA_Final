namespace SSA_Final.Models
{
    public class HighRiskAlertReport
    {
        public DateTime GeneratedAtUtc { get; set; } = DateTime.UtcNow;

        public DateTime LookbackStartUtc { get; set; }

        public DateTime LookbackEndUtc { get; set; } = DateTime.UtcNow;

        public double LookbackHours { get; set; }

        public IReadOnlyList<HighRiskAlertReportItem> Items { get; set; } =
            Array.Empty<HighRiskAlertReportItem>();
    }
}
