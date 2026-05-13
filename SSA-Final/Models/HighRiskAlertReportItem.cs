namespace SSA_Final.Models
{
    public class HighRiskAlertReportItem
    {
        public Guid ScanId { get; set; }

        public DateTime ScanTimestampUtc { get; set; }

        public string BaseDomain { get; set; } = string.Empty;

        public int SuspiciousVariantCount { get; set; }

        public string? TopSignal { get; set; }

        public int TopSignalScore { get; set; }

        public string? TopSignalDetail { get; set; }

        public bool HasBlocklistMatch { get; set; }

        public string? BlocklistSource { get; set; }
    }
}
