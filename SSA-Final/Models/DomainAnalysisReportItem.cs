namespace SSA_Final.Models
{
    public class DomainAnalysisReportItem
    {
        public Guid ScanId { get; set; }

        public string BaseDomain { get; set; } = string.Empty;

        public DomainScanStatus ScanStatus { get; set; }

        public ScanTrigger ScanTrigger { get; set; }

        public string DiscoveredDomain { get; set; } = string.Empty;

        public bool IsSuspicious { get; set; }

        public string RiskClassification { get; set; } = string.Empty;

        public int OverallRiskScore { get; set; }

        public string Summary { get; set; } = string.Empty;

        public IReadOnlyList<string> Indicators { get; set; } = Array.Empty<string>();

        public DateTime AnalysedAtUtc { get; set; }
    }
}
