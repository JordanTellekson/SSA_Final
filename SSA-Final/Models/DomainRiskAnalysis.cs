namespace SSA_Final.Models
{
    public class DomainRiskAnalysis
    {
        public string DomainName { get; set; } = string.Empty;

        public bool IsSuspicious { get; set; }

        public string Reason { get; set; } = string.Empty;

        public string Notes { get; set; } = string.Empty;
    }
}
