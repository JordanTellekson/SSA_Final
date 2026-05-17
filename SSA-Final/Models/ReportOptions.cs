namespace SSA_Final.Models
{
    public class ReportOptions
    {
        public const string SectionName = "Reports";

        public double HighRiskLookbackHours { get; set; } = 24;

        public TimeSpan GetLookbackWindow()
        {
            return TimeSpan.FromHours(HighRiskLookbackHours > 0 ? HighRiskLookbackHours : 24);
        }
    }
}
