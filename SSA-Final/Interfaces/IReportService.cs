using SSA_Final.Models;

namespace SSA_Final.Interfaces
{
    public interface IReportService
    {
        Task<HighRiskAlertReport> GenerateHighRiskAlertReportAsync(
            TimeSpan? lookbackWindow = null,
            CancellationToken cancellationToken = default);

        Task<DomainAnalysisReport> GenerateDomainAnalysisReportAsync(
            TimeSpan? lookbackWindow = null,
            bool suspiciousOnly = false,
            DateTime? startUtc = null,
            DateTime? endUtc = null,
            CancellationToken cancellationToken = default);

        string ToCsv(HighRiskAlertReport report);

        string ToCsv(DomainAnalysisReport report);
    }
}
