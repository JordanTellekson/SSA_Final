using SSA_Final.Models;

namespace SSA_Final.Interfaces
{
    public interface IReportService
    {
        Task<HighRiskAlertReport> GenerateHighRiskAlertReportAsync(
            TimeSpan? lookbackWindow = null,
            CancellationToken cancellationToken = default);

        string ToCsv(HighRiskAlertReport report);
    }
}
