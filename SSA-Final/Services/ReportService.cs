using System.Globalization;
using System.Text;
using Microsoft.Extensions.Configuration;
using SSA_Final.Interfaces;
using SSA_Final.Models;

namespace SSA_Final.Services
{
    public class ReportService : IReportService
    {
        private readonly IScanStore _scanStore;
        private readonly ReportOptions _options;

        public ReportService(IScanStore scanStore, IConfiguration configuration)
        {
            _scanStore = scanStore;
            _options = new ReportOptions();
            configuration.GetSection(ReportOptions.SectionName).Bind(_options);
        }

        public async Task<HighRiskAlertReport> GenerateHighRiskAlertReportAsync(
            TimeSpan? lookbackWindow = null,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var window = lookbackWindow ?? _options.GetLookbackWindow();
            var lookbackEnd = DateTime.UtcNow;
            var lookbackStart = lookbackEnd - window;
            var scans = await _scanStore.GetCompletedHighRiskScansAsync(window);

            var items = scans
                .Select(BuildReportItem)
                .OrderByDescending(item => item.ScanTimestampUtc)
                .ThenBy(item => item.BaseDomain, StringComparer.OrdinalIgnoreCase)
                .ToList();

            return new HighRiskAlertReport
            {
                GeneratedAtUtc = lookbackEnd,
                LookbackStartUtc = lookbackStart,
                LookbackEndUtc = lookbackEnd,
                LookbackHours = window.TotalHours,
                Items = items
            };
        }

        public string ToCsv(HighRiskAlertReport report)
        {
            var csv = new StringBuilder();
            csv.AppendLine("ScanId,ScanTimestampUtc,BaseDomain,SuspiciousVariantCount,TopSignal,TopSignalScore,TopSignalDetail,HasBlocklistMatch,BlocklistSource");

            foreach (var item in report.Items)
            {
                csv.Append(Csv(item.ScanId.ToString()));
                csv.Append(',');
                csv.Append(Csv(item.ScanTimestampUtc.ToString("O", CultureInfo.InvariantCulture)));
                csv.Append(',');
                csv.Append(Csv(item.BaseDomain));
                csv.Append(',');
                csv.Append(item.SuspiciousVariantCount.ToString(CultureInfo.InvariantCulture));
                csv.Append(',');
                csv.Append(Csv(item.TopSignal));
                csv.Append(',');
                csv.Append(item.TopSignalScore.ToString(CultureInfo.InvariantCulture));
                csv.Append(',');
                csv.Append(Csv(item.TopSignalDetail));
                csv.Append(',');
                csv.Append(item.HasBlocklistMatch ? "true" : "false");
                csv.Append(',');
                csv.AppendLine(Csv(item.BlocklistSource));
            }

            return csv.ToString();
        }

        private static HighRiskAlertReportItem BuildReportItem(DomainScan scan)
        {
            var suspiciousVariants = scan.Variants
                .Where(variant => variant.IsSuspicious)
                .ToList();

            var topVariant = suspiciousVariants
                .OrderByDescending(variant => variant.TopRiskSignalScore)
                .ThenBy(variant => variant.DiscoveredDomain, StringComparer.OrdinalIgnoreCase)
                .FirstOrDefault();

            var blocklistMatch = suspiciousVariants
                .FirstOrDefault(variant => variant.IsBlocklistMatch);

            return new HighRiskAlertReportItem
            {
                ScanId = scan.Id,
                ScanTimestampUtc = scan.TimeFinished ?? scan.CreatedAt,
                BaseDomain = scan.BaseDomain,
                SuspiciousVariantCount = suspiciousVariants.Count,
                TopSignal = topVariant?.TopRiskSignal,
                TopSignalScore = topVariant?.TopRiskSignalScore ?? 0,
                TopSignalDetail = topVariant?.TopRiskSignalDetail,
                HasBlocklistMatch = blocklistMatch is not null,
                BlocklistSource = blocklistMatch?.BlocklistSource
            };
        }

        private static string Csv(string? value)
        {
            value ??= string.Empty;

            if (!value.Contains(',') &&
                !value.Contains('"') &&
                !value.Contains('\r') &&
                !value.Contains('\n'))
            {
                return value;
            }

            return $"\"{value.Replace("\"", "\"\"")}\"";
        }
    }
}
