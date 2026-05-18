// API controller exposing reporting queries and CSV export over completed scan records.
// Surfaces time-windowed, risk-filtered results for analyst dashboards and integrations.

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SSA_Final.Interfaces;
using SSA_Final.Models;
using System.Text;

namespace SSA_Final.Controllers
{
    [Authorize]
    [ApiController]
    [Route("api/[controller]")]
    public class ReportsController : ControllerBase
    {
        private readonly IScanStore _scanStore;
        private readonly IReportService _reportService;
        private readonly ILogger<ReportsController> _logger;

        public ReportsController(
            IScanStore scanStore,
            IReportService reportService,
            ILogger<ReportsController> logger)
        {
            _scanStore = scanStore;
            _reportService = reportService;
            _logger = logger;
        }

        /// <summary>
        /// Returns completed scans within the given time window that have at least
        /// <paramref name="minRisk"/> malicious variants, ordered by threat severity descending.
        /// </summary>
        /// <param name="since">Start of the time window (UTC). Defaults to 7 days ago.</param>
        /// <param name="minRisk">Minimum number of malicious domains required. Defaults to 1.</param>
        [HttpGet("recent-highrisk")]
        public async Task<ActionResult<IReadOnlyList<DomainScan>>> GetRecentHighRisk(
            [FromQuery] DateTime? since,
            [FromQuery] int minRisk = 1)
        {
            var effectiveSince = since ?? DateTime.UtcNow.AddDays(-7);

            _logger.LogInformation(
                "Fetching high-risk scans since {Since} with minRisk={MinRisk}.",
                effectiveSince,
                minRisk);

            var results = await _scanStore.GetRecentHighRiskAsync(effectiveSince, minRisk);
            return Ok(results);
        }

        /// <summary>
        /// Generates and streams a CSV export of all completed scans within the lookback window.
        /// The file is named with the current UTC timestamp for traceability.
        /// </summary>
        /// <param name="lookbackHours">
        /// How far back to look for scans, in hours.
        /// Defaults to the value configured in <c>Reports:HighRiskLookbackHours</c> (30 days).
        /// </param>
        [HttpGet("download-csv")]
        public async Task<IActionResult> DownloadCsv([FromQuery] double? lookbackHours)
        {
            var window = lookbackHours.HasValue
                ? TimeSpan.FromHours(lookbackHours.Value)
                : (TimeSpan?)null;

            _logger.LogInformation(
                "Generating scan CSV report. LookbackHours={Hours}",
                lookbackHours?.ToString() ?? "default");

            var report = await _reportService.GenerateHighRiskAlertReportAsync(window);
            var csv = _reportService.ToCsv(report);
            var bytes = Encoding.UTF8.GetBytes(csv);
            var filename = $"scan-report-{DateTime.UtcNow:yyyyMMdd-HHmm}.csv";

            _logger.LogInformation(
                "CSV report generated. Rows={Rows}, Filename={Filename}",
                report.Items.Count, filename);

            return File(bytes, "text/csv", filename);
        }

        /// <summary>
        /// Streams a CSV export with one row per analyzed domain in the selected time window.
        /// Use suspiciousOnly=true to include only domains flagged as suspicious.
        /// </summary>
        [HttpGet("domains-csv")]
        public async Task<IActionResult> DownloadDomainsCsv(
            [FromQuery] double? lookbackHours,
            [FromQuery] DateTime? startUtc,
            [FromQuery] DateTime? endUtc,
            [FromQuery] bool suspiciousOnly = false)
        {
            if (lookbackHours.HasValue && lookbackHours.Value <= 0)
            {
                return BadRequest("lookbackHours must be greater than zero.");
            }

            var normalizedStart = NormalizeUtc(startUtc);
            var normalizedEnd = NormalizeUtc(endUtc);
            if (normalizedStart.HasValue &&
                normalizedEnd.HasValue &&
                normalizedStart.Value > normalizedEnd.Value)
            {
                return BadRequest("startUtc must be on or before endUtc.");
            }

            var window = lookbackHours.HasValue
                ? TimeSpan.FromHours(lookbackHours.Value)
                : (TimeSpan?)null;

            _logger.LogInformation(
                "Generating domain CSV report. LookbackHours={Hours}, StartUtc={StartUtc}, EndUtc={EndUtc}, SuspiciousOnly={SuspiciousOnly}",
                lookbackHours?.ToString() ?? "default",
                normalizedStart?.ToString("O") ?? "default",
                normalizedEnd?.ToString("O") ?? "default",
                suspiciousOnly);

            var report = await _reportService.GenerateDomainAnalysisReportAsync(
                window,
                suspiciousOnly,
                normalizedStart,
                normalizedEnd);
            var csv = _reportService.ToCsv(report);
            var bytes = Encoding.UTF8.GetBytes(csv);
            var scope = suspiciousOnly ? "suspicious-domains" : "domains";
            var filename = $"{scope}-report-{DateTime.UtcNow:yyyyMMdd-HHmm}.csv";

            _logger.LogInformation(
                "Domain CSV report generated. Rows={Rows}, Filename={Filename}",
                report.Items.Count,
                filename);

            return File(bytes, "text/csv", filename);
        }

        /// <summary>
        /// Streams a CSV export of all variant analysis results for a single scan.
        /// </summary>
        /// <param name="id">The scan ID to export.</param>
        [HttpGet("scan/{id:guid}/csv")]
        public async Task<IActionResult> DownloadScanCsv(Guid id)
        {
            var scan = _scanStore.GetById(id);
            if (scan is null)
            {
                _logger.LogWarning("CSV export requested for unknown scan {ScanId}.", id);
                return NotFound();
            }

            var variants = await _scanStore.GetVariantsAsync(id, new SSA_Final.Models.VariantQuery());

            _logger.LogInformation(
                "Generating per-scan CSV. ScanId={ScanId}, VariantCount={Count}",
                id, variants.Count);

            var csv = BuildVariantCsv(scan.BaseDomain, variants);
            var bytes = Encoding.UTF8.GetBytes(csv);
            var safeDomain = scan.BaseDomain.Replace('.', '-');
            var filename = $"scan-{safeDomain}-{DateTime.UtcNow:yyyyMMdd-HHmm}.csv";

            return File(bytes, "text/csv", filename);
        }

        private static string BuildVariantCsv(
            string baseDomain,
            IReadOnlyList<SSA_Final.Models.DomainAnalysisResult> variants)
        {
            var csv = new System.Text.StringBuilder();
            csv.AppendLine("BaseDomain,DiscoveredDomain,IsSuspicious,RiskClassification,OverallRiskScore,TopRiskSignal,TopRiskSignalScore,IsBlocklistMatch,BlocklistSource,AnalysedAtUtc");

            foreach (var v in variants)
            {
                csv.Append(CsvEscape(baseDomain)); csv.Append(',');
                csv.Append(CsvEscape(v.DiscoveredDomain)); csv.Append(',');
                csv.Append(v.IsSuspicious ? "true" : "false"); csv.Append(',');
                csv.Append(CsvEscape(v.RiskClassification)); csv.Append(',');
                csv.Append(v.OverallRiskScore.ToString(System.Globalization.CultureInfo.InvariantCulture)); csv.Append(',');
                csv.Append(CsvEscape(v.TopRiskSignal)); csv.Append(',');
                csv.Append(v.TopRiskSignalScore.ToString(System.Globalization.CultureInfo.InvariantCulture)); csv.Append(',');
                csv.Append(v.IsBlocklistMatch ? "true" : "false"); csv.Append(',');
                csv.Append(CsvEscape(v.BlocklistSource)); csv.Append(',');
                csv.AppendLine(CsvEscape(v.AnalysedAt.ToString("O", System.Globalization.CultureInfo.InvariantCulture)));
            }

            return csv.ToString();
        }

        private static string CsvEscape(string? value)
        {
            value ??= string.Empty;
            if (!value.Contains(',') && !value.Contains('"') &&
                !value.Contains('\r') && !value.Contains('\n'))
                return value;
            return $"\"{value.Replace("\"", "\"\"")}\"";
        }

        private static DateTime? NormalizeUtc(DateTime? value)
        {
            if (!value.HasValue)
            {
                return null;
            }

            return value.Value.Kind switch
            {
                DateTimeKind.Utc => value.Value,
                DateTimeKind.Local => value.Value.ToUniversalTime(),
                _ => DateTime.SpecifyKind(value.Value, DateTimeKind.Utc)
            };
        }
    }
}
