using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SSA_Final.Interfaces;

namespace SSA_Final.Controllers
{
    [Authorize]
    public class ReportsController : Controller
    {
        private readonly IReportService _reportService;

        public ReportsController(IReportService reportService)
        {
            _reportService = reportService;
        }

        [HttpGet]
        public async Task<IActionResult> Generate(
            [FromQuery] double? lookbackHours,
            [FromQuery] string? format,
            CancellationToken cancellationToken)
        {
            var lookbackWindow = lookbackHours is > 0
                ? TimeSpan.FromHours(lookbackHours.Value)
                : (TimeSpan?)null;

            var report = await _reportService.GenerateHighRiskAlertReportAsync(
                lookbackWindow,
                cancellationToken);

            if (string.Equals(format, "csv", StringComparison.OrdinalIgnoreCase))
            {
                var csv = _reportService.ToCsv(report);
                var fileName = $"high-risk-alert-report-{report.LookbackEndUtc:yyyyMMddHHmmss}.csv";
                return File(Encoding.UTF8.GetBytes(csv), "text/csv", fileName);
            }

            return Json(report);
        }
    }
}
