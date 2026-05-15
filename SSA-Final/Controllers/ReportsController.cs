// API controller exposing reporting queries over completed scan records.
// Surfaces time-windowed, risk-filtered results for analyst dashboards and integrations.

using Microsoft.AspNetCore.Mvc;
using SSA_Final.Interfaces;
using SSA_Final.Models;

namespace SSA_Final.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class ReportsController : ControllerBase
    {
        private readonly IScanStore _scanStore;
        private readonly ILogger<ReportsController> _logger;

        public ReportsController(IScanStore scanStore, ILogger<ReportsController> logger)
        {
            _scanStore = scanStore;
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
    }
}
