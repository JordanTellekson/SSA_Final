// MVC controller for authenticated scan result listings and details.
// Provides summary and per-scan drill-down views over persisted scan data.

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SSA_Final.Interfaces;
using SSA_Final.Models;
using SSA_Final.ViewModels;

namespace SSA_Final.Controllers
{
    [Authorize]
    public class ScanResultsController : Controller
    {
        private readonly ILogger<ScanResultsController> _logger;
        private readonly IScanStore _scanStore;

        public ScanResultsController(ILogger<ScanResultsController> logger, IScanStore scanStore)
        {
            _logger = logger;
            _scanStore = scanStore;
        }

        public async Task<IActionResult> Index([FromQuery] ScanQuery scanQuery)
        {
            _logger.LogInformation("Scan results page loaded at {Time}", DateTime.UtcNow);

            if (!string.IsNullOrWhiteSpace(scanQuery.Query))
            {
                scanQuery.Page = 1;
            }

            var result = await _scanStore.GetPagedAsync(scanQuery);
            var hasAnyScans = await _scanStore.GetAnyAsync();

            ViewData["Status"] = scanQuery.Status;
            ViewData["HasMalicious"] = scanQuery.HasMalicious;

            var vm = new PagedResultViewModel<DomainScan>
            {
                Result = result,
                Query = scanQuery.Query,
                ViewType = "table",
                HasAnyScans = hasAnyScans
            };

            if (Request.Headers["X-Requested-With"] == "XMLHttpRequest")
            {
                return PartialView("_ScanList", vm);
            }

            return View(vm);
        }

        public async Task<IActionResult> Details(Guid id)
        {
            var scan = _scanStore.GetById(id);
            if (scan is null)
            {
                _logger.LogWarning("Scan {Id} not found.", id);
                return NotFound();
            }

            foreach (var variant in scan.Variants)
            {
                variant.DiscoveredDomain ??= string.Empty;
                variant.Summary ??= string.Empty;
                variant.Indicators ??= new List<string>();
            }

            return View(scan);
        }

        /// <summary>
        /// Lightweight JSON endpoint polled by the Details page while a scan is in progress.
        /// Returns only the current status so the view can decide when to reload.
        /// </summary>
        [HttpGet]
        public IActionResult GetScanStatus(Guid id)
        {
            var scan = _scanStore.GetById(id);
            if (scan is null)
            {
                return NotFound();
            }

            return Json(new { status = scan.Status.ToString() });
        }
    }
}

