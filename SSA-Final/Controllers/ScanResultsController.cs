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

            var vm = new PagedResultViewModel<DomainScan>
            {
                Result = result,
                Query = scanQuery.Query,
                Mode = "table"
            };

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

            return View(scan);
        }
    }
}