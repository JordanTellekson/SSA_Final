using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SSA_Final.Interfaces;

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

        public async Task<IActionResult> Index()
        {
            var scans = _scanStore.GetAll();
            return View(scans);
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