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

        public IActionResult Index()
        {
            var scans = _scanStore.GetAll();
            return View(scans);
        }

        public IActionResult Details(Guid id)
        {
            var scan = _scanStore.GetById(id);
            if (scan is null)
            {
                _logger.LogWarning("Scan {Id} not found.", id);
                return NotFound();
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