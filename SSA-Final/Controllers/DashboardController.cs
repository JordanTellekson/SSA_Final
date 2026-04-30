// MVC controller for launching new domain scans from the dashboard UI.
// Coordinates variant generation, analysis execution, lifecycle updates, and navigation.

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SSA_Final.Interfaces;
using SSA_Final.Models;
using SSA_Final.ViewModels;
using System.Threading.Channels;

namespace SSA_Final.Controllers
{
    [Authorize]
    public class DashboardController : Controller
    {
        private readonly ILogger<DashboardController> _logger;
        private readonly IScanStore _scanStore;
        private readonly ChannelWriter<Guid> _channelWriter;

        public DashboardController(
            ILogger<DashboardController> logger,
            IScanStore scanStore,
            ChannelWriter<Guid> channelWriter)
        {
            _logger = logger;
            _scanStore = scanStore;
            _channelWriter = channelWriter;
        }

        [HttpGet]
        public IActionResult Index()
        {
            return View(new DomainScanViewModel());
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Index(DomainScanViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var baseDomain = model.Domain.Trim().ToLower();

            var scan = new DomainScan
            {
                BaseDomain = baseDomain,
                CreatedAt = DateTime.UtcNow,
                Status = DomainScanStatus.Pending,
                NumMaliciousDomains = 0
            };

            _scanStore.Add(scan);

            // Hand off to the background worker — do not block the HTTP thread.
            _channelWriter.TryWrite(scan.Id);

            _logger.LogInformation(
                "Scan {DomainScanId}: queued for background processing (domain: '{Domain}').",
                scan.Id, baseDomain);

            return RedirectToAction("Details", "ScanResults", new { id = scan.Id });
        }
    }
}
