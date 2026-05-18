// MVC controller for launching new domain scans from the dashboard UI.
// Coordinates variant generation, analysis execution, lifecycle updates, and navigation.

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SSA_Final.Interfaces;
using SSA_Final.Models;
using SSA_Final.Services;
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
        private readonly LegitimateDomainBatchQueueService _legitimateDomainBatchQueueService;

        public DashboardController(
            ILogger<DashboardController> logger,
            IScanStore scanStore,
            ChannelWriter<Guid> channelWriter,
            LegitimateDomainBatchQueueService legitimateDomainBatchQueueService)
        {
            _logger = logger;
            _scanStore = scanStore;
            _channelWriter = channelWriter;
            _legitimateDomainBatchQueueService = legitimateDomainBatchQueueService;
        }

        [HttpGet]
        public async Task<IActionResult> Index()
        {
            return View(await BuildDashboardViewModelAsync());
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Index(DomainScanViewModel model)
        {
            if (!ModelState.IsValid)
            {
                var invalidModel = await BuildDashboardViewModelAsync();
                invalidModel.Domain = model.Domain;
                return View(invalidModel);
            }

            var baseDomain = model.Domain.Trim().ToLower();

            var scan = new DomainScan
            {
                BaseDomain = baseDomain,
                CreatedAt = DateTime.UtcNow,
                Status = DomainScanStatus.Pending,
                ScanTrigger = ScanTrigger.Manual,
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

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult QueueLegitimateDomainBatch()
        {
            var result = _legitimateDomainBatchQueueService.StartNextRun();
            switch (result.Status)
            {
                case LegitimateDomainBatchQueueStatus.Queued:
                    TempData["ScanSuccess"] =
                        $"Started the next 50-domain baseline run and queued {result.CreatedScans} scan(s), {result.RangeStart}-{result.RangeEnd} of {result.TotalCount}.";
                    break;
                case LegitimateDomainBatchQueueStatus.ActiveScansInProgress:
                    TempData["ScanError"] =
                        $"{result.ActiveScanCount} legitimate domain batch scan(s) are still pending or running. The next set of 10 will queue automatically when they finish.";
                    break;
                case LegitimateDomainBatchQueueStatus.NoDomains:
                    TempData["ScanError"] = result.TotalCount == 0
                        ? "No legitimate domains were found to test."
                        : "All legitimate domains have been queued for this pass.";
                    break;
                case LegitimateDomainBatchQueueStatus.RunComplete:
                    TempData["ScanSuccess"] =
                        "The current legitimate domain baseline run is complete. You can start the next 50-domain batch.";
                    break;
                default:
                    TempData["ScanError"] = "The legitimate domain baseline run could not be started.";
                    break;
            }

            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult ResetLegitimateDomainBatchProgress()
        {
            var progress = _legitimateDomainBatchQueueService.GetProgress();
            if (progress.IsRunActive || _legitimateDomainBatchQueueService.GetActiveLegitimateBatchScanCount() > 0)
            {
                TempData["ScanError"] =
                    "Legitimate domain batch scans are still pending or running. Wait for them to finish before resetting progress.";

                return RedirectToAction(nameof(Index));
            }

            _legitimateDomainBatchQueueService.ResetProgress();
            TempData["ScanSuccess"] = "Legitimate domain baseline progress was reset to the first domain.";
            return RedirectToAction(nameof(Index));
        }

        private async Task<DomainScanViewModel> BuildDashboardViewModelAsync()
        {
            return new DomainScanViewModel
            {
                Stats = await _scanStore.GetScanStatsAsync(),
                LegitimateBatchProgress = _legitimateDomainBatchQueueService.GetProgress(),
                ActiveLegitimateBatchScans = _legitimateDomainBatchQueueService.GetActiveLegitimateBatchScanCount()
            };
        }
    }
}
