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
        private const int LegitimateDomainBatchSize = 10;

        private readonly ILogger<DashboardController> _logger;
        private readonly IScanStore _scanStore;
        private readonly ChannelWriter<Guid> _channelWriter;
        private readonly ILegitimateDomainBatchService _legitimateDomainBatchService;

        public DashboardController(
            ILogger<DashboardController> logger,
            IScanStore scanStore,
            ChannelWriter<Guid> channelWriter,
            ILegitimateDomainBatchService legitimateDomainBatchService)
        {
            _logger = logger;
            _scanStore = scanStore;
            _channelWriter = channelWriter;
            _legitimateDomainBatchService = legitimateDomainBatchService;
        }

        [HttpGet]
        public async Task<IActionResult> Index([FromQuery] int legitimateBatchStart = 0)
        {
            return View(await BuildDashboardViewModelAsync(legitimateBatchStart));
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
        public IActionResult QueueLegitimateDomainBatch(int startIndex = 0)
        {
            var activeBatchScans = GetActiveLegitimateBatchScanCount();
            if (activeBatchScans > 0)
            {
                TempData["ScanError"] =
                    $"{activeBatchScans} legitimate domain batch scan(s) are still pending or running. Wait for them to finish before moving on.";

                return RedirectToAction(nameof(Index), new { legitimateBatchStart = startIndex });
            }

            var batch = _legitimateDomainBatchService.GetBatch(startIndex, LegitimateDomainBatchSize);
            if (!batch.HasDomains)
            {
                TempData["ScanError"] = batch.TotalCount == 0
                    ? "No legitimate domains were found to test."
                    : "All legitimate domains have been queued for this pass.";

                return RedirectToAction(nameof(Index), new { legitimateBatchStart = batch.StartIndex });
            }

            var queued = 0;
            foreach (var domain in batch.Domains)
            {
                var scan = new DomainScan
                {
                    BaseDomain = domain,
                    CreatedAt = DateTime.UtcNow,
                    Status = DomainScanStatus.Pending,
                    ScanTrigger = ScanTrigger.LegitimateBatch,
                    NumMaliciousDomains = 0
                };

                _scanStore.Add(scan);
                if (_channelWriter.TryWrite(scan.Id))
                {
                    queued++;
                }
                else
                {
                    _logger.LogWarning(
                        "Legitimate domain batch scan {DomainScanId} for '{Domain}' could not be queued.",
                        scan.Id,
                        domain);
                }
            }

            var rangeStart = batch.StartIndex + 1;
            var rangeEnd = batch.StartIndex + queued;
            TempData["ScanSuccess"] =
                $"Queued {queued} legitimate domain baseline scan(s), {rangeStart}-{rangeEnd} of {batch.TotalCount}.";

            _logger.LogInformation(
                "Queued {Count} legitimate domain baseline scan(s), {Start}-{End} of {Total}.",
                queued,
                rangeStart,
                rangeEnd,
                batch.TotalCount);

            return RedirectToAction(nameof(Index), new { legitimateBatchStart = batch.NextStartIndex });
        }

        private async Task<DomainScanViewModel> BuildDashboardViewModelAsync(int legitimateBatchStart = 0)
        {
            return new DomainScanViewModel
            {
                Stats = await _scanStore.GetScanStatsAsync(),
                LegitimateBatch = _legitimateDomainBatchService.GetBatch(
                    legitimateBatchStart,
                    LegitimateDomainBatchSize),
                ActiveLegitimateBatchScans = GetActiveLegitimateBatchScanCount()
            };
        }

        private int GetActiveLegitimateBatchScanCount()
        {
            return _scanStore.GetPendingScans()
                .Concat(_scanStore.GetInProgressScans())
                .Count(scan => scan.ScanTrigger == ScanTrigger.LegitimateBatch);
        }
    }
}
