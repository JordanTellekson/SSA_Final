using Microsoft.AspNetCore.Authorization;
using SSA_Final.Models;
using SSA_Final.ViewModels;
using Microsoft.AspNetCore.Mvc;
using SSA_Final.Interfaces;

namespace SSA_Final.Controllers
{
    [Authorize]
    public class HistoryController : Controller
    {
        private readonly ILogger<HistoryController> _logger;
        private readonly IScanStore _scanStore;

        public HistoryController(ILogger<HistoryController> logger, IScanStore scanStore)
        {
            _logger = logger;
            _scanStore = scanStore;
        }

        public async Task<IActionResult> Index([FromQuery] ScanQuery scanQuery)
        {
            _logger.LogInformation("History page loaded at {Time}", DateTime.UtcNow);

            if (!string.IsNullOrWhiteSpace(scanQuery.Query))
            {
                scanQuery.Page = 1;
            }

            var result = await _scanStore.GetPagedAsync(scanQuery);

            ViewData["Status"] = scanQuery.Status;
            ViewData["HasMalicious"] = scanQuery.HasMalicious;
            
            var vm = new PagedResultViewModel<DomainScan>
            {
                Result = result,
                Query = scanQuery.Query,
                Mode = "history"
            };

            return View(vm);
        }
    }
}