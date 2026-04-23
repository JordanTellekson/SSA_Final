using Microsoft.AspNetCore.Authorization;
using SSA_Final.Models;
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

        public async Task<IActionResult> Index([FromQuery] ScanQuery query)
        {
            _logger.LogInformation("History page loaded at {Time}", DateTime.UtcNow);
            var scans = await _scanStore.GetAsync(query);
            return View(scans);
        }
    }
}