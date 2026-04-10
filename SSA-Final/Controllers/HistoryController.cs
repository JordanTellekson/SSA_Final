using Microsoft.AspNetCore.Authorization;
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

        public IActionResult Index()
        {
            _logger.LogInformation("History page loaded at {Time}", DateTime.UtcNow);
            var scans = _scanStore.GetAll();
            return View(scans);
        }
    }
}