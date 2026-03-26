using Microsoft.AspNetCore.Mvc;

namespace SSA_Final.Controllers
{
    public class HistoryController : Controller
    {
        private readonly ILogger<HistoryController> _logger;

        public HistoryController(ILogger<HistoryController> logger)
        {
            _logger = logger;
        }

        public IActionResult Index()
        {
            _logger.LogInformation("History page loaded");

            return View();
        }
    }
}