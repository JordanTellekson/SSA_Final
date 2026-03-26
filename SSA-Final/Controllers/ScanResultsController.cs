using Microsoft.AspNetCore.Mvc;

namespace SSA_Final.Controllers
{
    public class ScanResultsController : Controller
    {
        private readonly ILogger<ScanResultsController> _logger;

        public ScanResultsController(ILogger<ScanResultsController> logger)
        {
            _logger = logger;
        }

        public IActionResult Index()
        {
            _logger.LogInformation("Scan results viewed");

            return View();
        }
    }
}