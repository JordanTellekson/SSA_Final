using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace SSA_Final.Controllers
{
    public class DashboardController : Controller
    {
        private readonly ILogger<DashboardController> _logger;

        public DashboardController(ILogger<DashboardController> logger)
        {
            _logger = logger;
        }

        [HttpGet]
        public ActionResult Index()
        {
            _logger.LogInformation("Dashboard Index accessed at {Time}", DateTime.UtcNow);

            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Index(string domain)
        {
            // Preserve input
            ViewBag.Domain = domain;

            if (string.IsNullOrWhiteSpace(domain))
            {
                ModelState.AddModelError("domain", "Domain is required.");
                return View();
            }

            // Basic domain validation
            var isValidDomain = System.Text.RegularExpressions.Regex.IsMatch(
                domain,
                @"^(?!:\/\/)([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"
            );

            if (!isValidDomain)
            {
                ModelState.AddModelError("domain", "Enter a valid domain (e.g. example.com)");
                return View();
            }

            // Create in-memory DomainScan object
            //var domainScan = new DomainScan
            //{
            //    Domain = domain,
            //    CreatedAt = DateTime.UtcNow
            //};

            ViewBag.Success = $"Scan created for {domain}";
            ViewBag.Domain = ""; // clear input after success

            return View();
        }
    }
}