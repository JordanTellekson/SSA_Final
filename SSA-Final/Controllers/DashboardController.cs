using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SSA_Final.Models;
using SSA_Final.ViewModels;

namespace SSA_Final.Controllers
{
    [Authorize]
    public class DashboardController : Controller
    {
        // In-memory storage (fow now)
        private static List<DomainScan> _scans = new List<DomainScan>();

        private readonly ILogger<DashboardController> _logger;

        public DashboardController(ILogger<DashboardController> logger)
        {
            _logger = logger;
        }

        [HttpGet]
        public ActionResult Index()
        {
            _logger.LogInformation("Dashboard Index accessed at {Time}", DateTime.UtcNow);
            var model = new DomainScanViewModel();
            ViewBag.Scans = _scans;

            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Index(string domain)
        {
            // Preserve input
            ViewBag.Domain = domain;
            ViewBag.Scans = _scans;

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

            var normalizedDomain = domain.Trim().ToLower();

            var domainScan = new DomainScan
            {
                Domain = normalizedDomain,
                CreatedAt = DateTime.UtcNow
            };

            _scans.Add(domainScan);

            ViewBag.Success = $"Scan created for {normalizedDomain}";
            ViewBag.Domain = "";

            return View();
        }
    }
}