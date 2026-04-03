using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SSA_Final.Interfaces;
using SSA_Final.Models;
using SSA_Final.ViewModels;

namespace SSA_Final.Controllers
{
    [Authorize]
    public class DashboardController : Controller
    {
        // In-memory storage (for now)
        private static readonly List<DomainScan> _scans = new();

        private readonly ILogger<DashboardController> _logger;
        private readonly IDomainGenerator _domainGenerator;
        private readonly IDomainAnalyzer _domainAnalyzer;

        public DashboardController(
            ILogger<DashboardController> logger,
            IDomainGenerator domainGenerator,
            IDomainAnalyzer domainAnalyzer)
        {
            _logger = logger;
            _domainGenerator = domainGenerator;
            _domainAnalyzer = domainAnalyzer;
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
        public async Task<ActionResult> Index(string domain)
        {
            ViewBag.Domain = domain;
            ViewBag.Scans = _scans;

            if (string.IsNullOrWhiteSpace(domain))
            {
                ModelState.AddModelError("domain", "Domain is required.");
                return View();
            }

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
            _logger.LogInformation(
                "Initiating scan for domain: {Domain}", normalizedDomain);

            // Generate variations
            _logger.LogInformation(
                "Calling IDomainGenerator.GenerateVariations for {Domain}", normalizedDomain);

            var variations = _domainGenerator.GenerateVariations(normalizedDomain).ToList();

            _logger.LogInformation(
                "IDomainGenerator produced {Count} variation(s) for {Domain}",
                variations.Count, normalizedDomain);

            // Analyze domain
            _logger.LogInformation(
                "Calling IDomainAnalyzer.Analyze for {Domain}", normalizedDomain);

            var analysisResult = await _domainAnalyzer.Analyze(normalizedDomain);

            _logger.LogInformation(
                "IDomainAnalyzer returned Suspicious={IsSuspicious} for {Domain}",
                analysisResult.IsSuspicious, normalizedDomain);

            // Persist scan record
            var domainScan = new DomainScan
            {
                Domain = normalizedDomain,
                CreatedAt = DateTime.UtcNow
            };

            _scans.Add(domainScan);

            ViewBag.Variations = variations;
            ViewBag.AnalysisResult = analysisResult;
            ViewBag.Success = $"Scan created for {normalizedDomain}";
            ViewBag.Domain = string.Empty;

            return View();
        }
    }
}