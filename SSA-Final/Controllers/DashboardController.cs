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
        private readonly ILogger<DashboardController> _logger;
        private readonly IDomainGenerator _domainGenerator;
        private readonly IDomainAnalyzer _domainAnalyzer;
        private readonly IScanStore _scanStore;

        public DashboardController(
            ILogger<DashboardController> logger,
            IDomainGenerator domainGenerator,
            IDomainAnalyzer domainAnalyzer,
            IScanStore scanStore)
        {
            _logger = logger;
            _domainGenerator = domainGenerator;
            _domainAnalyzer = domainAnalyzer;
            _scanStore = scanStore;
        }

        [HttpGet]
        public IActionResult Index()
        {
            return View(new DomainScanViewModel());
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Index(DomainScanViewModel model)
        {
            if (!ModelState.IsValid)
                return View(model);

            var baseDomain = model.Domain.Trim().ToLower();
            _logger.LogInformation("Initiating scan for domain: {Domain}", baseDomain);

            var variants = _domainGenerator.GenerateVariations(baseDomain).ToList();

            var analysisResults = new List<DomainAnalysisResult>();
            foreach (var variant in variants)
            {
                var result = await _domainAnalyzer.Analyze(variant);
                analysisResults.Add(result);
            }

            var scan = new DomainScan
            {
                BaseDomain = baseDomain,
                ScannedAt = DateTime.UtcNow,
                Variants = analysisResults,
                Status = analysisResults.Any(r => r.IsSuspicious)
                    ? DomainScanStatus.CompleteWithResults
                    : DomainScanStatus.Complete
            };

            _scanStore.Add(scan);

            _logger.LogInformation(
                "Scan {Id} complete for {Domain}: {Count} variant(s), {Malicious} suspicious.",
                scan.Id, baseDomain, analysisResults.Count, scan.MaliciousCount);

            return RedirectToAction("Details", "ScanResults", new { id = scan.Id });
        }
    }
}