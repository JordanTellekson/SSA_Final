// MVC controller for launching new domain scans from the dashboard UI.
// Coordinates variant generation, analysis execution, lifecycle updates, and navigation.

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
            var model = new DomainScanViewModel
            {
                ScanHistory = _scanStore.GetAll()
            };

            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Index(DomainScanViewModel model)
        {
            if (!ModelState.IsValid)
            {
                model.ScanHistory = _scanStore.GetAll();
                return View(model);
            }

            var baseDomain = model.Domain.Trim().ToLower();
            _logger.LogInformation("Initiating scan for domain: {Domain}", baseDomain);

            var scan = new DomainScan
            {
                BaseDomain = baseDomain,
                CreatedAt = DateTime.UtcNow,
                Status = DomainScanStatus.InProgress,
                NumMaliciousDomains = 0
            };

            _scanStore.Add(scan);

            try
            {
                var variants = _domainGenerator.GenerateVariations(baseDomain).ToList();

                var analysisResults = new List<DomainAnalysisResult>();
                foreach (var variant in variants)
                {
                    var result = await _domainAnalyzer.Analyze(variant);
                    result.DomainScanId = scan.Id;
                    analysisResults.Add(result);
                }

                scan.Variants = analysisResults;
                scan.NumMaliciousDomains = analysisResults.Count(r => r.IsSuspicious);
                scan.TimeFinished = DateTime.UtcNow;
                scan.Status = DomainScanStatus.Completed;

                _scanStore.Update(scan);

                _logger.LogInformation(
                    "Scan {Id} complete for {Domain}: {Count} variant(s), {Malicious} suspicious.",
                    scan.Id, baseDomain, analysisResults.Count, scan.NumMaliciousDomains);

                return RedirectToAction("Details", "ScanResults", new { id = scan.Id });
            }
            catch (Exception ex)
            {
                scan.TimeFinished = DateTime.UtcNow;
                scan.Status = DomainScanStatus.Failed;
                _scanStore.Update(scan);

                _logger.LogError(ex, "Scan {Id} failed for {Domain}", scan.Id, baseDomain);
                TempData["ScanError"] = "Scan failed. Please try again.";

                return RedirectToAction("Details", "ScanResults", new { id = scan.Id });
            }
        }
    }
}

