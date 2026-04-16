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
        private readonly IDomainScanRepository _domainScanRepository;

        public DashboardController(
            ILogger<DashboardController> logger,
            IDomainGenerator domainGenerator,
            IDomainAnalyzer domainAnalyzer,
            IDomainScanRepository domainScanRepository)
        {
            _logger = logger;
            _domainGenerator = domainGenerator;
            _domainAnalyzer = domainAnalyzer;
            _domainScanRepository = domainScanRepository;
        }

        [HttpGet]
        public IActionResult Index()
        {
            _logger.LogInformation("Dashboard Index accessed at {Time}", DateTime.UtcNow);

            var model = new DomainScanViewModel();
            ViewBag.Scans = _domainScanRepository.GetAll();

            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Index(DomainScanViewModel model)
        {
            if (!ModelState.IsValid)
            {
                ViewBag.Scans = _domainScanRepository.GetAll();
                return View(model);
            }

            var baseDomain = model.Domain.Trim().ToLowerInvariant();
            ViewBag.Domain = baseDomain;
            ViewBag.Scans = _domainScanRepository.GetAll();
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
                ScanDate = DateTime.UtcNow,
                TimeFinished = DateTime.UtcNow,
                Status = analysisResults.Any(r => r.IsSuspicious)
                    ? DomainScanStatus.CompleteWithResults
                    : DomainScanStatus.Complete,
                Results = analysisResults,
                RiskAnalyses = analysisResults
                    .Select(result => new DomainRiskAnalysis
                    {
                        DomainName = result.DomainName,
                        IsSuspicious = result.IsSuspicious,
                        Reason = result.Reason,
                        Notes = result.Notes
                    })
                    .ToList()
            };

            _domainScanRepository.Create(scan);

            _logger.LogInformation(
                "Scan {Id} complete for {Domain}: {Count} variant(s), {Malicious} suspicious.",
                scan.Id, baseDomain, analysisResults.Count, scan.NumMaliciousDomains);

            return RedirectToAction("Details", "ScanResults", new { id = scan.Id });
        }
    }
}
