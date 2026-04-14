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
            ViewBag.Domain = domain;
            ViewBag.Scans = _domainScanRepository.GetAll();

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
                BaseDomain = normalizedDomain,
                ScanDate = DateTime.UtcNow,
                TimeFinished = DateTime.UtcNow,
                Status = analysisResult.IsSuspicious
                    ? DomainScanStatus.CompleteWithResults
                    : DomainScanStatus.Complete,
                Results = new List<DomainAnalysisResult> { analysisResult },
                RiskAnalyses = new List<DomainRiskAnalysis>
                {
                    new()
                    {
                        DomainName = analysisResult.DomainName,
                        IsSuspicious = analysisResult.IsSuspicious,
                        Reason = analysisResult.Reason,
                        Notes = analysisResult.Notes
                    }
                }
            };

            _domainScanRepository.Create(domainScan);

            _logger.LogInformation(
                "Scan {Id} complete for {Domain}: {Count} variant(s), {Malicious} suspicious.",
                scan.Id, baseDomain, analysisResults.Count, scan.MaliciousCount);

            return RedirectToAction("Details", "ScanResults", new { id = scan.Id });
        }
    }
}
