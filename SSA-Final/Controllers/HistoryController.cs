using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SSA_Final.Interfaces;
using SSA_Final.Models;

namespace SSA_Final.Controllers
{
    [Authorize]
    /// <summary>
    /// Displays historical scans and seeds demo history when no data exists.
    /// </summary>
    public class HistoryController : Controller
    {
        private readonly ILogger<HistoryController> _logger;
        private readonly IDomainScanRepository _domainScanRepository;

        /// <summary>
        /// Creates the history controller.
        /// </summary>
        public HistoryController(
            ILogger<HistoryController> logger,
            IDomainScanRepository domainScanRepository)
        {
            _logger = logger;
            _domainScanRepository = domainScanRepository;
        }

        /// <summary>
        /// Renders the scan-history page.
        /// </summary>
        /// <returns>History view with all scans from the repository.</returns>
        public IActionResult Index()
        {
            if (_domainScanRepository.GetAll().Count == 0)
            {
                SeedHistory();
            }

            _logger.LogInformation("History page loaded");

            return View(_domainScanRepository.GetAll());
        }

        /// <summary>
        /// Seeds a few sample records so first-run environments have data to display.
        /// </summary>
        private void SeedHistory()
        {
            _domainScanRepository.Create(new DomainScan
            {
                BaseDomain = "google.com",
                ScanDate = DateTime.UtcNow.AddDays(-1),
                TimeFinished = DateTime.UtcNow,
                Status = DomainScanStatus.CompleteWithResults,
                Results = new List<DomainAnalysisResult>
                {
                    new()
                    {
                        DomainName = "goog1e.com",
                        IsSuspicious = true,
                        Reason = "Typosquatting pattern detected",
                        Notes = "Looks visually similar to google.com"
                    }
                },
                RiskAnalyses = new List<DomainRiskAnalysis>
                {
                    new()
                    {
                        DomainName = "goog1e.com",
                        IsSuspicious = true,
                        Reason = "Typosquatting pattern detected",
                        Notes = "Looks visually similar to google.com"
                    }
                }
            });

            _domainScanRepository.Create(new DomainScan
            {
                BaseDomain = "mstc.edu",
                ScanDate = DateTime.UtcNow.AddDays(-2),
                TimeFinished = DateTime.UtcNow.AddDays(-1),
                Status = DomainScanStatus.Complete
            });

            _domainScanRepository.Create(new DomainScan
            {
                BaseDomain = "yetanotherdomain.com",
                ScanDate = DateTime.UtcNow.AddDays(-2),
                TimeFinished = DateTime.UtcNow.AddDays(-1),
                Status = DomainScanStatus.Complete
            });

            _domainScanRepository.Create(new DomainScan
            {
                BaseDomain = "example.com",
                ScanDate = DateTime.UtcNow.AddDays(-3),
                TimeFinished = DateTime.UtcNow.AddDays(-2),
                Status = DomainScanStatus.InProgress
            });
        }
    }
}
