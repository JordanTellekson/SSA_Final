using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SSA_Final.Interfaces;
using SSA_Final.Models;

namespace SSA_Final.Controllers
{
    [Authorize]
    public class ScanResultsController : Controller
    {
        private readonly ILogger<ScanResultsController> _logger;
        private readonly IDomainAnalyzer _domainAnalyzer;

        public ScanResultsController(
            ILogger<ScanResultsController> logger,
            IDomainAnalyzer domainAnalyzer)
        {
            _logger = logger;
            _domainAnalyzer = domainAnalyzer;
        }

        public async Task<IActionResult> Index(string? domain = null)
        {
            _logger.LogInformation("ScanResults.Index accessed at {Time}", DateTime.UtcNow);

            DomainAnalysisResult? result = null;

            if (!string.IsNullOrWhiteSpace(domain))
            {
                _logger.LogInformation(
                    "Calling IDomainAnalyzer.Analyze from ScanResultsController for {Domain}", domain);

                result = await _domainAnalyzer.Analyze(domain);

                _logger.LogInformation(
                    "IDomainAnalyzer returned Suspicious={IsSuspicious} for {Domain}",
                    result.IsSuspicious, domain);
            }

            ViewBag.AnalysisResult = result;

            return View();
        }
    }
}