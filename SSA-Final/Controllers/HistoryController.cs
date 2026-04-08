using Microsoft.AspNetCore.Mvc;
using SSA_Final.Models;

namespace SSA_Final.Controllers
{
    public class HistoryController : Controller
    {
        private readonly ILogger<HistoryController> _logger;

        public HistoryController(ILogger<HistoryController> logger)
        {
            _logger = logger;
        }

        public IActionResult Index()
        {
            List<DomainScan> scans = new();
            DomainScan scan = new()
            {
                Domain = "google.com",
                CreatedAt = DateTime.Now.AddDays(-1),
                TimeFinished = DateTime.Now,
                NumMaliciousDomains = 5,
                Status = DomainScanStatus.CompleteWithResults
            };
            scans.Add(scan);
            scan = new()
            {
                Domain = "mstc.edu",
                CreatedAt = DateTime.Now.AddDays(-2),
                TimeFinished = DateTime.Now.AddDays(-1),
                NumMaliciousDomains = 0,
                Status = DomainScanStatus.Complete
            };
            scans.Add(scan);
            scan = new()
            {
                Domain = "yetanotherdomain.com",
                CreatedAt = DateTime.Now.AddDays(-2),
                TimeFinished = DateTime.Now.AddDays(-1),
                NumMaliciousDomains = 0,
                Status = DomainScanStatus.Complete
            };
            scans.Add(scan);
            scan = new()
            {
                Domain = "example.com",
                CreatedAt = DateTime.Now.AddDays(-3),
                TimeFinished = DateTime.Now.AddDays(-2),
                NumMaliciousDomains = 0,
                Status = DomainScanStatus.InProgress
            };
            scans.Add(scan);
            _logger.LogInformation("History page loaded");

            return View(scans);
        }
    }
}