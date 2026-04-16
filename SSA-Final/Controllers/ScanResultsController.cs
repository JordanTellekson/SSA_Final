using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SSA_Final.Interfaces;

namespace SSA_Final.Controllers
{
    [Authorize]
    public class ScanResultsController : Controller
    {
        private readonly ILogger<ScanResultsController> _logger;
        private readonly IDomainScanRepository _domainScanRepository;

        public ScanResultsController(
            ILogger<ScanResultsController> logger,
            IDomainScanRepository domainScanRepository)
        {
            _logger = logger;
            _domainScanRepository = domainScanRepository;
        }

        public IActionResult Index()
        {
            var scans = _domainScanRepository.GetAll().ToList();
            return View(scans);
        }

        public IActionResult Details(Guid id)
        {
            var scan = _domainScanRepository.GetById(id);
            if (scan is null)
            {
                _logger.LogWarning("Scan {Id} not found.", id);
                return NotFound();
            }

            return View(scan);
        }
    }
}
