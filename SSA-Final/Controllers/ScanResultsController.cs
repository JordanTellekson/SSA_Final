using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SSA_Final.Interfaces;

namespace SSA_Final.Controllers
{
    [Authorize]
    /// <summary>
    /// Displays scan list and scan detail pages.
    /// </summary>
    public class ScanResultsController : Controller
    {
        private readonly ILogger<ScanResultsController> _logger;
        private readonly IDomainScanRepository _domainScanRepository;

        /// <summary>
        /// Creates the scan-results controller.
        /// </summary>
        public ScanResultsController(
            ILogger<ScanResultsController> logger,
            IDomainScanRepository domainScanRepository)
        {
            _logger = logger;
            _domainScanRepository = domainScanRepository;
        }

        /// <summary>
        /// Shows all scans currently stored in the repository.
        /// </summary>
        /// <returns>Scan-results list view.</returns>
        public IActionResult Index()
        {
            var scans = _domainScanRepository.GetAll().ToList();
            return View(scans);
        }

        /// <summary>
        /// Shows one scan by identifier.
        /// </summary>
        /// <param name="id">Scan identifier.</param>
        /// <returns>Detail view when found; HTTP 404 otherwise.</returns>
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
