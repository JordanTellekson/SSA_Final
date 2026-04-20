using Microsoft.AspNetCore.Mvc;
using SSA_Final.Interfaces;
using SSA_Final.Models;

namespace SSA_Final.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    /// <summary>
    /// API endpoints for domain risk scoring and allow-list matching.
    /// </summary>
    public class DomainRiskController : ControllerBase
    {
        private readonly IDomainRiskAnalyzer _domainRiskAnalyzer;
        private readonly ILogger<DomainRiskController> _logger;

        /// <summary>
        /// Creates the risk API controller.
        /// </summary>
        public DomainRiskController(
            IDomainRiskAnalyzer domainRiskAnalyzer,
            ILogger<DomainRiskController> logger)
        {
            _domainRiskAnalyzer = domainRiskAnalyzer;
            _logger = logger;
        }

        [HttpGet("analyze")]
        /// <summary>
        /// Returns a full risk-analysis response for the supplied domain.
        /// </summary>
        /// <param name="domain">Domain query value to evaluate.</param>
        /// <returns>Bad request for invalid domains; otherwise risk-analysis result.</returns>
        public ActionResult<DomainRiskAnalysisResult> Analyze([FromQuery] string? domain)
        {
            var result = _domainRiskAnalyzer.AnalyzeDomainRisk(domain);
            if (!result.IsValidDomain)
            {
                return BadRequest(result);
            }

            _logger.LogInformation(
                "Domain risk analysis completed for {Domain}. Score={Score}, KnownActive={KnownActive}",
                result.InputDomain,
                result.OverallRiskScore,
                result.IsKnownActiveDomain);

            return Ok(result);
        }

        [HttpGet("match")]
        /// <summary>
        /// Returns whether the supplied domain is present in the known active-domain list.
        /// </summary>
        /// <param name="domain">Domain query value to check.</param>
        /// <returns>Anonymous payload with match result.</returns>
        public ActionResult<object> Match([FromQuery] string? domain)
        {
            var isKnownActiveDomain = _domainRiskAnalyzer.IsKnownActiveDomain(domain);
            return Ok(new { domain, isKnownActiveDomain });
        }
    }
}
