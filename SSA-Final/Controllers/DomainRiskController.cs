// API controller exposing domain risk analysis and active-domain matching endpoints.
// Returns structured scoring payloads used by client integrations.

using Microsoft.AspNetCore.Mvc;
using SSA_Final.Interfaces;
using SSA_Final.Models;

namespace SSA_Final.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class DomainRiskController : ControllerBase
    {
        private readonly IDomainRiskAnalyzer _domainRiskAnalyzer;
        private readonly ILogger<DomainRiskController> _logger;

        public DomainRiskController(
            IDomainRiskAnalyzer domainRiskAnalyzer,
            ILogger<DomainRiskController> logger)
        {
            _domainRiskAnalyzer = domainRiskAnalyzer;
            _logger = logger;
        }

        [HttpGet("analyze")]
        public async Task<ActionResult<DomainRiskAnalysisResult>> Analyze([FromQuery] string? domain)
        {
            var result = await _domainRiskAnalyzer.AnalyzeDomainRiskAsync(domain);
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
        public ActionResult<object> Match([FromQuery] string? domain)
        {
            var isKnownActiveDomain = _domainRiskAnalyzer.IsKnownActiveDomain(domain);
            return Ok(new { domain, isKnownActiveDomain });
        }
    }
}


