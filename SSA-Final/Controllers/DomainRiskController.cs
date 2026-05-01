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
        private readonly IDomainAnalyzer _domainAnalyzer;
        private readonly ILogger<DomainRiskController> _logger;

        public DomainRiskController(
            IDomainAnalyzer domainAnalyzer,
            ILogger<DomainRiskController> logger)
        {
            _domainAnalyzer = domainAnalyzer;
            _logger = logger;
        }

        [HttpGet("analyze")]
        public async Task<ActionResult<DomainAnalysisResult>> Analyze([FromQuery] string? domain)
        {
            var result = await _domainAnalyzer.AnalyzeDomainRiskAsync(domain);
            NormalizeResult(result, domain);

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
        public ActionResult<DomainAnalysisResult> Match([FromQuery] string? domain)
        {
            var isKnownActiveDomain = _domainAnalyzer.IsKnownActiveDomain(domain);

            var result = new DomainAnalysisResult
            {
                InputDomain = domain?.Trim() ?? string.Empty,
                DiscoveredDomain = domain?.Trim() ?? string.Empty,
                IsKnownActiveDomain = isKnownActiveDomain,
                IsValidDomain = !string.IsNullOrWhiteSpace(domain),
                IsSuspicious = false,
                OverallRiskScore = 0,
                Summary = isKnownActiveDomain
                    ? "Domain found in active-domain list."
                    : "Domain not found in active-domain list."
            };

            NormalizeResult(result, domain);
            return Ok(result);
        }

        private static void NormalizeResult(DomainAnalysisResult result, string? inputDomain)
        {
            var normalizedInput = inputDomain?.Trim() ?? string.Empty;

            if (string.IsNullOrWhiteSpace(result.InputDomain))
            {
                result.InputDomain = normalizedInput;
            }

            if (string.IsNullOrWhiteSpace(result.DiscoveredDomain))
            {
                result.DiscoveredDomain = result.InputDomain;
            }

            result.Indicators ??= new List<string>();

            if (string.IsNullOrWhiteSpace(result.Summary))
            {
                result.Summary = result.IsSuspicious
                    ? "Potential phishing indicators detected."
                    : "No phishing indicators detected.";
            }
        }
    }
}


