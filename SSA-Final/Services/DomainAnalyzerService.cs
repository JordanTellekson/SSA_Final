using SSA_Final.Interfaces;
using SSA_Final.Models;

namespace SSA_Final.Services
{
    public class DomainAnalyzerService : IDomainAnalyzer
    {
        private readonly ILogger<DomainAnalyzerService> _logger;

        public DomainAnalyzerService(ILogger<DomainAnalyzerService> logger)
        {
            _logger = logger;
        }

        public async Task<DomainAnalysisResult> Analyze(string domain)
        {
            _logger.LogInformation(
                "[DomainAnalyzerService] Analyze called for domain: {Domain}", domain);

            if (string.IsNullOrWhiteSpace(domain))
            {
                _logger.LogWarning(
                    "[DomainAnalyzerService] Analyze received null or empty domain.");

                return new DomainAnalysisResult
                {
                    Domain = domain ?? string.Empty,
                    IsSuspicious = false,
                    Summary = "No domain supplied — analysis skipped.",
                    AnalysedAt = DateTime.UtcNow
                };
            }

            // TODO: Replace with real checks — WHOIS age, DNS fingerprinting,
            //       brand-similarity scoring, blocklist lookups, etc.
            await Task.CompletedTask; // placeholder for future async I/O

            var result = new DomainAnalysisResult
            {
                Domain = domain,
                IsSuspicious = false,
                Summary = "Stub analysis complete — no indicators detected.",
                AnalysedAt = DateTime.UtcNow
            };

            _logger.LogInformation(
                "[DomainAnalyzerService] Analyze completed for {Domain}. Suspicious={IsSuspicious}",
                result.Domain, result.IsSuspicious);

            return result;
        }
    }
}