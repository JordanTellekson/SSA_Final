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
                    DomainName = domain ?? string.Empty,
                    IsSuspicious = false,
                    Reason = "No domain supplied - analysis skipped.",
                    Notes = "Input domain was null or whitespace.",
                    AnalysedAt = DateTime.UtcNow
                };
            }

            // TODO: Replace with real checks — WHOIS age, DNS fingerprinting,
            //       brand-similarity scoring, blocklist lookups, etc.
            await Task.CompletedTask; // placeholder for future async I/O

            var result = new DomainAnalysisResult
            {
                DomainName = domain,
                IsSuspicious = false,
                Reason = "Stub analysis complete - no indicators detected.",
                Notes = "Replace with production checks (WHOIS, DNS fingerprints, blocklists, brand similarity).",
                AnalysedAt = DateTime.UtcNow
            };

            _logger.LogInformation(
                "[DomainAnalyzerService] Analyze completed for {Domain}. Suspicious={IsSuspicious}",
                result.DomainName, result.IsSuspicious);

            return result;
        }
    }
}
