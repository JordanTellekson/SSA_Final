using SSA_Final.Interfaces;
using SSA_Final.Models;

namespace SSA_Final.Services
{
    /// <summary>
    /// Performs per-domain variant analysis and returns structured findings.
    /// </summary>
    public class DomainAnalyzerService : IDomainAnalyzer
    {
        private readonly ILogger<DomainAnalyzerService> _logger;

        /// <summary>
        /// Creates the analyzer service.
        /// </summary>
        public DomainAnalyzerService(ILogger<DomainAnalyzerService> logger)
        {
            _logger = logger;
        }

        /// <summary>
        /// Analyzes a single domain candidate and returns suspiciousness details.
        /// </summary>
        /// <param name="domain">Domain candidate to analyze.</param>
        /// <returns>Analysis result for the provided domain.</returns>
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
