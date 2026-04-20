using SSA_Final.Interfaces;
using SSA_Final.Models;

namespace SSA_Final.Services.Mocks
{
    /// <summary>
    /// Test double for <see cref="IDomainAnalyzer"/> with call tracking and seedable responses.
    /// </summary>
    public class MockDomainAnalyzer : IDomainAnalyzer
    {
        /// <summary>
        /// Number of times <see cref="Analyze"/> has been invoked.
        /// </summary>
        public int CallCount { get; private set; }

        /// <summary>
        /// Last domain value passed to <see cref="Analyze"/>.
        /// </summary>
        public string LastCalledDomain { get; private set; } = string.Empty;

        // ── Seeded responses ─────────────────────────────────────────────────
        private readonly Dictionary<string, DomainAnalysisResult> _seededResults = new();

        /// <summary>
        /// Seed a pre-defined <see cref="DomainAnalysisResult"/> for a specific domain.
        /// If no seed is found the mock returns a safe default result.
        /// </summary>
        public void SetResult(string domain, DomainAnalysisResult result)
            => _seededResults[domain] = result;

        /// <summary>
        /// Returns a seeded analysis result when configured; otherwise returns a safe default result.
        /// </summary>
        /// <param name="domain">Domain to analyze.</param>
        /// <returns>Seeded or fallback analysis result.</returns>
        public Task<DomainAnalysisResult> Analyze(string domain)
        {
            CallCount++;
            LastCalledDomain = domain;

            if (_seededResults.TryGetValue(domain, out var seeded))
                return Task.FromResult(seeded);

            return Task.FromResult(new DomainAnalysisResult
            {
                DomainName = domain,
                IsSuspicious = false,
                Reason = "Mock analysis — no seed configured for this domain.",
                AnalysedAt = DateTime.UtcNow
            });
        }
    }
}
