using SSA_Final.Interfaces;
using SSA_Final.Models;

namespace SSA_Final.Services.Mocks
{
    public class MockDomainAnalyzer : IDomainAnalyzer
    {
        public int CallCount { get; private set; }
        public string LastCalledDomain { get; private set; } = string.Empty;

        // ── Seeded responses ─────────────────────────────────────────────────
        private readonly Dictionary<string, DomainAnalysisResult> _seededResults = new();

        /// <summary>
        /// Seed a pre-defined <see cref="DomainAnalysisResult"/> for a specific domain.
        /// If no seed is found the mock returns a safe default result.
        /// </summary>
        public void SetResult(string domain, DomainAnalysisResult result)
            => _seededResults[domain] = result;

        public Task<DomainAnalysisResult> Analyze(string domain)
        {
            CallCount++;
            LastCalledDomain = domain;

            if (_seededResults.TryGetValue(domain, out var seeded))
                return Task.FromResult(seeded);

            return Task.FromResult(new DomainAnalysisResult
            {
                Domain = domain,
                IsSuspicious = false,
                Summary = "Mock analysis — no seed configured for this domain.",
                AnalysedAt = DateTime.UtcNow
            });
        }
    }
}