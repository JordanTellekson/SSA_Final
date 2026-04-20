using SSA_Final.Interfaces;

namespace SSA_Final.Services.Mocks
{
    /// <summary>
    /// Test double for <see cref="IDomainGenerator"/> with call tracking and seedable responses.
    /// </summary>
    public class MockDomainGenerator : IDomainGenerator
    {
        // Call tracking
        /// <summary>
        /// Number of times <see cref="GenerateVariations"/> has been invoked.
        /// </summary>
        public int CallCount { get; private set; }

        /// <summary>
        /// Last domain value passed to <see cref="GenerateVariations"/>.
        /// </summary>
        public string LastCalledDomain { get; private set; } = string.Empty;

        // Seeded responses
        private readonly Dictionary<string, IEnumerable<string>> _seededVariations = new();

        /// <summary>
        /// Seed a pre-defined list of variations for a specific domain.
        /// If no seed is found the mock returns a generic placeholder instead of throwing.
        /// </summary>
        public void SetVariations(string domain, IEnumerable<string> variations)
            => _seededVariations[domain] = variations;

        /// <summary>
        /// Returns seeded variations when available, otherwise a deterministic placeholder variation.
        /// </summary>
        /// <param name="baseDomain">Base domain input.</param>
        /// <returns>Seeded or fallback variation sequence.</returns>
        public IEnumerable<string> GenerateVariations(string baseDomain)
        {
            CallCount++;
            LastCalledDomain = baseDomain;

            if (_seededVariations.TryGetValue(baseDomain, out var seeded))
                return seeded;

            return new[] { $"mock-variation-of-{baseDomain}" };
        }
    }
}
