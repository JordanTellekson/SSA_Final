using SSA_Final.Interfaces;

namespace SSA_Final.Services.Mocks
{
    public class MockDomainGenerator : IDomainGenerator
    {
        // Call tracking
        public int CallCount { get; private set; }
        public string LastCalledDomain { get; private set; } = string.Empty;

        // Seeded responses
        private readonly Dictionary<string, IEnumerable<string>> _seededVariations = new();

        /// <summary>
        /// Seed a pre-defined list of variations for a specific domain.
        /// If no seed is found the mock returns a generic placeholder instead of throwing.
        /// </summary>
        public void SetVariations(string domain, IEnumerable<string> variations)
            => _seededVariations[domain] = variations;

        // IDomainGenerator
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