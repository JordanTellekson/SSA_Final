using SSA_Final.Interfaces;

namespace SSA_Final.Services
{
    public class DomainGeneratorService : IDomainGenerator
    {
        private readonly ILogger<DomainGeneratorService> _logger;

        public DomainGeneratorService(ILogger<DomainGeneratorService> logger)
        {
            _logger = logger;
        }

        /// <inheritdoc />
        public IEnumerable<string> GenerateVariations(string baseDomain)
        {
            _logger.LogInformation(
                "[DomainGeneratorService] GenerateVariations called for domain: {Domain}",
                baseDomain);

            if (string.IsNullOrWhiteSpace(baseDomain))
            {
                _logger.LogWarning(
                    "[DomainGeneratorService] GenerateVariations received null or empty domain.");
                return Enumerable.Empty<string>();
            }

            // TODO: Replace with a real typosquatting / homoglyph engine.
            var parts = baseDomain.Split('.', 2);
            if (parts.Length < 2)
            {
                _logger.LogWarning(
                    "[DomainGeneratorService] Domain '{Domain}' could not be split into name + TLD.",
                    baseDomain);
                return Enumerable.Empty<string>();
            }

            var name = parts[0];
            var tld = parts[1];

            var variations = new List<string>
            {
                // Character omission
                name.Length > 1 ? $"{name[1..]}.{tld}" : baseDomain,
                // Character duplication
                $"{name}{name[^1]}.{tld}",
                // Common TLD swap
                $"{name}.net",
                $"{name}.org",
                // Hyphen insertion
                name.Length > 2 ? $"{name[..^1]}-{name[^1]}.{tld}" : baseDomain,
            };

            _logger.LogInformation(
                "[DomainGeneratorService] Generated {Count} variation(s) for domain: {Domain}",
                variations.Count, baseDomain);

            return variations.Distinct();
        }
    }
}