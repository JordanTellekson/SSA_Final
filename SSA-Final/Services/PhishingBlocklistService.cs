// Service that fetches and caches phishing domains from OpenPhish.
// Normalizes entries to hostnames and supports resilient fallback behavior.

using Microsoft.Extensions.Caching.Memory;
using SSA_Final.Interfaces;
using SSA_Final.Models;

namespace SSA_Final.Services
{
    public class PhishingBlocklistService : IPhishingBlocklistService
    {
        private readonly IMemoryCache _cache;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly ILogger<PhishingBlocklistService> _logger;

        private const string CacheKey = "PhishingBlocklist";
        private static readonly TimeSpan CacheTtl = TimeSpan.FromMinutes(60);

        public PhishingBlocklistService(
            IMemoryCache cache,
            IHttpClientFactory httpClientFactory,
            ILogger<PhishingBlocklistService> logger)
        {
            _cache = cache;
            _httpClientFactory = httpClientFactory;
            _logger = logger;
        }

        public async Task<BlocklistCheckResult> CheckAsync(string domain)
        {
            var (domains, lastUpdated, isStale) = await GetBlocklistAsync();

            return new BlocklistCheckResult
            {
                IsMatch = domains.Contains(domain),
                Source = "OpenPhish",
                LastUpdated = lastUpdated,
                IsStale = isStale
            };
        }

        private async Task<(HashSet<string> Domains, DateTime LastUpdated, bool IsStale)> GetBlocklistAsync()
        {
            if (_cache.TryGetValue(CacheKey, out (HashSet<string>, DateTime, bool) cached))
            {
                return cached;
            }

            try
            {
                var client = _httpClientFactory.CreateClient();
                var data = await client.GetStringAsync("https://openphish.com/feed.txt");

                var domains = data.Split('\n', StringSplitOptions.RemoveEmptyEntries)
                    .Select(ParseDomain)
                    .Where(d => !string.IsNullOrWhiteSpace(d))
                    .ToHashSet(StringComparer.OrdinalIgnoreCase);

                var result = (
                    Domains: domains,
                    LastUpdated: DateTime.UtcNow,
                    IsStale: false
                );

                _cache.Set(CacheKey, result, CacheTtl);

                return result;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to fetch phishing blocklist. Falling back to empty dataset.");

                // Graceful degradation
                return (
                    Domains: new HashSet<string>(StringComparer.OrdinalIgnoreCase),
                    LastUpdated: DateTime.UtcNow,
                    IsStale: true
                );
            }
        }

        /// <summary>
        /// Extracts the host/domain from a blocklist entry.
        /// OpenPhish provides full URLs, so we normalize to host.
        /// </summary>
        private static string? ParseDomain(string raw)
        {
            if (string.IsNullOrWhiteSpace(raw))
                return null;

            var value = raw.Trim();

            if (!value.Contains("://", StringComparison.Ordinal))
            {
                value = "http://" + value;
            }

            if (!Uri.TryCreate(value, UriKind.Absolute, out var uri))
                return null;

            var host = uri.Host.Trim().TrimEnd('.');

            if (host.StartsWith("www.", StringComparison.OrdinalIgnoreCase))
            {
                host = host[4..];
            }

            return string.IsNullOrWhiteSpace(host)
                ? null
                : host.ToLowerInvariant();
        }
    }
}

