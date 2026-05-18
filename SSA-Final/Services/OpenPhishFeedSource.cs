// Fetches suspected phishing hostnames from the OpenPhish community feed (feed.txt).
// Implements IDomainFeedSource so it can be enumerated alongside other feed sources
// by FeedIngestionBackgroundService without any coupling to PhishingBlocklistService.

using SSA_Final.Interfaces;

namespace SSA_Final.Services
{
    public class OpenPhishFeedSource : IDomainFeedSource
    {
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly ILogger<OpenPhishFeedSource> _logger;
        private readonly string _feedUrl;

        /// <summary>Named HttpClient registered in Program.cs for this feed source.</summary>
        public const string HttpClientName = "FeedSource.OpenPhish";

        public string Name => "OpenPhish";

        public OpenPhishFeedSource(
            IHttpClientFactory httpClientFactory,
            ILogger<OpenPhishFeedSource> logger,
            IConfiguration configuration)
        {
            _httpClientFactory = httpClientFactory;
            _logger = logger;
            _feedUrl = configuration["FeedSources:OpenPhish:Url"]
                ?? "https://openphish.com/feed.txt";
        }

        public async Task<IEnumerable<string>> FetchDomainsAsync(CancellationToken ct)
        {
            try
            {
                var client = _httpClientFactory.CreateClient(HttpClientName);
                var raw = await client.GetStringAsync(_feedUrl, ct);

                var domains = raw
                    .Split('\n', StringSplitOptions.RemoveEmptyEntries)
                    .Select(ParseDomain)
                    .Where(d => !string.IsNullOrWhiteSpace(d))
                    .Select(d => d!)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList();

                _logger.LogInformation(
                    "{FeedSource}: fetched {Count} domain(s) from {Url}.",
                    Name, domains.Count, _feedUrl);

                return domains;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(
                    ex,
                    "{FeedSource}: failed to fetch feed from {Url} — returning empty list.",
                    Name, _feedUrl);

                return Enumerable.Empty<string>();
            }
        }

        /// <summary>
        /// Extracts the hostname from a raw feed entry.
        /// OpenPhish provides full URLs (e.g. https://evil.com/phish), so we normalize
        /// to the bare host. Matches the normalization logic in PhishingBlocklistService.
        /// </summary>
        private static string? ParseDomain(string raw)
        {
            if (string.IsNullOrWhiteSpace(raw))
                return null;

            var value = raw.Trim();

            if (!value.Contains("://", StringComparison.Ordinal))
                value = "http://" + value;

            if (!Uri.TryCreate(value, UriKind.Absolute, out var uri))
                return null;

            var host = uri.Host.Trim().TrimEnd('.');

            if (host.StartsWith("www.", StringComparison.OrdinalIgnoreCase))
                host = host[4..];

            return string.IsNullOrWhiteSpace(host)
                ? null
                : host.ToLowerInvariant();
        }
    }
}
