using System.Net;
using SSA_Final.Interfaces;
using SSA_Final.Models;

namespace SSA_Final.Services
{
    public class LegitimateDomainBatchService : ILegitimateDomainBatchService
    {
        private const string LegitimateDomainsFileName = "Legitimate_Domains.txt";

        private readonly IWebHostEnvironment _hostEnvironment;
        private readonly ILogger<LegitimateDomainBatchService> _logger;

        public LegitimateDomainBatchService(
            IWebHostEnvironment hostEnvironment,
            ILogger<LegitimateDomainBatchService> logger)
        {
            _hostEnvironment = hostEnvironment;
            _logger = logger;
        }

        public LegitimateDomainBatch GetBatch(int startIndex, int batchSize)
        {
            var domains = LoadDomains();
            var safeBatchSize = Math.Clamp(batchSize, 1, 100);
            var safeStartIndex = Math.Clamp(startIndex, 0, domains.Count);
            var batchDomains = domains
                .Skip(safeStartIndex)
                .Take(safeBatchSize)
                .ToList();

            return new LegitimateDomainBatch
            {
                StartIndex = safeStartIndex,
                NextStartIndex = Math.Min(safeStartIndex + batchDomains.Count, domains.Count),
                TotalCount = domains.Count,
                BatchSize = safeBatchSize,
                Domains = batchDomains
            };
        }

        private List<string> LoadDomains()
        {
            var path = Path.Combine(_hostEnvironment.ContentRootPath, LegitimateDomainsFileName);
            if (!File.Exists(path))
            {
                _logger.LogWarning("Legitimate domain batch file not found at path: {Path}", path);
                return new List<string>();
            }

            var domains = new List<string>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var line in File.ReadLines(path))
            {
                var normalized = NormalizeDomain(line);
                if (!string.IsNullOrWhiteSpace(normalized) && seen.Add(normalized))
                {
                    domains.Add(normalized);
                }
            }

            return domains;
        }

        private static string? NormalizeDomain(string? rawDomain)
        {
            if (string.IsNullOrWhiteSpace(rawDomain))
            {
                return null;
            }

            var value = rawDomain.Trim();
            if (value.StartsWith('#'))
            {
                return null;
            }

            if (!value.Contains("://", StringComparison.Ordinal))
            {
                value = "http://" + value;
            }

            if (!Uri.TryCreate(value, UriKind.Absolute, out var uri))
            {
                return null;
            }

            var host = uri.Host.Trim().TrimEnd('.');
            if (host.StartsWith("www.", StringComparison.OrdinalIgnoreCase))
            {
                host = host[4..];
            }

            if (IPAddress.TryParse(host, out _))
            {
                return null;
            }

            return string.IsNullOrWhiteSpace(host) ? null : host.ToLowerInvariant();
        }
    }
}
