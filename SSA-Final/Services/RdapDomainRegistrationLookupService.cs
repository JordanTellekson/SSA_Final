// RDAP-backed domain registration lookup service.
// Uses IANA's RDAP bootstrap data to find the authoritative registry endpoint.

using Microsoft.Extensions.Caching.Memory;
using SSA_Final.Interfaces;
using SSA_Final.Models;
using System.Globalization;
using System.Text.Json;

namespace SSA_Final.Services
{
    /// <summary>
    /// Retrieves structured registration metadata through RDAP. RDAP is preferred
    /// over raw WHOIS text because it returns JSON with standardized event and
    /// entity fields, which keeps parsing small and testable.
    /// </summary>
    public class RdapDomainRegistrationLookupService : IDomainRegistrationLookupService
    {
        private const string BootstrapCacheKey = "DomainAnalyzer.RdapBootstrap.Dns";
        private const string BootstrapUrl = "https://data.iana.org/rdap/dns.json";

        private readonly IHttpClientFactory _httpClientFactory;
        private readonly IMemoryCache _cache;
        private readonly ILogger<RdapDomainRegistrationLookupService> _logger;
        private readonly TimeSpan _lookupCacheDuration;
        private readonly TimeSpan _bootstrapCacheDuration;

        public RdapDomainRegistrationLookupService(
            IHttpClientFactory httpClientFactory,
            IMemoryCache cache,
            IConfiguration configuration,
            ILogger<RdapDomainRegistrationLookupService> logger)
        {
            _httpClientFactory = httpClientFactory;
            _cache = cache;
            _logger = logger;

            var lookupCacheMinutes = configuration.GetValue<int>(
                "DomainAnalyzer:RegistrationLookupCacheMinutes",
                1440);
            _lookupCacheDuration = TimeSpan.FromMinutes(Math.Max(1, lookupCacheMinutes));

            var bootstrapCacheHours = configuration.GetValue<int>(
                "DomainAnalyzer:RdapBootstrapCacheHours",
                24);
            _bootstrapCacheDuration = TimeSpan.FromHours(Math.Max(1, bootstrapCacheHours));
        }

        public async Task<DomainRegistrationMetadata> LookupAsync(
            string domain,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(domain))
            {
                return Failure(string.Empty, "No domain supplied for registration lookup.");
            }

            var normalizedDomain = domain.Trim().TrimEnd('.').ToLowerInvariant();
            var cacheKey = $"DomainAnalyzer.Registration.{normalizedDomain}";

            var result = await _cache.GetOrCreateAsync(cacheKey, async entry =>
            {
                entry.AbsoluteExpirationRelativeToNow = _lookupCacheDuration;
                return await LookupFreshAsync(normalizedDomain, cancellationToken);
            });

            return result ?? Failure(normalizedDomain, "Registration lookup returned no result.");
        }

        private async Task<DomainRegistrationMetadata> LookupFreshAsync(
            string domain,
            CancellationToken cancellationToken)
        {
            try
            {
                var tld = GetTld(domain);
                if (string.IsNullOrWhiteSpace(tld))
                {
                    return Failure(domain, "Domain does not contain a TLD.");
                }

                var bootstrap = await GetBootstrapAsync(cancellationToken);
                if (!bootstrap.TryGetValue(tld, out var rdapBaseUrl))
                {
                    return Failure(domain, $"No RDAP bootstrap endpoint found for TLD '{tld}'.");
                }

                var rdapUri = BuildDomainLookupUri(rdapBaseUrl, domain);
                var client = _httpClientFactory.CreateClient("DomainAnalyzer.Rdap");

                using var request = new HttpRequestMessage(HttpMethod.Get, rdapUri);
                request.Headers.Accept.ParseAdd("application/rdap+json");
                request.Headers.UserAgent.ParseAdd("SSA-Final-DomainAnalyzer/1.0");

                using var response = await client.SendAsync(
                    request,
                    HttpCompletionOption.ResponseHeadersRead,
                    cancellationToken);

                if (!response.IsSuccessStatusCode)
                {
                    return Failure(
                        domain,
                        $"RDAP lookup failed with HTTP {(int)response.StatusCode}.");
                }

                await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
                using var document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);

                var metadata = ParseRdapResponse(domain, document.RootElement);
                _logger.LogInformation(
                    "[RdapDomainRegistrationLookupService] Registration lookup completed for {Domain}. Created={Created}, Expires={Expires}, Registrar={Registrar}, Privacy={Privacy}",
                    domain,
                    metadata.CreationDateUtc,
                    metadata.ExpirationDateUtc,
                    metadata.RegistrarName,
                    metadata.HasPrivacyProtection);

                return metadata;
            }
            catch (OperationCanceledException)
            {
                return Failure(domain, "RDAP lookup timed out or was cancelled.");
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex,
                    "[RdapDomainRegistrationLookupService] Registration lookup failed for {Domain}.",
                    domain);
                return Failure(domain, "RDAP lookup failed due to an unexpected error.");
            }
        }

        private async Task<IReadOnlyDictionary<string, string>> GetBootstrapAsync(
            CancellationToken cancellationToken)
        {
            var bootstrap = await _cache.GetOrCreateAsync(BootstrapCacheKey, async entry =>
            {
                entry.AbsoluteExpirationRelativeToNow = _bootstrapCacheDuration;

                var client = _httpClientFactory.CreateClient("DomainAnalyzer.Rdap");
                using var response = await client.GetAsync(
                    BootstrapUrl,
                    HttpCompletionOption.ResponseHeadersRead,
                    cancellationToken);
                response.EnsureSuccessStatusCode();

                await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
                using var document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);

                return ParseBootstrap(document.RootElement);
            });

            return bootstrap ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        }

        private static IReadOnlyDictionary<string, string> ParseBootstrap(JsonElement root)
        {
            var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (!root.TryGetProperty("services", out var services) ||
                services.ValueKind != JsonValueKind.Array)
            {
                return map;
            }

            foreach (var service in services.EnumerateArray())
            {
                if (service.ValueKind != JsonValueKind.Array || service.GetArrayLength() < 2)
                {
                    continue;
                }

                var tlds = service[0];
                var urls = service[1];
                if (tlds.ValueKind != JsonValueKind.Array ||
                    urls.ValueKind != JsonValueKind.Array ||
                    urls.GetArrayLength() == 0)
                {
                    continue;
                }

                var baseUrl = urls[0].GetString();
                if (string.IsNullOrWhiteSpace(baseUrl))
                {
                    continue;
                }

                foreach (var tld in tlds.EnumerateArray())
                {
                    var value = tld.GetString();
                    if (!string.IsNullOrWhiteSpace(value))
                    {
                        map[value] = baseUrl;
                    }
                }
            }

            return map;
        }

        private static DomainRegistrationMetadata ParseRdapResponse(
            string domain,
            JsonElement root)
        {
            return new DomainRegistrationMetadata
            {
                Domain = domain,
                CreationDateUtc = GetEventDate(root, "registration", "creation"),
                ExpirationDateUtc = GetEventDate(root, "expiration", "expiry", "expire"),
                RegistrarName = GetRegistrarName(root),
                HasPrivacyProtection = HasPrivacySignal(root),
                IsLookupSuccessful = true
            };
        }

        private static DateTime? GetEventDate(JsonElement root, params string[] actionTerms)
        {
            if (!root.TryGetProperty("events", out var events) ||
                events.ValueKind != JsonValueKind.Array)
            {
                return null;
            }

            foreach (var item in events.EnumerateArray())
            {
                if (!TryGetString(item, "eventAction", out var action) ||
                    !actionTerms.Any(term => action.Contains(term, StringComparison.OrdinalIgnoreCase)) ||
                    !TryGetString(item, "eventDate", out var eventDate))
                {
                    continue;
                }

                if (DateTimeOffset.TryParse(
                        eventDate,
                        CultureInfo.InvariantCulture,
                        DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                        out var parsed))
                {
                    return parsed.UtcDateTime;
                }
            }

            return null;
        }

        private static string? GetRegistrarName(JsonElement root)
        {
            if (TryGetString(root, "registrarName", out var registrarName))
            {
                return registrarName;
            }

            if (!root.TryGetProperty("entities", out var entities) ||
                entities.ValueKind != JsonValueKind.Array)
            {
                return null;
            }

            foreach (var entity in entities.EnumerateArray())
            {
                if (!HasRole(entity, "registrar"))
                {
                    continue;
                }

                return GetVcardText(entity, "fn")
                    ?? GetVcardText(entity, "org")
                    ?? (TryGetString(entity, "handle", out var handle) ? handle : null);
            }

            return null;
        }

        private static bool HasRole(JsonElement entity, string role)
        {
            if (!entity.TryGetProperty("roles", out var roles) ||
                roles.ValueKind != JsonValueKind.Array)
            {
                return false;
            }

            return roles.EnumerateArray().Any(item =>
                item.GetString()?.Equals(role, StringComparison.OrdinalIgnoreCase) == true);
        }

        private static string? GetVcardText(JsonElement entity, string propertyName)
        {
            if (!entity.TryGetProperty("vcardArray", out var vcardArray) ||
                vcardArray.ValueKind != JsonValueKind.Array ||
                vcardArray.GetArrayLength() < 2 ||
                vcardArray[1].ValueKind != JsonValueKind.Array)
            {
                return null;
            }

            foreach (var property in vcardArray[1].EnumerateArray())
            {
                if (property.ValueKind != JsonValueKind.Array ||
                    property.GetArrayLength() < 4 ||
                    property[0].GetString()?.Equals(propertyName, StringComparison.OrdinalIgnoreCase) != true)
                {
                    continue;
                }

                return property[3].ValueKind == JsonValueKind.String
                    ? property[3].GetString()
                    : null;
            }

            return null;
        }

        private static bool HasPrivacySignal(JsonElement root)
        {
            if (root.TryGetProperty("redacted", out var redacted) &&
                redacted.ValueKind == JsonValueKind.Array &&
                redacted.GetArrayLength() > 0)
            {
                return true;
            }

            return ContainsPrivacyText(root);
        }

        private static bool ContainsPrivacyText(JsonElement element)
        {
            return element.ValueKind switch
            {
                JsonValueKind.Object => element.EnumerateObject()
                    .Any(property => ContainsPrivacyText(property.Value)),
                JsonValueKind.Array => element.EnumerateArray().Any(ContainsPrivacyText),
                JsonValueKind.String => IsPrivacyText(element.GetString()),
                _ => false
            };
        }

        private static bool IsPrivacyText(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return false;
            }

            return value.Contains("redacted", StringComparison.OrdinalIgnoreCase) ||
                   value.Contains("privacy", StringComparison.OrdinalIgnoreCase) ||
                   value.Contains("private", StringComparison.OrdinalIgnoreCase) ||
                   value.Contains("withheld", StringComparison.OrdinalIgnoreCase) ||
                   value.Contains("gdpr", StringComparison.OrdinalIgnoreCase);
        }

        private static bool TryGetString(JsonElement element, string propertyName, out string value)
        {
            value = string.Empty;
            if (!element.TryGetProperty(propertyName, out var property) ||
                property.ValueKind != JsonValueKind.String)
            {
                return false;
            }

            value = property.GetString() ?? string.Empty;
            return !string.IsNullOrWhiteSpace(value);
        }

        private static Uri BuildDomainLookupUri(string rdapBaseUrl, string domain)
        {
            var normalizedBase = rdapBaseUrl.EndsWith("/", StringComparison.Ordinal)
                ? rdapBaseUrl
                : rdapBaseUrl + "/";

            return new Uri(new Uri(normalizedBase), $"domain/{Uri.EscapeDataString(domain)}");
        }

        private static string GetTld(string domain)
        {
            var labels = domain.Split('.', StringSplitOptions.RemoveEmptyEntries);
            return labels.Length < 2 ? string.Empty : labels[^1].ToLowerInvariant();
        }

        private static DomainRegistrationMetadata Failure(string domain, string reason)
        {
            return new DomainRegistrationMetadata
            {
                Domain = domain,
                IsLookupSuccessful = false,
                FailureReason = reason
            };
        }
    }
}
