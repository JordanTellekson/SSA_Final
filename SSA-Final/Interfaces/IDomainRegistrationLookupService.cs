// Contract for retrieving registration metadata used by domain risk scoring.

using SSA_Final.Models;

namespace SSA_Final.Interfaces
{
    /// <summary>
    /// Looks up RDAP/WHOIS-style registration metadata for a domain. Implementations
    /// must fail gracefully because registries can rate-limit, redact, or omit data.
    /// </summary>
    public interface IDomainRegistrationLookupService
    {
        /// <summary>
        /// Retrieves creation, expiration, registrar, and redaction metadata for
        /// <paramref name="domain"/> without throwing for normal lookup failures.
        /// </summary>
        Task<DomainRegistrationMetadata> LookupAsync(
            string domain,
            CancellationToken cancellationToken = default);
    }
}
