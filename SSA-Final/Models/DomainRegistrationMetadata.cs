// RDAP/WHOIS registration metadata used by domain risk scoring.

namespace SSA_Final.Models
{
    /// <summary>
    /// Normalized registration lookup result. Missing values are expected because
    /// RDAP/WHOIS availability varies by TLD, registry, and privacy policy.
    /// </summary>
    public class DomainRegistrationMetadata
    {
        /// <summary>The domain that was queried.</summary>
        public string Domain { get; set; } = string.Empty;

        /// <summary>UTC creation date reported by RDAP/WHOIS, when available.</summary>
        public DateTime? CreationDateUtc { get; set; }

        /// <summary>UTC expiration date reported by RDAP/WHOIS, when available.</summary>
        public DateTime? ExpirationDateUtc { get; set; }

        /// <summary>Registrar name reported by RDAP/WHOIS, when available.</summary>
        public string? RegistrarName { get; set; }

        /// <summary>
        /// True when RDAP/WHOIS data appears redacted, withheld, or privacy-protected.
        /// </summary>
        public bool HasPrivacyProtection { get; set; }

        /// <summary>True when lookup completed and returned parseable registration data.</summary>
        public bool IsLookupSuccessful { get; set; }

        /// <summary>Human-readable reason for lookup failure or incomplete metadata.</summary>
        public string? FailureReason { get; set; }
    }
}
