using System.ComponentModel;

namespace SSA_Final.Models
{
    /// <summary>
    /// Lifecycle states for a domain scan job.
    /// </summary>
    public enum DomainScanStatus
    {
        /// <summary>
        /// Scan has been created but not started.
        /// </summary>
        [Description("Scan pending")]
        Pending,

        /// <summary>
        /// Scan is currently processing domain variants.
        /// </summary>
        [Description("Scan in progress")]
        InProgress,

        /// <summary>
        /// Scan finished with no suspicious findings.
        /// </summary>
        [Description("Scan complete")]
        Complete,

        /// <summary>
        /// Scan finished and found at least one suspicious result.
        /// </summary>
        [Description("Scan complete, malicious domains found")]
        CompleteWithResults
    }
}
