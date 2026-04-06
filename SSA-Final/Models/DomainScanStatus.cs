using System.ComponentModel;

namespace SSA_Final.Models
{
    public enum DomainScanStatus
    {
        [Description("Scan pending")]
        Pending,

        [Description("Scan in progress")]
        InProgress,

        [Description("Scan complete")]
        Complete,

        [Description("Scan complete, malicious domains found")]
        CompleteWithResults
    }
}
