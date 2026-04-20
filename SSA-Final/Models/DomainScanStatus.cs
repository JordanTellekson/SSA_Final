using System.ComponentModel;

namespace SSA_Final.Models
{
    public enum DomainScanStatus
    {
        [Description("Scan pending")]
        Pending,

        [Description("Scan in progress")]
        InProgress,

        [Description("Scan completed")]
        Completed,

        [Description("Scan failed")]
        Failed
    }
}
