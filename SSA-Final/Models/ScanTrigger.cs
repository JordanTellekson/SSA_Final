// Indicates what initiated a domain scan, used to branch pipeline behavior in ScanBackgroundService.

using System.ComponentModel;

namespace SSA_Final.Models
{
    public enum ScanTrigger
    {
        [Description("Manual scan")]
        Manual = 0,

        [Description("Feed ingestion")]
        FeedIngestion = 1,

        [Description("Scheduled scan")]
        Scheduled = 2,

        [Description("CertStream ingestion")]
        CertStream = 3
    }
}
