// Aggregated statistics over all DomainScan records.
// Populated by IScanStore.GetScanStatsAsync and surfaced on the Dashboard.

namespace SSA_Final.Models
{
    public class ScanStats
    {
        /// <summary>Total number of scan records in the system.</summary>
        public int TotalScans { get; set; }

        /// <summary>
        /// Sum of VariantCount across all scans — the total number of candidate domains
        /// that have been submitted for analysis.
        /// </summary>
        public int TotalVariantsAnalyzed { get; set; }

        /// <summary>Total number of variant records flagged as suspicious.</summary>
        public int TotalSuspiciousVariants { get; set; }

        /// <summary>Number of scans that contain at least one suspicious variant.</summary>
        public int ScansWithThreats { get; set; }

        /// <summary>Number of scans currently in Pending or InProgress state.</summary>
        public int ActiveScans { get; set; }

        /// <summary>
        /// Scan counts broken down by ScanTrigger label (Manual, Scheduled,
        /// FeedIngestion, CertStream). Useful for reporting on ingestion source volume.
        /// </summary>
        public Dictionary<string, int> ScansByTrigger { get; set; } = new();
    }
}
