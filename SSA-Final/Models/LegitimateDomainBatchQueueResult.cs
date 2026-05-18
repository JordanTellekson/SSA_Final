namespace SSA_Final.Models
{
    public enum LegitimateDomainBatchQueueStatus
    {
        Queued,
        ActiveScansInProgress,
        NoDomains,
        RunNotActive,
        RunComplete
    }

    public class LegitimateDomainBatchQueueResult
    {
        public LegitimateDomainBatchQueueStatus Status { get; set; }
        public int CreatedScans { get; set; }
        public int SubmittedScans { get; set; }
        public int ActiveScanCount { get; set; }
        public int RunQueuedCount { get; set; }
        public int RunLimit { get; set; }
        public int TotalCount { get; set; }
        public int RangeStart { get; set; }
        public int RangeEnd { get; set; }
    }
}
