namespace SSA_Final.Models
{
    public class LegitimateDomainBatchProgress
    {
        public int NextStartIndex { get; set; }
        public int RunStartIndex { get; set; }
        public int RunQueuedCount { get; set; }
        public int RunLimit { get; set; }
        public bool IsRunActive { get; set; }
        public DateTime UpdatedAtUtc { get; set; }
        public LegitimateDomainBatch NextBatch { get; set; } = new();

        public int CurrentRunStartDisplay => RunStartIndex + 1;
        public int CurrentRunEndDisplay => Math.Min(RunStartIndex + RunLimit, NextBatch.TotalCount);
        public int RemainingInRun => Math.Max(0, Math.Min(RunLimit - RunQueuedCount, NextBatch.TotalCount - NextStartIndex));
        public bool CanStartRun => !IsRunActive && NextBatch.HasDomains;
    }
}
