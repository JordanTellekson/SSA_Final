namespace SSA_Final.Models
{
    public class LegitimateDomainBatchReservation
    {
        public LegitimateDomainBatch Batch { get; set; } = new();
        public bool IsRunActive { get; set; }
        public bool StartedRun { get; set; }
        public bool CompletedRun { get; set; }
        public int RunStartIndex { get; set; }
        public int RunQueuedCount { get; set; }
        public int RunLimit { get; set; }
    }
}
