using SSA_Final.Models;

namespace SSA_Final.Interfaces
{
    public interface ILegitimateDomainBatchService
    {
        LegitimateDomainBatch GetBatch(int startIndex, int batchSize);
        LegitimateDomainBatchProgress GetProgress(int batchSize, int runLimit);
        LegitimateDomainBatchReservation StartRun(int batchSize, int runLimit);
        LegitimateDomainBatchReservation ReserveNextBatch(int batchSize, int runLimit);
        void CompleteActiveRun();
        void ResetProgress();
    }
}
