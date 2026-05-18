using SSA_Final.Models;

namespace SSA_Final.Interfaces
{
    public interface ILegitimateDomainBatchService
    {
        LegitimateDomainBatch GetBatch(int startIndex, int batchSize);
    }
}
