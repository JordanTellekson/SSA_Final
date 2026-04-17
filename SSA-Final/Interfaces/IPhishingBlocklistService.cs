using SSA_Final.Models;

namespace SSA_Final.Interfaces
{
    public interface IPhishingBlocklistService
    {
        Task<BlocklistCheckResult> CheckAsync(string domain);
    }
}
