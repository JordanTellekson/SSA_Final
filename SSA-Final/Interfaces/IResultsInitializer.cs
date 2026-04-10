using SSA_Final.Models;

namespace SSA_Final.Interfaces
{
    public interface IResultsInitializer
    {
        public List<DiscoveredDomain> GetInitialResults();
    }
}
