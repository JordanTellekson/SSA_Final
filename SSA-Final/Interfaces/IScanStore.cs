// Contract for storing and querying domain scan lifecycle records.

using SSA_Final.Models;

namespace SSA_Final.Interfaces
{
    public interface IScanStore
    {
        void Add(DomainScan scan);
        void Update(DomainScan scan);
        List<DomainScan> GetAll();
        DomainScan? GetById(Guid id);
        List<DomainScan> GetPendingScans();
        Task<bool> GetAnyAsync();
        Task<IPagedResult<DomainScan>> GetPagedAsync(ScanQuery query);
        Task<IReadOnlyList<DomainAnalysisResult>> GetVariantsAsync(
            Guid scanId,
            VariantQuery query);
    }
}

