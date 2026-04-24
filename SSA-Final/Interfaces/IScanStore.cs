using SSA_Final.Models;

namespace SSA_Final.Interfaces
{
    public interface IScanStore
    {
        void Add(DomainScan scan);
        List<DomainScan> GetAll();
        DomainScan? GetById(Guid id);
        Task<IPagedResult<DomainScan>> GetPagedAsync(ScanQuery query);
        Task<IReadOnlyList<DomainAnalysisResult>> GetVariantsAsync(
            Guid scanId,
            VariantQuery query);
    }
}