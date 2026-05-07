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
        List<DomainScan> GetInProgressScans();
        Task<bool> GetAnyAsync();
        Task<IPagedResult<DomainScan>> GetPagedAsync(ScanQuery query);
        Task<IReadOnlyList<DomainAnalysisResult>> GetVariantsAsync(
            Guid scanId,
            VariantQuery query);

        /// <summary>
        /// Returns true if a scan for <paramref name="domain"/> already exists with a
        /// <see cref="DomainScan.CreatedAt"/> within the given <paramref name="window"/>.
        /// Used by feed ingestion to skip recently-seen domains and prevent duplicate records.
        /// </summary>
        Task<bool> WasRecentlyScannedAsync(string domain, TimeSpan window);
    }
}

