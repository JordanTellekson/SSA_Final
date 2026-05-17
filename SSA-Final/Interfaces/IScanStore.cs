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
        Task<IReadOnlyList<DomainScan>> GetCompletedHighRiskScansAsync(TimeSpan lookbackWindow);
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

        /// <summary>
        /// Returns all completed <see cref="DomainScan"/> records where
        /// <see cref="DomainScan.TimeFinished"/> is on or after <paramref name="since"/>
        /// and <see cref="DomainScan.NumMaliciousDomains"/> is at least
        /// <paramref name="minSuspiciousVariants"/>, ordered by
        /// <see cref="DomainScan.NumMaliciousDomains"/> descending.
        /// </summary>
        Task<IReadOnlyList<DomainScan>> GetRecentHighRiskAsync(DateTime since, int minSuspiciousVariants);
    }
}

