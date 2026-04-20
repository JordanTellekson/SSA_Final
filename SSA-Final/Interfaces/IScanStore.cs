using SSA_Final.Models;

namespace SSA_Final.Interfaces
{
    /// <summary>
    /// Lightweight in-memory scan store contract used by list/detail pages.
    /// </summary>
    public interface IScanStore
    {
        /// <summary>
        /// Adds a scan record to the store.
        /// </summary>
        /// <param name="scan">Scan record to add.</param>
        void Add(DomainScan scan);

        /// <summary>
        /// Returns all scans currently held in memory.
        /// </summary>
        /// <returns>Scan list in store-defined order.</returns>
        List<DomainScan> GetAll();

        /// <summary>
        /// Retrieves a scan by id.
        /// </summary>
        /// <param name="id">Scan id.</param>
        /// <returns>Matching scan or <c>null</c> when absent.</returns>
        DomainScan? GetById(Guid id);
    }
}
