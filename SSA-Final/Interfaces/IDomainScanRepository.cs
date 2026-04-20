using SSA_Final.Models;

namespace SSA_Final.Interfaces
{
    /// <summary>
    /// Repository abstraction for persisting and retrieving domain scan records.
    /// </summary>
    public interface IDomainScanRepository
    {
        /// <summary>
        /// Persists a new scan entry.
        /// </summary>
        /// <param name="scan">Scan to store.</param>
        /// <returns>The stored scan instance.</returns>
        DomainScan Create(DomainScan scan);

        /// <summary>
        /// Returns all known scans.
        /// </summary>
        /// <returns>Read-only list of scan records.</returns>
        IReadOnlyList<DomainScan> GetAll();

        /// <summary>
        /// Finds a scan by unique identifier.
        /// </summary>
        /// <param name="id">Scan id.</param>
        /// <returns>Matching scan when found; otherwise <c>null</c>.</returns>
        DomainScan? GetById(Guid id);

        /// <summary>
        /// Replaces an existing scan entry.
        /// </summary>
        /// <param name="scan">Updated scan payload.</param>
        /// <returns><c>true</c> if the scan exists and was replaced.</returns>
        bool Update(DomainScan scan);

        /// <summary>
        /// Deletes a scan by id.
        /// </summary>
        /// <param name="id">Scan id.</param>
        /// <returns><c>true</c> when a record was removed.</returns>
        bool Delete(Guid id);
    }
}
