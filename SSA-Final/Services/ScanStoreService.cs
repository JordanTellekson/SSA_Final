using SSA_Final.Interfaces;
using SSA_Final.Models;

namespace SSA_Final.Services
{
    /// <summary>
    /// Simple synchronized in-memory scan store used by list/detail flows.
    /// </summary>
    public class ScanStoreService : IScanStore
    {
        private readonly List<DomainScan> _scans = new();
        private readonly Lock _lock = new();

        /// <summary>
        /// Adds a scan to the in-memory list.
        /// </summary>
        /// <param name="scan">Scan to add.</param>
        public void Add(DomainScan scan)
        {
            lock (_lock) { _scans.Add(scan); }
        }

        /// <summary>
        /// Returns all scans sorted by newest scan date first.
        /// </summary>
        /// <returns>Sorted scan list.</returns>
        public List<DomainScan> GetAll()
        {
            lock (_lock) { return _scans.OrderByDescending(s => s.ScanDate).ToList(); }
        }

        /// <summary>
        /// Returns one scan by id.
        /// </summary>
        /// <param name="id">Scan id.</param>
        /// <returns>Matching scan or <c>null</c>.</returns>
        public DomainScan? GetById(Guid id)
        {
            lock (_lock) { return _scans.FirstOrDefault(s => s.Id == id); }
        }
    }
}
