using SSA_Final.Interfaces;
using SSA_Final.Models;

namespace SSA_Final.Services
{
    /// <summary>
    /// Thread-safe in-memory implementation of <see cref="IDomainScanRepository"/>.
    /// </summary>
    public class InMemoryDomainScanRepository : IDomainScanRepository
    {
        private readonly List<DomainScan> _scans = new();
        private readonly object _sync = new();

        /// <summary>
        /// Adds a new scan record to the in-memory store.
        /// </summary>
        /// <param name="scan">Scan payload to persist.</param>
        /// <returns>The stored scan.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="scan"/> is null.</exception>
        public DomainScan Create(DomainScan scan)
        {
            if (scan is null)
            {
                throw new ArgumentNullException(nameof(scan));
            }

            lock (_sync)
            {
                if (scan.Id == Guid.Empty)
                {
                    scan.Id = Guid.NewGuid();
                }

                _scans.Add(scan);
                return scan;
            }
        }

        /// <summary>
        /// Returns a snapshot list of all scans.
        /// </summary>
        /// <returns>Read-only list of scans.</returns>
        public IReadOnlyList<DomainScan> GetAll()
        {
            lock (_sync)
            {
                return _scans.ToList();
            }
        }

        /// <summary>
        /// Retrieves one scan by id.
        /// </summary>
        /// <param name="id">Scan id.</param>
        /// <returns>Matching scan or <c>null</c> when not found.</returns>
        public DomainScan? GetById(Guid id)
        {
            lock (_sync)
            {
                return _scans.FirstOrDefault(scan => scan.Id == id);
            }
        }

        /// <summary>
        /// Replaces an existing scan with updated data.
        /// </summary>
        /// <param name="scan">Updated scan object.</param>
        /// <returns><c>true</c> when update succeeds; otherwise <c>false</c>.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="scan"/> is null.</exception>
        public bool Update(DomainScan scan)
        {
            if (scan is null)
            {
                throw new ArgumentNullException(nameof(scan));
            }

            lock (_sync)
            {
                var index = _scans.FindIndex(existing => existing.Id == scan.Id);
                if (index < 0)
                {
                    return false;
                }

                _scans[index] = scan;
                return true;
            }
        }

        /// <summary>
        /// Removes a scan from the store.
        /// </summary>
        /// <param name="id">Scan id to delete.</param>
        /// <returns><c>true</c> when a record was deleted.</returns>
        public bool Delete(Guid id)
        {
            lock (_sync)
            {
                var existing = _scans.FirstOrDefault(scan => scan.Id == id);
                if (existing is null)
                {
                    return false;
                }

                _scans.Remove(existing);
                return true;
            }
        }
    }
}
