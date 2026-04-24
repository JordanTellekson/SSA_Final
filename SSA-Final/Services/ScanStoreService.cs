// In-memory scan store used for process-local scan lifecycle persistence.
// Provides thread-safe add/update/query operations for dashboard and history pages.

using SSA_Final.Interfaces;
using SSA_Final.Models;

namespace SSA_Final.Services
{
    public class ScanStoreService : IScanStore
    {
        private readonly List<DomainScan> _scans = new();
        private readonly Lock _lock = new();

        public void Add(DomainScan scan)
        {
            lock (_lock) { _scans.Add(scan); }
        }

        public void Update(DomainScan scan)
        {
            lock (_lock)
            {
                var index = _scans.FindIndex(s => s.Id == scan.Id);
                if (index >= 0)
                {
                    _scans[index] = scan;
                }
            }
        }

        public List<DomainScan> GetAll()
        {
            lock (_lock) { return _scans.OrderByDescending(s => s.CreatedAt).ToList(); }
        }

        public DomainScan? GetById(Guid id)
        {
            lock (_lock) { return _scans.FirstOrDefault(s => s.Id == id); }
        }
    }
}

