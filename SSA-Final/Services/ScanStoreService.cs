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

        public List<DomainScan> GetAll()
        {
            lock (_lock) { return _scans.OrderByDescending(s => s.ScannedAt).ToList(); }
        }

        public DomainScan? GetById(Guid id)
        {
            lock (_lock) { return _scans.FirstOrDefault(s => s.Id == id); }
        }
    }
}