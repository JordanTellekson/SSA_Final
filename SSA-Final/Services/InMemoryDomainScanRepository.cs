using SSA_Final.Interfaces;
using SSA_Final.Models;

namespace SSA_Final.Services
{
    public class InMemoryDomainScanRepository : IDomainScanRepository
    {
        private readonly List<DomainScan> _scans = new();
        private readonly object _sync = new();

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

        public IReadOnlyList<DomainScan> GetAll()
        {
            lock (_sync)
            {
                return _scans.ToList();
            }
        }

        public DomainScan? GetById(Guid id)
        {
            lock (_sync)
            {
                return _scans.FirstOrDefault(scan => scan.Id == id);
            }
        }

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
