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

        public async Task<IReadOnlyList<DomainScan>> GetAsync(ScanQuery query)
        {
            query.Query = string.IsNullOrWhiteSpace(query.Query)
                ? null
                : query.Query.Trim();

            lock (_lock)
            {
                var filtered = _scans.AsEnumerable();

                if (!string.IsNullOrEmpty(query.Query))
                {
                    filtered = filtered.Where(s =>
                        s.BaseDomain.Contains(query.Query, StringComparison.OrdinalIgnoreCase));
                }

                return filtered
                    .OrderByDescending(s => s.ScannedAt) // FIXED
                    .ToList();
            }
        }

        public Task<IReadOnlyList<DomainAnalysisResult>> GetVariantsAsync(
            Guid scanId,
            VariantQuery query)
        {
            query.Query = string.IsNullOrWhiteSpace(query.Query)
                ? null
                : query.Query.Trim();

            lock (_lock)
            {
                var scan = _scans.FirstOrDefault(s => s.Id == scanId);

                if (scan == null)
                    return Task.FromResult<IReadOnlyList<DomainAnalysisResult>>(
                        new List<DomainAnalysisResult>());

                var variants = scan.Variants.AsEnumerable(); // ✅ FIXED

                if (!string.IsNullOrEmpty(query.Query))
                {
                    variants = variants.Where(v =>
                        v.Domain.Contains(query.Query, StringComparison.OrdinalIgnoreCase)); // ✅ FIXED
                }

                return Task.FromResult<IReadOnlyList<DomainAnalysisResult>>(
                    variants.ToList());
            }
        }
    }
}