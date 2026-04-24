using SSA_Final.Interfaces;
using SSA_Final.Models;

namespace SSA_Final.Services
{
    public class ScanStoreService : IScanStore
    {
        private readonly List<DomainScan> _scans = new();
        private readonly Lock _lock = new();
        private readonly ISearchService _searchService;

        public ScanStoreService(ISearchService searchService)
        {
            _searchService = searchService;
        }

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

        public Task<IPagedResult<DomainScan>> GetPagedAsync(ScanQuery query)
        {
            query.Page = Math.Max(1, query.Page);
            query.PageSize = Math.Clamp(query.PageSize, 1, 100);

            lock (_lock)
            {
                IEnumerable<DomainScan> scanned = _scans;

                List<DomainScan> items;
                int total;

                if (!string.IsNullOrWhiteSpace(query.Query))
                {
                    var results = _searchService.Search(scanned, query.Query).ToList();

                    query.Page = 1;

                    total = results.Count;

                    items = results
                        .OrderByDescending(x => x.Score)
                        .Skip((query.Page - 1) * query.PageSize)
                        .Take(query.PageSize)
                        .Select(x => x.Item)
                        .ToList();
                }
                else
                {
                    total = scanned.Count();

                    items = scanned
                        .OrderByDescending(s => s.ScannedAt)
                        .Skip((query.Page - 1) * query.PageSize)
                        .Take(query.PageSize)
                        .ToList();
                }

                return Task.FromResult<IPagedResult<DomainScan>>(
                    new PagedResult<DomainScan>
                    {
                        Items = items,
                        TotalCount = total,
                        Page = query.Page,
                        PageSize = query.PageSize
                    }
                );
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