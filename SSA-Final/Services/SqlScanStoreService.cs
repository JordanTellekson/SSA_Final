using SSA_Final.Exceptions;
using SSA_Final.Interfaces;
using Microsoft.EntityFrameworkCore;
using SSA_Final.Data;
using SSA_Final.Models;

namespace SSA_Final.Services
{
    public class SqlScanStoreService : IScanStore
    {
        private readonly SSA_FinalContext _dbContext;
        private readonly ISearchService _searchService;
        private readonly ILogger<SqlScanStoreService> _logger;

        public SqlScanStoreService(
            SSA_FinalContext dbContext,
            ISearchService searchService,
            ILogger<SqlScanStoreService> logger)
        {
            _dbContext = dbContext;
            _searchService = searchService;
            _logger = logger;
        }

        public void Add(DomainScan scan)
        {
            try
            {
                _dbContext.Add(scan);
                _dbContext.SaveChanges();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "ScanStore: failed to add scan {ScanId} for domain '{Domain}'.",
                    scan.Id, scan.BaseDomain);
                throw new ScanStoreException(
                    $"Failed to persist new scan {scan.Id} for domain '{scan.BaseDomain}'.", ex);
            }
        }

        public void Update(DomainScan scan)
        {
            try
            {
                foreach (var variant in scan.Variants)
                {
                    if (_dbContext.Entry(variant).State == EntityState.Detached)
                    {
                        _dbContext.DomainAnalysisResults.Add(variant);
                    }
                }

                _dbContext.SaveChanges();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "ScanStore: failed to update scan {ScanId}.", scan.Id);
                throw new ScanStoreException(
                    $"Failed to update scan {scan.Id}.", ex);
            }
        }

        public List<DomainScan> GetAll()
        {
            try
            {
                return _dbContext.DomainScans
                    .Include(x => x.Variants)
                    .OrderByDescending(x => x.CreatedAt)
                    .ToList();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "ScanStore: failed to retrieve all scans.");
                throw new ScanStoreException("Failed to retrieve all scans.", ex);
            }
        }

        public DomainScan? GetById(Guid id)
        {
            try
            {
                return _dbContext.DomainScans
                    .Include(x => x.Variants)
                    .FirstOrDefault(x => x.Id == id);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "ScanStore: failed to retrieve scan {ScanId}.", id);
                throw new ScanStoreException($"Failed to retrieve scan {id}.", ex);
            }
        }

        public List<DomainScan> GetPendingScans()
        {
            try
            {
                return _dbContext.DomainScans
                    .Where(x => x.Status == DomainScanStatus.Pending)
                    .ToList();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "ScanStore: failed to retrieve pending scans.");
                throw new ScanStoreException("Failed to retrieve pending scans.", ex);
            }
        }

        public List<DomainScan> GetInProgressScans()
        {
            try
            {
                return _dbContext.DomainScans
                    .Where(x => x.Status == DomainScanStatus.InProgress)
                    .ToList();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "ScanStore: failed to retrieve in-progress scans.");
                throw new ScanStoreException("Failed to retrieve in-progress scans.", ex);
            }
        }

        public async Task<bool> GetAnyAsync()
        {
            return await _dbContext.DomainScans.AnyAsync();
        }

        public async Task<IPagedResult<DomainScan>> GetPagedAsync(ScanQuery query)
        {
            query.Page = Math.Max(1, query.Page);
            query.PageSize = Math.Clamp(query.PageSize, 1, 100);

            IQueryable<DomainScan> scanned = _dbContext.DomainScans;

            // Filtering
            if (query.Status.HasValue)
            {
                scanned = scanned.Where(s => s.Status == query.Status.Value);
            }

            if (query.HasMalicious.HasValue)
            {
                scanned = query.HasMalicious.Value
                    ? scanned.Where(s => s.NumMaliciousDomains > 0)
                    : scanned.Where(s => s.NumMaliciousDomains == 0);
            }

            // SEARCH path (must materialize for scoring)
            if (!string.IsNullOrWhiteSpace(query.Query))
            {
                var list = await scanned.ToListAsync();

                var results = _searchService.Search(list, query.Query).ToList();

                query.Page = 1;

                var total = results.Count;

                var items = results
                    .OrderByDescending(x => x.Score)
                    .Skip((query.Page - 1) * query.PageSize)
                    .Take(query.PageSize)
                    .Select(x => x.Item)
                    .ToList();

                return new PagedResult<DomainScan>
                {
                    Items = items,
                    TotalCount = total,
                    Page = query.Page,
                    PageSize = query.PageSize
                };
            }

            // NORMAL paging (database-side)
            var totalCount = await scanned.CountAsync();

            var pageItems = await scanned
                .OrderByDescending(s => s.TimeFinished ?? s.CreatedAt)
                .Skip((query.Page - 1) * query.PageSize)
                .Take(query.PageSize)
                .ToListAsync();

            return new PagedResult<DomainScan>
            {
                Items = pageItems,
                TotalCount = totalCount,
                Page = query.Page,
                PageSize = query.PageSize
            };
        }

        public async Task<IReadOnlyList<DomainAnalysisResult>> GetVariantsAsync(
            Guid scanId,
            VariantQuery query)
        {
            query.Query = string.IsNullOrWhiteSpace(query.Query)
                ? null
                : query.Query.Trim();

            var variantsQuery = _dbContext.DomainAnalysisResults
                .Where(v => v.DomainScanId == scanId);

            if (!string.IsNullOrEmpty(query.Query))
            {
                variantsQuery = variantsQuery.Where(v =>
                    v.DiscoveredDomain.Contains(query.Query));
            }

            return await variantsQuery.ToListAsync();
        }
    }
}
