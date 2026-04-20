using SSA_Final.Interfaces;
using Microsoft.EntityFrameworkCore;
using SSA_Final.Data;
using SSA_Final.Models;

namespace SSA_Final.Services
{
    public class SqlScanStoreService : IScanStore
    {
        private readonly SSA_FinalContext _dbContext;

        public SqlScanStoreService(SSA_FinalContext dbContext)
        {
            _dbContext = dbContext;
        }

        public void Add(DomainScan scan)
        {
            _dbContext.Add(scan);
            _dbContext.SaveChanges();
        }

        public void Update(DomainScan scan)
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

        public List<DomainScan> GetAll()
        {
            return _dbContext.DomainScans
                .Include(x => x.Variants)
                .OrderByDescending(x => x.CreatedAt)
                .ToList();
        }

        public DomainScan? GetById(Guid id)
        {
            return _dbContext.DomainScans
                .Include(x => x.Variants)
                .FirstOrDefault(x => x.Id == id);
        }

    }
}
