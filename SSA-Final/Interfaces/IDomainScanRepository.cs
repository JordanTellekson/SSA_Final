using SSA_Final.Models;

namespace SSA_Final.Interfaces
{
    public interface IDomainScanRepository
    {
        DomainScan Create(DomainScan scan);

        IReadOnlyList<DomainScan> GetAll();

        DomainScan? GetById(Guid id);

        bool Update(DomainScan scan);

        bool Delete(Guid id);
    }
}
