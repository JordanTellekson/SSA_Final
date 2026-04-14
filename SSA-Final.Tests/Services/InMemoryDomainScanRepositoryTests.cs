using SSA_Final.Models;
using SSA_Final.Services;
using Xunit;

namespace SSA_Final.Tests.Services
{
    public class InMemoryDomainScanRepositoryTests
    {
        [Fact]
        public void Crud_Should_Create_Read_Update_And_Delete_DomainScan()
        {
            var repository = new InMemoryDomainScanRepository();
            var scan = new DomainScan
            {
                BaseDomain = "example.com",
                ScanDate = DateTime.UtcNow
            };

            var created = repository.Create(scan);
            Assert.NotEqual(Guid.Empty, created.Id);

            var loaded = repository.GetById(created.Id);
            Assert.NotNull(loaded);
            Assert.Equal("example.com", loaded!.BaseDomain);

            loaded.Status = DomainScanStatus.Complete;
            loaded.Results = new List<DomainAnalysisResult>
            {
                new()
                {
                    DomainName = "example.com",
                    IsSuspicious = false,
                    Reason = "No indicators",
                    Notes = "Clean"
                }
            };

            var updated = repository.Update(loaded);
            Assert.True(updated);
            Assert.Single(repository.GetAll());

            var deleted = repository.Delete(created.Id);
            Assert.True(deleted);
            Assert.Empty(repository.GetAll());
        }
    }
}
