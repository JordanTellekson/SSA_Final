using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Logging.Abstractions;
using SSA_Final.Services;

namespace SSA_Final.Tests.Services;

public class LegitimateDomainBatchServiceTests : IDisposable
{
    private readonly string _contentRoot;

    public LegitimateDomainBatchServiceTests()
    {
        _contentRoot = Path.Combine(Path.GetTempPath(), $"ssa-legitimate-domains-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_contentRoot);
    }

    [Fact]
    public void GetBatch_ReturnsNormalizedDomainsInBatches()
    {
        File.WriteAllLines(
            Path.Combine(_contentRoot, "Legitimate_Domains.txt"),
            new[]
            {
                "# comment",
                "https://www.google.com/search",
                "google.com",
                "microsoft.com",
                "apple.com",
                "amazon.com",
                "paypal.com",
                "bankofamerica.com",
                "chase.com",
                "wellsfargo.com",
                "netflix.com",
                "facebook.com",
                "127.0.0.1",
                "instagram.com",
                "openai.com"
            });

        var service = CreateService();

        var firstBatch = service.GetBatch(0, 10);
        var secondBatch = service.GetBatch(firstBatch.NextStartIndex, 10);

        Assert.Equal(12, firstBatch.TotalCount);
        Assert.Equal(10, firstBatch.Domains.Count);
        Assert.Equal(10, firstBatch.NextStartIndex);
        Assert.Equal("google.com", firstBatch.Domains[0]);
        Assert.Equal(new[] { "instagram.com", "openai.com" }, secondBatch.Domains);
        Assert.False(secondBatch.HasMore);
    }

    [Fact]
    public void GetBatch_ReturnsEmptyBatchWhenFileIsMissing()
    {
        var service = CreateService();

        var batch = service.GetBatch(0, 10);

        Assert.Empty(batch.Domains);
        Assert.Equal(0, batch.TotalCount);
        Assert.Equal(0, batch.NextStartIndex);
    }

    [Fact]
    public void StartRun_ReservesFirstSetAndPersistsNextSet()
    {
        WriteDomains(60);
        var service = CreateService();

        var reservation = service.StartRun(batchSize: 10, runLimit: 50);
        var progressFromNewInstance = CreateService().GetProgress(batchSize: 10, runLimit: 50);

        Assert.True(reservation.StartedRun);
        Assert.Equal(10, reservation.Batch.Domains.Count);
        Assert.Equal("domain-001.test", reservation.Batch.Domains[0]);
        Assert.Equal(10, reservation.RunQueuedCount);

        Assert.True(progressFromNewInstance.IsRunActive);
        Assert.Equal(10, progressFromNewInstance.NextStartIndex);
        Assert.Equal(10, progressFromNewInstance.NextBatch.StartIndex);
        Assert.Equal("domain-011.test", progressFromNewInstance.NextBatch.Domains[0]);
        Assert.Equal(10, progressFromNewInstance.NextBatch.Domains.Count);
    }

    [Fact]
    public void ReserveNextBatch_StopsAfterFiftyEntriesUntilRunIsCompleted()
    {
        WriteDomains(60);
        var service = CreateService();

        service.StartRun(batchSize: 10, runLimit: 50);
        service.ReserveNextBatch(batchSize: 10, runLimit: 50);
        service.ReserveNextBatch(batchSize: 10, runLimit: 50);
        service.ReserveNextBatch(batchSize: 10, runLimit: 50);
        service.ReserveNextBatch(batchSize: 10, runLimit: 50);

        var progressAtLimit = service.GetProgress(batchSize: 10, runLimit: 50);
        var completion = service.ReserveNextBatch(batchSize: 10, runLimit: 50);
        var progressAfterCompletion = service.GetProgress(batchSize: 10, runLimit: 50);

        Assert.True(progressAtLimit.IsRunActive);
        Assert.Equal(50, progressAtLimit.RunQueuedCount);
        Assert.Empty(progressAtLimit.NextBatch.Domains);

        Assert.True(completion.CompletedRun);
        Assert.False(progressAfterCompletion.IsRunActive);
        Assert.Equal(50, progressAfterCompletion.NextStartIndex);
        Assert.Equal("domain-051.test", progressAfterCompletion.NextBatch.Domains[0]);
    }

    public void Dispose()
    {
        if (Directory.Exists(_contentRoot))
        {
            Directory.Delete(_contentRoot, recursive: true);
        }
    }

    private LegitimateDomainBatchService CreateService()
    {
        return new LegitimateDomainBatchService(
            new TestWebHostEnvironment { ContentRootPath = _contentRoot },
            NullLogger<LegitimateDomainBatchService>.Instance);
    }

    private void WriteDomains(int count)
    {
        File.WriteAllLines(
            Path.Combine(_contentRoot, "Legitimate_Domains.txt"),
            Enumerable.Range(1, count).Select(i => $"domain-{i:000}.test"));
    }

    private sealed class TestWebHostEnvironment : IWebHostEnvironment
    {
        public string ApplicationName { get; set; } = string.Empty;
        public IFileProvider WebRootFileProvider { get; set; } = null!;
        public string WebRootPath { get; set; } = string.Empty;
        public string EnvironmentName { get; set; } = "Development";
        public string ContentRootPath { get; set; } = string.Empty;
        public IFileProvider ContentRootFileProvider { get; set; } = null!;
    }
}
