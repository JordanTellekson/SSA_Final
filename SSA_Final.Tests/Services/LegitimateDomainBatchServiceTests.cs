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
