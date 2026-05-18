using Microsoft.Extensions.Configuration;
using SSA_Final.Interfaces;
using SSA_Final.Models;
using SSA_Final.Services;

namespace SSA_Final.Tests.Services;

internal sealed class FakeReportScanStore : IScanStore
{
    private readonly IReadOnlyList<DomainScan> _scans;

    public FakeReportScanStore(IReadOnlyList<DomainScan> scans)
    {
        _scans = scans;
    }

    public void Add(DomainScan scan)
    {
        throw new NotSupportedException();
    }

    public void Update(DomainScan scan)
    {
        throw new NotSupportedException();
    }

    public List<DomainScan> GetAll()
    {
        return _scans.ToList();
    }

    public DomainScan? GetById(Guid id)
    {
        return _scans.FirstOrDefault(scan => scan.Id == id);
    }

    public List<DomainScan> GetPendingScans()
    {
        return _scans.Where(scan => scan.Status == DomainScanStatus.Pending).ToList();
    }

    public List<DomainScan> GetInProgressScans()
    {
        return _scans.Where(scan => scan.Status == DomainScanStatus.InProgress).ToList();
    }

    public Task<bool> GetAnyAsync()
    {
        return Task.FromResult(_scans.Count > 0);
    }

    public Task<IReadOnlyList<DomainScan>> GetCompletedHighRiskScansAsync(TimeSpan lookbackWindow)
    {
        var cutoff = DateTime.UtcNow - lookbackWindow;
        var scans = _scans
            .Where(scan =>
                scan.Status == DomainScanStatus.Completed &&
                scan.NumMaliciousDomains > 0 &&
                (scan.TimeFinished ?? scan.CreatedAt) >= cutoff)
            .ToList();

        return Task.FromResult<IReadOnlyList<DomainScan>>(scans);
    }

    public Task<IPagedResult<DomainScan>> GetPagedAsync(ScanQuery query)
    {
        throw new NotSupportedException();
    }

    public Task<IReadOnlyList<DomainAnalysisResult>> GetVariantsAsync(Guid scanId, VariantQuery query)
    {
        return Task.FromResult<IReadOnlyList<DomainAnalysisResult>>(
            GetById(scanId)?.Variants ?? new List<DomainAnalysisResult>());
    }

    public Task<bool> WasRecentlyScannedAsync(string domain, TimeSpan window)
    {
        throw new NotSupportedException();
    }
}

public class ReportServiceTests
{
    private static IConfiguration BuildConfig(double lookbackHours = 24)
    {
        return new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Reports:HighRiskLookbackHours"] = lookbackHours.ToString()
            })
            .Build();
    }

    private static DomainScan MakeScan(
        string domain,
        DateTime timestamp,
        int suspiciousCount,
        params DomainAnalysisResult[] variants)
    {
        return new DomainScan
        {
            Id = Guid.NewGuid(),
            BaseDomain = domain,
            CreatedAt = timestamp.AddMinutes(-2),
            TimeFinished = timestamp,
            Status = DomainScanStatus.Completed,
            NumMaliciousDomains = suspiciousCount,
            Variants = variants.ToList()
        };
    }

    [Fact]
    public async Task GenerateHighRiskAlertReport_FiltersToCompletedHighRiskScansInWindow()
    {
        var now = DateTime.UtcNow;
        var included = MakeScan(
            "paypal.com",
            now.AddHours(-2),
            1,
            new DomainAnalysisResult
            {
                DiscoveredDomain = "paypa1-login.com",
                IsSuspicious = true,
                TopRiskSignal = "Typosquatting/Edit Distance",
                TopRiskSignalScore = 20,
                TopRiskSignalDetail = "Close brand match."
            });
        var clean = MakeScan("example.com", now.AddHours(-1), 0);
        var old = MakeScan("amazon.com", now.AddHours(-30), 1);
        var pending = MakeScan("microsoft.com", now.AddHours(-1), 1);
        pending.Status = DomainScanStatus.Pending;

        var service = new ReportService(
            new FakeReportScanStore([included, clean, old, pending]),
            BuildConfig());

        var first = await service.GenerateHighRiskAlertReportAsync();
        var second = await service.GenerateHighRiskAlertReportAsync();

        Assert.Single(first.Items);
        Assert.Equal(included.Id, first.Items[0].ScanId);
        Assert.Equal(first.Items.Select(item => item.ScanId), second.Items.Select(item => item.ScanId));
    }

    [Fact]
    public async Task GenerateHighRiskAlertReport_ReportsTopSignalAndBlocklistMatch()
    {
        var scan = MakeScan(
            "example.com",
            DateTime.UtcNow.AddMinutes(-10),
            2,
            new DomainAnalysisResult
            {
                DiscoveredDomain = "example-login.com",
                IsSuspicious = true,
                TopRiskSignal = "Keyword Abuse",
                TopRiskSignalScore = 12,
                TopRiskSignalDetail = "Phishing keyword detected."
            },
            new DomainAnalysisResult
            {
                DiscoveredDomain = "blocked.example.com",
                IsSuspicious = true,
                TopRiskSignal = "Blocklist Match",
                TopRiskSignalScore = 100,
                TopRiskSignalDetail = "Domain found in OpenPhish feed.",
                IsBlocklistMatch = true,
                BlocklistSource = "OpenPhish"
            });

        var service = new ReportService(new FakeReportScanStore([scan]), BuildConfig());

        var report = await service.GenerateHighRiskAlertReportAsync();
        var item = Assert.Single(report.Items);

        Assert.Equal("Blocklist Match", item.TopSignal);
        Assert.Equal(100, item.TopSignalScore);
        Assert.True(item.HasBlocklistMatch);
        Assert.Equal("OpenPhish", item.BlocklistSource);
    }

    [Fact]
    public void ToCsv_ProducesHeaderAndEscapesSignalDetail()
    {
        var service = new ReportService(
            new FakeReportScanStore(Array.Empty<DomainScan>()),
            BuildConfig());
        var report = new HighRiskAlertReport
        {
            Items = new[]
            {
                new HighRiskAlertReportItem
                {
                    ScanId = Guid.Parse("11111111-1111-1111-1111-111111111111"),
                    ScanTimestampUtc = new DateTime(2026, 5, 13, 12, 0, 0, DateTimeKind.Utc),
                    BaseDomain = "example.com",
                    SuspiciousVariantCount = 1,
                    TopSignal = "Keyword Abuse",
                    TopSignalScore = 12,
                    TopSignalDetail = "Detected login, secure",
                    HasBlocklistMatch = false
                }
            }
        };

        var csv = service.ToCsv(report);

        Assert.Contains("ScanId,ScanTimestampUtc,BaseDomain", csv);
        Assert.Contains("\"Detected login, secure\"", csv);
    }
}
