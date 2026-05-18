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

    public Task<IReadOnlyList<DomainScan>> GetCompletedHighRiskScansAsync(TimeSpan lookbackWindow, int minMaliciousDomains = 0)
    {
        var cutoff = DateTime.UtcNow - lookbackWindow;
        var scans = _scans
            .Where(scan =>
                scan.Status == DomainScanStatus.Completed &&
                scan.NumMaliciousDomains >= minMaliciousDomains &&
                (scan.TimeFinished ?? scan.CreatedAt) >= cutoff)
            .ToList();

        return Task.FromResult<IReadOnlyList<DomainScan>>(scans);
    }

    public Task<ScanStats> GetScanStatsAsync(CancellationToken ct = default)
    {
        throw new NotSupportedException();
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

    public Task<IReadOnlyList<DomainAnalysisReportItem>> GetAnalyzedDomainReportItemsAsync(
        DateTime startUtc,
        DateTime endUtc,
        bool suspiciousOnly = false)
    {
        var items = _scans
            .SelectMany(scan => scan.Variants.Select(variant => new { scan, variant }))
            .Where(row =>
                row.variant.AnalysedAt >= startUtc &&
                row.variant.AnalysedAt <= endUtc &&
                (!suspiciousOnly || row.variant.IsSuspicious))
            .OrderByDescending(row => row.variant.AnalysedAt)
            .ThenBy(row => row.variant.DiscoveredDomain, StringComparer.OrdinalIgnoreCase)
            .Select(row => new DomainAnalysisReportItem
            {
                ScanId = row.scan.Id,
                BaseDomain = row.scan.BaseDomain,
                ScanStatus = row.scan.Status,
                ScanTrigger = row.scan.ScanTrigger,
                DiscoveredDomain = row.variant.DiscoveredDomain,
                IsSuspicious = row.variant.IsSuspicious,
                RiskClassification = row.variant.RiskClassification,
                OverallRiskScore = row.variant.OverallRiskScore,
                Summary = row.variant.Summary,
                Indicators = row.variant.Indicators.ToList(),
                AnalysedAtUtc = row.variant.AnalysedAt
            })
            .ToList();

        return Task.FromResult<IReadOnlyList<DomainAnalysisReportItem>>(items);
    }

    public Task<bool> WasRecentlyScannedAsync(string domain, TimeSpan window)
    {
        throw new NotSupportedException();
    }

    public Task<IReadOnlyList<DomainScan>> GetRecentHighRiskAsync(DateTime since, int minSuspiciousVariants)
    {
        var scans = _scans
            .Where(scan =>
                scan.Status == DomainScanStatus.Completed &&
                (scan.TimeFinished ?? scan.CreatedAt) >= since &&
                scan.NumMaliciousDomains >= minSuspiciousVariants)
            .ToList();

        return Task.FromResult<IReadOnlyList<DomainScan>>(scans);
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
    public async Task GenerateHighRiskAlertReport_FiltersToCompletedScansInWindowRegardlessOfRisk()
    {
        var now = DateTime.UtcNow;
        var highRisk = MakeScan(
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
        var tooOld = MakeScan("amazon.com", now.AddHours(-30), 1);
        var pending = MakeScan("microsoft.com", now.AddHours(-1), 1);
        pending.Status = DomainScanStatus.Pending;

        var service = new ReportService(
            new FakeReportScanStore([highRisk, clean, tooOld, pending]),
            BuildConfig());

        var first = await service.GenerateHighRiskAlertReportAsync();
        var second = await service.GenerateHighRiskAlertReportAsync();

        // Both completed scans within the window are included (clean + high-risk).
        // Scans outside the window and non-completed scans are excluded.
        Assert.Equal(2, first.Items.Count);
        Assert.Contains(first.Items, item => item.ScanId == highRisk.Id);
        Assert.Contains(first.Items, item => item.ScanId == clean.Id);
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

    [Fact]
    public async Task GenerateDomainAnalysisReport_ReturnsAnalyzedDomainsInWindow()
    {
        var now = DateTime.UtcNow;
        var scan = MakeScan(
            "example.com",
            now.AddMinutes(-10),
            1,
            new DomainAnalysisResult
            {
                DiscoveredDomain = "example.com",
                IsSuspicious = false,
                RiskClassification = "Low",
                OverallRiskScore = 0,
                Summary = "No issues detected.",
                AnalysedAt = now.AddHours(-1),
                Indicators = new List<string>()
            },
            new DomainAnalysisResult
            {
                DiscoveredDomain = "example-login.com",
                IsSuspicious = true,
                RiskClassification = "High",
                OverallRiskScore = 65,
                Summary = "Domain flagged with indicators.",
                AnalysedAt = now.AddMinutes(-30),
                Indicators = new List<string> { "Keyword Abuse: login" }
            },
            new DomainAnalysisResult
            {
                DiscoveredDomain = "old.example.com",
                IsSuspicious = true,
                RiskClassification = "Critical",
                OverallRiskScore = 100,
                Summary = "Too old for the requested window.",
                AnalysedAt = now.AddHours(-30),
                Indicators = new List<string> { "Blocklist Match" }
            });

        var service = new ReportService(new FakeReportScanStore([scan]), BuildConfig());

        var report = await service.GenerateDomainAnalysisReportAsync(
            lookbackWindow: TimeSpan.FromHours(24),
            endUtc: now);

        Assert.False(report.SuspiciousOnly);
        Assert.Equal(2, report.Items.Count);
        Assert.Contains(report.Items, item => item.DiscoveredDomain == "example.com");
        Assert.Contains(report.Items, item => item.DiscoveredDomain == "example-login.com");
        Assert.DoesNotContain(report.Items, item => item.DiscoveredDomain == "old.example.com");
    }

    [Fact]
    public async Task GenerateDomainAnalysisReport_WithSuspiciousOnly_ReturnsOnlySuspiciousDomains()
    {
        var now = DateTime.UtcNow;
        var scan = MakeScan(
            "example.com",
            now.AddMinutes(-10),
            1,
            new DomainAnalysisResult
            {
                DiscoveredDomain = "example.com",
                IsSuspicious = false,
                RiskClassification = "Low",
                Summary = "No issues detected.",
                AnalysedAt = now.AddMinutes(-20)
            },
            new DomainAnalysisResult
            {
                DiscoveredDomain = "example-login.com",
                IsSuspicious = true,
                RiskClassification = "High",
                Summary = "Domain flagged with indicators.",
                AnalysedAt = now.AddMinutes(-10)
            });

        var service = new ReportService(new FakeReportScanStore([scan]), BuildConfig());

        var report = await service.GenerateDomainAnalysisReportAsync(
            lookbackWindow: TimeSpan.FromHours(24),
            suspiciousOnly: true,
            endUtc: now);

        var item = Assert.Single(report.Items);
        Assert.True(report.SuspiciousOnly);
        Assert.Equal("example-login.com", item.DiscoveredDomain);
    }

    [Fact]
    public void ToCsv_DomainAnalysisReport_IncludesRequestedColumnsAndEscapesIndicators()
    {
        var service = new ReportService(
            new FakeReportScanStore(Array.Empty<DomainScan>()),
            BuildConfig());
        var report = new DomainAnalysisReport
        {
            Items = new[]
            {
                new DomainAnalysisReportItem
                {
                    ScanId = Guid.Parse("22222222-2222-2222-2222-222222222222"),
                    BaseDomain = "example.com",
                    DiscoveredDomain = "example-login.com",
                    IsSuspicious = true,
                    RiskClassification = "High",
                    OverallRiskScore = 65,
                    Summary = "Domain flagged, check details.",
                    Indicators = new[] { "Keyword Abuse: login", "No DNS records found, skipped network checks" },
                    AnalysedAtUtc = new DateTime(2026, 5, 18, 12, 0, 0, DateTimeKind.Utc),
                    ScanStatus = DomainScanStatus.Completed,
                    ScanTrigger = ScanTrigger.Manual
                }
            }
        };

        var csv = service.ToCsv(report);

        Assert.Contains("ScanId,BaseDomain,DiscoveredDomain,Status,Classification,OverallRiskScore,Summary,Indicators,AnalysedAtUtc,ScanStatus,ScanTrigger", csv);
        Assert.Contains("Suspicious,High,65", csv);
        Assert.Contains("\"Domain flagged, check details.\"", csv);
        Assert.Contains("\"Keyword Abuse: login; No DNS records found, skipped network checks\"", csv);
    }
}
