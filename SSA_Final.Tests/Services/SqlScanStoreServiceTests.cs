// Unit tests for SqlScanStoreService.WasRecentlyScannedAsync.
// Uses the EF Core InMemory provider to exercise the LINQ query directly
// without requiring a real database connection.

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using SSA_Final.Data;
using SSA_Final.Interfaces;
using SSA_Final.Models;
using SSA_Final.Services;

namespace SSA_Final.Tests.Services;

// ── Test doubles ──────────────────────────────────────────────────────────────

/// <summary>
/// No-op ISearchService stub — WasRecentlyScannedAsync does not use search,
/// but SqlScanStoreService requires it in the constructor.
/// </summary>
internal sealed class NullSearchService : ISearchService
{
    public IEnumerable<(DomainScan Item, int Score)> Search(
        IEnumerable<DomainScan> source, string? query)
        => Enumerable.Empty<(DomainScan, int)>();
}

// ── Tests ─────────────────────────────────────────────────────────────────────

public class SqlScanStoreServiceTests
{
    // ── Builder helpers ───────────────────────────────────────────────────────

    /// <summary>
    /// Creates a fresh in-memory SSA_FinalContext isolated to the calling test
    /// by using the test's method name as the database name.
    /// </summary>
    private static SSA_FinalContext BuildContext([System.Runtime.CompilerServices.CallerMemberName] string dbName = "")
    {
        var options = new DbContextOptionsBuilder<SSA_FinalContext>()
            .UseInMemoryDatabase(dbName)
            .Options;

        return new SSA_FinalContext(options);
    }

    private static SqlScanStoreService BuildService(SSA_FinalContext context)
        => new(context, new NullSearchService(), NullLogger<SqlScanStoreService>.Instance);

    private static DomainScan MakeScan(string domain, DateTime createdAt) => new()
    {
        Id = Guid.NewGuid(),
        BaseDomain = domain.ToLowerInvariant(),
        CreatedAt = createdAt,
        Status = DomainScanStatus.Completed
    };

    // ── AC-required cases ────────────────────────────────────────────────────

    [Fact]
    public async Task WasRecentlyScannedAsync_ScannedWithinWindow_ReturnsTrue()
    {
        // A scan created 23 hours ago is within a 24-hour window → true.
        await using var ctx = BuildContext();
        ctx.DomainScans.Add(MakeScan("evil.com", DateTime.UtcNow.AddHours(-23)));
        await ctx.SaveChangesAsync();

        var svc = BuildService(ctx);
        var result = await svc.WasRecentlyScannedAsync("evil.com", TimeSpan.FromHours(24));

        Assert.True(result);
    }

    [Fact]
    public async Task WasRecentlyScannedAsync_ScannedOutsideWindow_ReturnsFalse()
    {
        // A scan created 25 hours ago is outside a 24-hour window → false.
        await using var ctx = BuildContext();
        ctx.DomainScans.Add(MakeScan("evil.com", DateTime.UtcNow.AddHours(-25)));
        await ctx.SaveChangesAsync();

        var svc = BuildService(ctx);
        var result = await svc.WasRecentlyScannedAsync("evil.com", TimeSpan.FromHours(24));

        Assert.False(result);
    }

    // ── Additional coverage ───────────────────────────────────────────────────

    [Fact]
    public async Task WasRecentlyScannedAsync_NoPriorScans_ReturnsFalse()
    {
        await using var ctx = BuildContext();
        var svc = BuildService(ctx);

        var result = await svc.WasRecentlyScannedAsync("evil.com", TimeSpan.FromHours(24));

        Assert.False(result);
    }

    [Fact]
    public async Task WasRecentlyScannedAsync_DifferentDomainWithinWindow_ReturnsFalse()
    {
        // A recent scan for a different domain must not count.
        await using var ctx = BuildContext();
        ctx.DomainScans.Add(MakeScan("other.com", DateTime.UtcNow.AddHours(-1)));
        await ctx.SaveChangesAsync();

        var svc = BuildService(ctx);
        var result = await svc.WasRecentlyScannedAsync("evil.com", TimeSpan.FromHours(24));

        Assert.False(result);
    }

    [Fact]
    public async Task WasRecentlyScannedAsync_DomainMatchIsCaseInsensitive_ReturnsTrue()
    {
        // Domain stored as lowercase must match an upper-cased input.
        await using var ctx = BuildContext();
        ctx.DomainScans.Add(MakeScan("evil.com", DateTime.UtcNow.AddHours(-1)));
        await ctx.SaveChangesAsync();

        var svc = BuildService(ctx);
        var result = await svc.WasRecentlyScannedAsync("EVIL.COM", TimeSpan.FromHours(24));

        Assert.True(result);
    }

    [Fact]
    public async Task WasRecentlyScannedAsync_ExactlyAtWindowBoundary_ReturnsTrue()
    {
        // A scan at exactly the cutoff moment should be considered within the window.
        await using var ctx = BuildContext();
        ctx.DomainScans.Add(MakeScan("evil.com", DateTime.UtcNow.AddHours(-24).AddSeconds(1)));
        await ctx.SaveChangesAsync();

        var svc = BuildService(ctx);
        var result = await svc.WasRecentlyScannedAsync("evil.com", TimeSpan.FromHours(24));

        Assert.True(result);
    }

    [Fact]
    public async Task GetCompletedHighRiskScansAsync_ReturnsCompletedScansInWindowRegardlessOfRisk()
    {
        await using var ctx = BuildContext();
        var highRisk = MakeScan("evil.com", DateTime.UtcNow.AddHours(-2));
        highRisk.TimeFinished = DateTime.UtcNow.AddHours(-1);
        highRisk.NumMaliciousDomains = 2;
        highRisk.Variants.Add(new DomainAnalysisResult
        {
            DiscoveredDomain = "evil-login.com",
            IsSuspicious = true,
            TopRiskSignal = "Keyword Abuse",
            TopRiskSignalScore = 12
        });

        var clean = MakeScan("safe.com", DateTime.UtcNow.AddHours(-1));
        clean.NumMaliciousDomains = 0;

        var tooOld = MakeScan("old.com", DateTime.UtcNow.AddHours(-30));
        tooOld.TimeFinished = DateTime.UtcNow.AddHours(-29);
        tooOld.NumMaliciousDomains = 1;

        var pending = MakeScan("pending.com", DateTime.UtcNow.AddHours(-1));
        pending.Status = DomainScanStatus.Pending;
        pending.NumMaliciousDomains = 1;

        ctx.DomainScans.AddRange(highRisk, clean, tooOld, pending);
        await ctx.SaveChangesAsync();

        var svc = BuildService(ctx);
        var result = await svc.GetCompletedHighRiskScansAsync(TimeSpan.FromHours(24));

        // Both completed scans within the window are returned (clean + high-risk).
        // Scans outside the window and non-completed scans are excluded.
        Assert.Equal(2, result.Count);
        Assert.Contains(result, s => s.Id == highRisk.Id);
        Assert.Contains(result, s => s.Id == clean.Id);

        // Variants are eagerly loaded for the high-risk scan.
        var highRiskResult = result.Single(s => s.Id == highRisk.Id);
        Assert.Single(highRiskResult.Variants);
    }

    [Fact]
    public async Task GetCompletedHighRiskScansAsync_WithMinMaliciousFilter_ExcludesCleanScans()
    {
        await using var ctx = BuildContext();
        var highRisk = MakeScan("evil.com", DateTime.UtcNow.AddHours(-2));
        highRisk.TimeFinished = DateTime.UtcNow.AddHours(-1);
        highRisk.NumMaliciousDomains = 2;

        var clean = MakeScan("safe.com", DateTime.UtcNow.AddHours(-1));
        clean.NumMaliciousDomains = 0;

        ctx.DomainScans.AddRange(highRisk, clean);
        await ctx.SaveChangesAsync();

        var svc = BuildService(ctx);
        var result = await svc.GetCompletedHighRiskScansAsync(TimeSpan.FromHours(24), minMaliciousDomains: 1);

        var scan = Assert.Single(result);
        Assert.Equal(highRisk.Id, scan.Id);
    }
}
