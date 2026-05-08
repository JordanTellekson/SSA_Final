// File: ScanBackgroundService.cs
// Purpose: Defines project behavior and data flow for phishing-domain analysis and reporting.

using Polly;
using Polly.Retry;
using SSA_Final.Interfaces;
using SSA_Final.Models;
using System.Threading.Channels;

namespace SSA_Final.Services
{
    public class ScanBackgroundService : BackgroundService
    {
        private readonly ChannelReader<Guid> _channelReader;
        private readonly IServiceScopeFactory _scopeFactory;
        private readonly ILogger<ScanBackgroundService> _logger;

        // Minimum pause between consecutive variant analyses to avoid hammering external services.
        private readonly int _perVariantDelayMs;

        // Limits how many ProcessScanAsync tasks run concurrently, preventing the thread pool
        // and HTTP connection pool from being exhausted when a large feed batch is queued.
        private readonly SemaphoreSlim _concurrencyLimiter;

        // Retry pipeline: up to 2 retries on HttpRequestException with exponential backoff (2s, 4s).
        private readonly ResiliencePipeline _retryPipeline = new ResiliencePipelineBuilder()
            .AddRetry(new RetryStrategyOptions
            {
                ShouldHandle = new PredicateBuilder().Handle<HttpRequestException>(),
                MaxRetryAttempts = 2,
                DelayGenerator = static args =>
                {
                    var delay = TimeSpan.FromSeconds(Math.Pow(2, args.AttemptNumber + 1));
                    return ValueTask.FromResult<TimeSpan?>(delay);
                },
                OnRetry = static args =>
                {
                    // Logging is done inside ProcessScanAsync with full context; no-op here.
                    return ValueTask.CompletedTask;
                }
            })
            .Build();

        public ScanBackgroundService(
            ChannelReader<Guid> channelReader,
            IServiceScopeFactory scopeFactory,
            ILogger<ScanBackgroundService> logger,
            IConfiguration configuration)
        {
            _channelReader = channelReader;
            _scopeFactory = scopeFactory;
            _logger = logger;
            _perVariantDelayMs = configuration.GetValue<int>("ScanWorker:PerVariantDelayMs", 150);

            var maxConcurrent = configuration.GetValue<int>("ScanWorker:MaxConcurrentScans");
            _concurrencyLimiter = new SemaphoreSlim(maxConcurrent > 0 ? maxConcurrent : 3);
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("ScanBackgroundService started.");

            // On startup, recover any scans left in Pending or InProgress (crash/restart recovery).
            // Wrapped in a try/catch so a transient DB error at startup does not crash the host.
            try
            {
                await DrainPendingScansAsync(stoppingToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "ScanBackgroundService: startup drain failed — pending scan recovery skipped. " +
                    "Ensure migrations have been applied and the database is reachable.");
            }

            // Main loop: process scan IDs as they arrive on the channel.
            // WaitAsync blocks here when all concurrency slots are occupied, providing
            // natural backpressure so the channel queue absorbs the excess rather than
            // spawning unbounded concurrent tasks.
            await foreach (var scanId in _channelReader.ReadAllAsync(stoppingToken))
            {
                await _concurrencyLimiter.WaitAsync(stoppingToken);

                _ = Task.Run(async () =>
                {
                    try
                    {
                        await ProcessScanAsync(scanId, stoppingToken);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(
                            ex,
                            "Scan {DomainScanId}: unhandled exception escaped ProcessScanAsync.",
                            scanId);
                    }
                    finally
                    {
                        _concurrencyLimiter.Release();
                    }
                }, stoppingToken);
            }

            _logger.LogInformation("ScanBackgroundService stopped.");
        }

        private async Task DrainPendingScansAsync(CancellationToken stoppingToken)
        {
            using var scope = _scopeFactory.CreateScope();
            var scanStore = scope.ServiceProvider.GetRequiredService<IScanStore>();

            // Reset any scans left InProgress from a previous run (e.g. crash mid-flight)
            // back to Pending so they are picked up and processed again below.
            var inProgressScans = scanStore.GetInProgressScans();
            if (inProgressScans.Count > 0)
            {
                _logger.LogWarning(
                    "ScanBackgroundService: found {Count} scan(s) stuck in InProgress on startup — resetting to Pending.",
                    inProgressScans.Count);

                foreach (var stuck in inProgressScans)
                {
                    stuck.Status = DomainScanStatus.Pending;
                    scanStore.Update(stuck);
                }
            }

            var pendingScans = scanStore.GetPendingScans();

            if (pendingScans.Count == 0)
            {
                _logger.LogInformation("ScanBackgroundService: no pending scans found on startup.");
                return;
            }

            _logger.LogInformation(
                "ScanBackgroundService: re-queuing {Count} pending scan(s) found on startup.",
                pendingScans.Count);

            foreach (var scan in pendingScans)
            {
                await _concurrencyLimiter.WaitAsync(stoppingToken);

                var scanId = scan.Id;
                _ = Task.Run(async () =>
                {
                    try
                    {
                        await ProcessScanAsync(scanId, stoppingToken);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(
                            ex,
                            "Scan {DomainScanId}: unhandled exception escaped ProcessScanAsync during startup drain.",
                            scanId);
                    }
                    finally
                    {
                        _concurrencyLimiter.Release();
                    }
                }, stoppingToken);
            }
        }

        private async Task ProcessScanAsync(Guid scanId, CancellationToken stoppingToken)
        {
            _logger.LogDebug("Scan {DomainScanId}: picked up by background worker.", scanId);

            using var scope = _scopeFactory.CreateScope();
            var scanStore = scope.ServiceProvider.GetRequiredService<IScanStore>();
            var domainGenerator = scope.ServiceProvider.GetRequiredService<IDomainGenerator>();
            var domainAnalyzer = scope.ServiceProvider.GetRequiredService<IDomainAnalyzer>();

            var scan = scanStore.GetById(scanId);
            if (scan is null)
            {
                _logger.LogWarning("Scan {DomainScanId}: not found in store — skipping.", scanId);
                return;
            }

            // Transition to InProgress.
            scan.Status = DomainScanStatus.InProgress;
            scanStore.Update(scan);
            _logger.LogDebug("Scan {DomainScanId}: status set to InProgress.", scanId);

            try
            {
                List<DomainAnalysisResult> analysisResults;

                if (scan.ScanTrigger == ScanTrigger.Manual)
                {
                    // Manual scans: generate typosquat variants and analyse each one.
                    var variants = domainGenerator.GenerateVariations(scan.BaseDomain).ToList();
                    _logger.LogInformation(
                        "Scan {DomainScanId}: generated {Count} variant(s) for '{Domain}'.",
                        scanId, variants.Count, scan.BaseDomain);

                    analysisResults = new List<DomainAnalysisResult>();

                    foreach (var variant in variants)
                    {
                        stoppingToken.ThrowIfCancellationRequested();

                        DomainAnalysisResult result;
                        try
                        {
                            result = await _retryPipeline.ExecuteAsync(
                                async ct => await domainAnalyzer.Analyze(variant),
                                stoppingToken);
                        }
                        catch (HttpRequestException ex)
                        {
                            // All retries exhausted for this variant — log and skip rather than
                            // failing the entire scan over a single unresolvable domain.
                            _logger.LogWarning(
                                ex,
                                "Scan {DomainScanId}: variant '{Variant}' skipped after all retries exhausted.",
                                scanId, variant);
                            continue;
                        }

                        result.DomainScanId = scanId;
                        analysisResults.Add(result);

                        // Throttle between variant analyses to avoid overwhelming external services.
                        if (_perVariantDelayMs > 0)
                        {
                            await Task.Delay(_perVariantDelayMs, stoppingToken);
                        }
                    }
                }
                else
                {
                    // FeedIngestion / Scheduled: the domain is already a suspected phishing domain
                    // sourced externally — skip variant generation and analyse it directly.
                    _logger.LogDebug(
                        "Scan {DomainScanId}: trigger is {Trigger} — analysing '{Domain}' directly (no variant generation).",
                        scanId, scan.ScanTrigger, scan.BaseDomain);

                    var result = await _retryPipeline.ExecuteAsync(
                        async ct => await domainAnalyzer.Analyze(scan.BaseDomain),
                        stoppingToken);

                    result.DomainScanId = scanId;
                    analysisResults = new List<DomainAnalysisResult> { result };
                }

                scan.Variants = analysisResults;
                scan.VariantCount = analysisResults.Count;
                scan.NumMaliciousDomains = analysisResults.Count(r => r.IsSuspicious);
                scan.TimeFinished = DateTime.UtcNow;
                scan.Status = DomainScanStatus.Completed;
                scanStore.Update(scan);

                _logger.LogInformation(
                    "Scan {DomainScanId}: completed. {VariantCount} variant(s) analysed, {MaliciousCount} suspicious.",
                    scanId, analysisResults.Count, scan.NumMaliciousDomains);
            }
            catch (OperationCanceledException)
            {
                // Reset to Pending on graceful shutdown so DrainPendingScansAsync re-queues
                // this scan when the application next starts up.
                scan.Status = DomainScanStatus.Pending;
                scanStore.Update(scan);
                _logger.LogWarning(
                    "Scan {DomainScanId}: cancelled during processing — reset to Pending for restart recovery.",
                    scanId);
            }
            catch (Exception ex)
            {
                scan.TimeFinished = DateTime.UtcNow;
                scan.Status = DomainScanStatus.Failed;
                scanStore.Update(scan);

                _logger.LogError(ex, "Scan {DomainScanId}: failed.", scanId);
            }
        }
    }
}
