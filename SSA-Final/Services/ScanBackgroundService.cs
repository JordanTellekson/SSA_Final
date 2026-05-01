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
            ILogger<ScanBackgroundService> logger)
        {
            _channelReader = channelReader;
            _scopeFactory = scopeFactory;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("ScanBackgroundService started.");

            // On startup, drain any scans left in Pending state (crash/restart recovery).
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
            await foreach (var scanId in _channelReader.ReadAllAsync(stoppingToken))
            {
                // Fire and forget per scan so concurrent scans do not block each other.
                _ = Task.Run(() => ProcessScanAsync(scanId, stoppingToken), stoppingToken);
            }

            _logger.LogInformation("ScanBackgroundService stopped.");
        }

        private async Task DrainPendingScansAsync(CancellationToken stoppingToken)
        {
            using var scope = _scopeFactory.CreateScope();
            var scanStore = scope.ServiceProvider.GetRequiredService<IScanStore>();
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
                _ = Task.Run(() => ProcessScanAsync(scan.Id, stoppingToken), stoppingToken);
            }
        }

        private async Task ProcessScanAsync(Guid scanId, CancellationToken stoppingToken)
        {
            _logger.LogInformation("Scan {DomainScanId}: picked up by background worker.", scanId);

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
            _logger.LogInformation("Scan {DomainScanId}: status set to InProgress.", scanId);

            try
            {
                var variants = domainGenerator.GenerateVariations(scan.BaseDomain).ToList();
                _logger.LogInformation(
                    "Scan {DomainScanId}: generated {Count} variant(s) for '{Domain}'.",
                    scanId, variants.Count, scan.BaseDomain);

                var analysisResults = new List<DomainAnalysisResult>();

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
                        // All retries exhausted for this variant — log and mark the whole scan failed.
                        _logger.LogError(
                            ex,
                            "Scan {DomainScanId}: variant '{Variant}' failed after all retries.",
                            scanId, variant);
                        throw;
                    }

                    result.DomainScanId = scanId;
                    analysisResults.Add(result);
                }

                scan.Variants = analysisResults;
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
