// Periodically pulls domains from all registered IDomainFeedSource implementations
// and queues them for analysis via ScanBackgroundService.
// Runs one cycle immediately on startup, then repeats on a configurable interval.

using SSA_Final.Interfaces;
using SSA_Final.Models;
using System.Diagnostics;
using System.Threading.Channels;

namespace SSA_Final.Services
{
    public class FeedIngestionBackgroundService : BackgroundService
    {
        private readonly IEnumerable<IDomainFeedSource> _feedSources;
        private readonly IServiceScopeFactory _scopeFactory;
        private readonly ChannelWriter<Guid> _channelWriter;
        private readonly ILogger<FeedIngestionBackgroundService> _logger;

        private readonly IHostApplicationLifetime _appLifetime;
        private readonly TimeSpan _pollingInterval;
        private readonly TimeSpan _deduplicationWindow;
        private readonly int _maxDomainsPerCycle;
        private readonly TimeSpan _startupDelay;

        public FeedIngestionBackgroundService(
            IEnumerable<IDomainFeedSource> feedSources,
            IServiceScopeFactory scopeFactory,
            ChannelWriter<Guid> channelWriter,
            ILogger<FeedIngestionBackgroundService> logger,
            IConfiguration configuration,
            IHostApplicationLifetime appLifetime)
        {
            _feedSources = feedSources;
            _scopeFactory = scopeFactory;
            _channelWriter = channelWriter;
            _logger = logger;
            _appLifetime = appLifetime;

            var pollingHours = configuration.GetValue<int>("FeedIngestion:PollingIntervalHours");
            _pollingInterval = TimeSpan.FromHours(pollingHours > 0 ? pollingHours : 6);

            var dedupHours = configuration.GetValue<int>("FeedIngestion:DeduplicationWindowHours");
            _deduplicationWindow = TimeSpan.FromHours(dedupHours > 0 ? dedupHours : 24);

            var maxDomains = configuration.GetValue<int>("FeedIngestion:MaxDomainsPerCycle");
            _maxDomainsPerCycle = maxDomains > 0 ? maxDomains : 500;

            var startupDelaySecs = configuration.GetValue<int>("FeedIngestion:StartupDelaySeconds");
            _startupDelay = TimeSpan.FromSeconds(startupDelaySecs > 0 ? startupDelaySecs : 15);
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation(
                "FeedIngestionBackgroundService started. " +
                "PollingInterval={Interval}, DeduplicationWindow={Window}, MaxDomainsPerCycle={Cap}, StartupDelay={Delay}.",
                _pollingInterval, _deduplicationWindow, _maxDomainsPerCycle, _startupDelay);

            // Wait for the HTTP pipeline to be fully up before the first cycle fires.
            // This prevents the feed from flooding the scan queue before the app is ready.
            var appStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            _appLifetime.ApplicationStarted.Register(() => appStarted.TrySetResult());

            try
            {
                await appStarted.Task.WaitAsync(stoppingToken);
                await Task.Delay(_startupDelay, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                return;
            }

            // Run the first cycle immediately after the startup delay.
            await RunIngestionCycleAsync(stoppingToken);

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(_pollingInterval, stoppingToken);
                }
                catch (OperationCanceledException)
                {
                    // Graceful shutdown — exit the loop cleanly.
                    break;
                }

                await RunIngestionCycleAsync(stoppingToken);
            }

            _logger.LogInformation("FeedIngestionBackgroundService stopped.");
        }

        private async Task RunIngestionCycleAsync(CancellationToken stoppingToken)
        {
            var sw = Stopwatch.StartNew();
            _logger.LogInformation("FeedIngestion: cycle starting.");

            using var scope = _scopeFactory.CreateScope();
            var scanStore = scope.ServiceProvider.GetRequiredService<IScanStore>();

            int totalFetched = 0;
            int totalSkipped = 0;
            int totalQueued = 0;

            foreach (var feedSource in _feedSources)
            {
                if (stoppingToken.IsCancellationRequested)
                    break;

                IEnumerable<string> domains;
                try
                {
                    domains = await feedSource.FetchDomainsAsync(stoppingToken);
                }
                catch (Exception ex)
                {
                    // FetchDomainsAsync implementations should handle their own errors,
                    // but guard here as a safety net so one bad source cannot abort the cycle.
                    _logger.LogWarning(
                        ex,
                        "FeedIngestion: unexpected error fetching from '{FeedSource}' — skipping source.",
                        feedSource.Name);
                    continue;
                }

                var domainList = domains.ToList();
                _logger.LogInformation(
                    "FeedIngestion: '{FeedSource}' returned {Count} domain(s).",
                    feedSource.Name, domainList.Count);

                totalFetched += domainList.Count;

                foreach (var domain in domainList)
                {
                    if (stoppingToken.IsCancellationRequested)
                        break;

                    // Enforce the per-cycle cap across all sources combined.
                    if (totalQueued >= _maxDomainsPerCycle)
                    {
                        _logger.LogInformation(
                            "FeedIngestion: per-cycle cap of {Cap} reached — remaining domains skipped.",
                            _maxDomainsPerCycle);
                        goto CycleComplete;
                    }

                    // Deduplication check — skip domains scanned within the configured window.
                    if (await scanStore.WasRecentlyScannedAsync(domain, _deduplicationWindow))
                    {
                        totalSkipped++;
                        continue;
                    }

                    var scan = new DomainScan
                    {
                        BaseDomain = domain,
                        CreatedAt = DateTime.UtcNow,
                        Status = DomainScanStatus.Pending,
                        ScanTrigger = ScanTrigger.FeedIngestion,
                        NumMaliciousDomains = 0
                    };

                    try
                    {
                        scanStore.Add(scan);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(
                            ex,
                            "FeedIngestion: failed to persist scan for '{Domain}' — skipping.",
                            domain);
                        continue;
                    }

                    _channelWriter.TryWrite(scan.Id);
                    totalQueued++;
                }
            }

            CycleComplete:
            sw.Stop();
            _logger.LogInformation(
                "FeedIngestion: cycle complete in {Elapsed}ms. " +
                "Fetched={Fetched}, Skipped={Skipped}, Queued={Queued}.",
                sw.ElapsedMilliseconds, totalFetched, totalSkipped, totalQueued);
        }
    }
}
