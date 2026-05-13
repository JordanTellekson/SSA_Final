// Periodically queues full typosquat scans for configured brand domains.
// Uses the existing scan channel so scheduled scans flow through the normal worker.

using SSA_Final.Interfaces;
using SSA_Final.Models;
using System.Diagnostics;
using System.Threading.Channels;
using Microsoft.Extensions.Configuration;

namespace SSA_Final.Services
{
    public class ScheduledScanBackgroundService : BackgroundService
    {
        private readonly IServiceScopeFactory _scopeFactory;
        private readonly ChannelWriter<Guid> _channelWriter;
        private readonly ILogger<ScheduledScanBackgroundService> _logger;
        private readonly IHostApplicationLifetime _appLifetime;
        private readonly IReadOnlyList<string> _monitoredDomains;
        private readonly TimeSpan _scanInterval;
        private readonly TimeSpan _startupDelay;

        public ScheduledScanBackgroundService(
            IServiceScopeFactory scopeFactory,
            ChannelWriter<Guid> channelWriter,
            ILogger<ScheduledScanBackgroundService> logger,
            IConfiguration configuration,
            IHostApplicationLifetime appLifetime)
        {
            _scopeFactory = scopeFactory;
            _channelWriter = channelWriter;
            _logger = logger;
            _appLifetime = appLifetime;

            _monitoredDomains = configuration
                .GetSection("MonitoredBrands:Domains")
                .Get<string[]>()?
                .Select(domain => domain.Trim().ToLowerInvariant())
                .Where(domain => !string.IsNullOrWhiteSpace(domain))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray()
                ?? Array.Empty<string>();

            var scanIntervalHours = configuration.GetValue<int>("MonitoredBrands:ScanIntervalHours");
            _scanInterval = TimeSpan.FromHours(scanIntervalHours > 0 ? scanIntervalHours : 24);

            var startupDelaySeconds = configuration.GetValue<int>("MonitoredBrands:StartupDelaySeconds");
            _startupDelay = TimeSpan.FromSeconds(startupDelaySeconds > 0 ? startupDelaySeconds : 30);
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation(
                "ScheduledScanBackgroundService started. MonitoredDomains={Count}, ScanInterval={Interval}, StartupDelay={Delay}.",
                _monitoredDomains.Count,
                _scanInterval,
                _startupDelay);

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

            await RunScheduledScanCycleAsync(stoppingToken);

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(_scanInterval, stoppingToken);
                }
                catch (OperationCanceledException)
                {
                    break;
                }

                await RunScheduledScanCycleAsync(stoppingToken);
            }

            _logger.LogInformation("ScheduledScanBackgroundService stopped.");
        }

        private async Task RunScheduledScanCycleAsync(CancellationToken stoppingToken)
        {
            if (_monitoredDomains.Count == 0)
            {
                _logger.LogInformation("ScheduledScan: no monitored brand domains configured.");
                return;
            }

            var sw = Stopwatch.StartNew();
            var queued = 0;
            var skipped = 0;

            using var scope = _scopeFactory.CreateScope();
            var scanStore = scope.ServiceProvider.GetRequiredService<IScanStore>();

            foreach (var domain in _monitoredDomains)
            {
                stoppingToken.ThrowIfCancellationRequested();

                if (await scanStore.WasRecentlyScannedAsync(domain, _scanInterval))
                {
                    skipped++;
                    continue;
                }

                var scan = new DomainScan
                {
                    BaseDomain = domain,
                    CreatedAt = DateTime.UtcNow,
                    Status = DomainScanStatus.Pending,
                    ScanTrigger = ScanTrigger.Scheduled,
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
                        "ScheduledScan: failed to persist scan for '{Domain}' - skipping.",
                        domain);
                    continue;
                }

                if (_channelWriter.TryWrite(scan.Id))
                {
                    queued++;
                }
                else
                {
                    _logger.LogWarning(
                        "ScheduledScan: scan {ScanId} for '{Domain}' could not be queued.",
                        scan.Id,
                        domain);
                }
            }

            sw.Stop();
            _logger.LogInformation(
                "ScheduledScan: cycle complete in {Elapsed}ms. Monitored={Monitored}, Skipped={Skipped}, Queued={Queued}.",
                sw.ElapsedMilliseconds,
                _monitoredDomains.Count,
                skipped,
                queued);
        }
    }
}
