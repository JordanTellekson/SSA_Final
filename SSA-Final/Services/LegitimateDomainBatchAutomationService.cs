using SSA_Final.Models;

namespace SSA_Final.Services
{
    public class LegitimateDomainBatchAutomationService : BackgroundService
    {
        private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(5);

        private readonly IServiceScopeFactory _scopeFactory;
        private readonly ILogger<LegitimateDomainBatchAutomationService> _logger;

        public LegitimateDomainBatchAutomationService(
            IServiceScopeFactory scopeFactory,
            ILogger<LegitimateDomainBatchAutomationService> logger)
        {
            _scopeFactory = scopeFactory;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(PollInterval, stoppingToken);
                    using var scope = _scopeFactory.CreateScope();
                    var queueService = scope.ServiceProvider.GetRequiredService<LegitimateDomainBatchQueueService>();
                    var result = queueService.QueueNextBatchForActiveRun();

                    if (result.Status == LegitimateDomainBatchQueueStatus.Queued)
                    {
                        _logger.LogInformation(
                            "Automatically queued legitimate domain baseline scans {Start}-{End} of {Total}.",
                            result.RangeStart,
                            result.RangeEnd,
                            result.TotalCount);
                    }
                    else if (result.Status == LegitimateDomainBatchQueueStatus.RunComplete)
                    {
                        _logger.LogInformation(
                            "Legitimate domain baseline run completed after queuing {Queued}/{Limit} entries.",
                            result.RunQueuedCount,
                            result.RunLimit);
                    }
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Legitimate domain batch automation failed during this polling cycle.");
                }
            }
        }
    }
}
