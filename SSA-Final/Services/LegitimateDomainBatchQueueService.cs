using SSA_Final.Interfaces;
using SSA_Final.Models;
using System.Threading.Channels;

namespace SSA_Final.Services
{
    public class LegitimateDomainBatchQueueService
    {
        public const int BatchSize = 10;
        public const int RunLimit = 50;

        private readonly IScanStore _scanStore;
        private readonly ChannelWriter<Guid> _channelWriter;
        private readonly ILegitimateDomainBatchService _batchService;
        private readonly ILogger<LegitimateDomainBatchQueueService> _logger;

        public LegitimateDomainBatchQueueService(
            IScanStore scanStore,
            ChannelWriter<Guid> channelWriter,
            ILegitimateDomainBatchService batchService,
            ILogger<LegitimateDomainBatchQueueService> logger)
        {
            _scanStore = scanStore;
            _channelWriter = channelWriter;
            _batchService = batchService;
            _logger = logger;
        }

        public LegitimateDomainBatchProgress GetProgress()
        {
            return _batchService.GetProgress(BatchSize, RunLimit);
        }

        public int GetActiveLegitimateBatchScanCount()
        {
            return _scanStore.GetPendingScans()
                .Concat(_scanStore.GetInProgressScans())
                .Count(scan => scan.ScanTrigger == ScanTrigger.LegitimateBatch);
        }

        public LegitimateDomainBatchQueueResult StartNextRun()
        {
            var activeBatchScans = GetActiveLegitimateBatchScanCount();
            if (activeBatchScans > 0)
            {
                return new LegitimateDomainBatchQueueResult
                {
                    Status = LegitimateDomainBatchQueueStatus.ActiveScansInProgress,
                    ActiveScanCount = activeBatchScans,
                    RunLimit = RunLimit
                };
            }

            var progress = GetProgress();
            if (progress.IsRunActive)
            {
                return QueueNextBatchForActiveRun();
            }

            if (!progress.NextBatch.HasDomains)
            {
                return new LegitimateDomainBatchQueueResult
                {
                    Status = LegitimateDomainBatchQueueStatus.NoDomains,
                    RunLimit = RunLimit,
                    TotalCount = progress.NextBatch.TotalCount
                };
            }

            var reservation = _batchService.StartRun(BatchSize, RunLimit);
            return QueueReservation(reservation);
        }

        public LegitimateDomainBatchQueueResult QueueNextBatchForActiveRun()
        {
            var activeBatchScans = GetActiveLegitimateBatchScanCount();
            if (activeBatchScans > 0)
            {
                return new LegitimateDomainBatchQueueResult
                {
                    Status = LegitimateDomainBatchQueueStatus.ActiveScansInProgress,
                    ActiveScanCount = activeBatchScans,
                    RunLimit = RunLimit
                };
            }

            var progress = GetProgress();
            if (!progress.IsRunActive)
            {
                return new LegitimateDomainBatchQueueResult
                {
                    Status = LegitimateDomainBatchQueueStatus.RunNotActive,
                    RunLimit = RunLimit,
                    TotalCount = progress.NextBatch.TotalCount
                };
            }

            if (progress.RunQueuedCount >= RunLimit || !progress.NextBatch.HasDomains)
            {
                _batchService.CompleteActiveRun();
                return new LegitimateDomainBatchQueueResult
                {
                    Status = LegitimateDomainBatchQueueStatus.RunComplete,
                    RunQueuedCount = progress.RunQueuedCount,
                    RunLimit = RunLimit,
                    TotalCount = progress.NextBatch.TotalCount
                };
            }

            var reservation = _batchService.ReserveNextBatch(BatchSize, RunLimit);
            return QueueReservation(reservation);
        }

        public void ResetProgress()
        {
            _batchService.ResetProgress();
        }

        private LegitimateDomainBatchQueueResult QueueReservation(LegitimateDomainBatchReservation reservation)
        {
            if (reservation.CompletedRun)
            {
                return new LegitimateDomainBatchQueueResult
                {
                    Status = LegitimateDomainBatchQueueStatus.RunComplete,
                    RunQueuedCount = reservation.RunQueuedCount,
                    RunLimit = reservation.RunLimit,
                    TotalCount = reservation.Batch.TotalCount
                };
            }

            if (!reservation.Batch.HasDomains)
            {
                return new LegitimateDomainBatchQueueResult
                {
                    Status = LegitimateDomainBatchQueueStatus.NoDomains,
                    RunQueuedCount = reservation.RunQueuedCount,
                    RunLimit = reservation.RunLimit,
                    TotalCount = reservation.Batch.TotalCount
                };
            }

            var created = 0;
            var submitted = 0;
            foreach (var domain in reservation.Batch.Domains)
            {
                var scan = new DomainScan
                {
                    BaseDomain = domain,
                    CreatedAt = DateTime.UtcNow,
                    Status = DomainScanStatus.Pending,
                    ScanTrigger = ScanTrigger.LegitimateBatch,
                    NumMaliciousDomains = 0
                };

                _scanStore.Add(scan);
                created++;

                if (_channelWriter.TryWrite(scan.Id))
                {
                    submitted++;
                }
                else
                {
                    _logger.LogWarning(
                        "Legitimate domain batch scan {DomainScanId} for '{Domain}' could not be submitted to the channel.",
                        scan.Id,
                        domain);
                }
            }

            var rangeStart = reservation.Batch.StartIndex + 1;
            var rangeEnd = reservation.Batch.StartIndex + created;

            _logger.LogInformation(
                "Queued {Count} legitimate domain baseline scan(s), {Start}-{End} of {Total}. Run progress: {Queued}/{Limit}.",
                created,
                rangeStart,
                rangeEnd,
                reservation.Batch.TotalCount,
                reservation.RunQueuedCount,
                reservation.RunLimit);

            return new LegitimateDomainBatchQueueResult
            {
                Status = LegitimateDomainBatchQueueStatus.Queued,
                CreatedScans = created,
                SubmittedScans = submitted,
                RunQueuedCount = reservation.RunQueuedCount,
                RunLimit = reservation.RunLimit,
                TotalCount = reservation.Batch.TotalCount,
                RangeStart = rangeStart,
                RangeEnd = rangeEnd
            };
        }
    }
}
