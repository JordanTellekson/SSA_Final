using System.Net;
using System.Text.Json;
using SSA_Final.Interfaces;
using SSA_Final.Models;

namespace SSA_Final.Services
{
    public class LegitimateDomainBatchService : ILegitimateDomainBatchService
    {
        private const string LegitimateDomainsFileName = "Legitimate_Domains.txt";
        private const string StateDirectoryName = "App_Data";
        private const string StateFileName = "legitimate-domain-batch-state.json";
        private static readonly Lock StateLock = new();
        private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
        {
            WriteIndented = true
        };

        private readonly IWebHostEnvironment _hostEnvironment;
        private readonly ILogger<LegitimateDomainBatchService> _logger;

        public LegitimateDomainBatchService(
            IWebHostEnvironment hostEnvironment,
            ILogger<LegitimateDomainBatchService> logger)
        {
            _hostEnvironment = hostEnvironment;
            _logger = logger;
        }

        public LegitimateDomainBatch GetBatch(int startIndex, int batchSize)
        {
            var domains = LoadDomains();
            var safeBatchSize = Math.Clamp(batchSize, 1, 100);
            var safeStartIndex = Math.Clamp(startIndex, 0, domains.Count);
            var batchDomains = domains
                .Skip(safeStartIndex)
                .Take(safeBatchSize)
                .ToList();

            return new LegitimateDomainBatch
            {
                StartIndex = safeStartIndex,
                NextStartIndex = Math.Min(safeStartIndex + batchDomains.Count, domains.Count),
                TotalCount = domains.Count,
                BatchSize = safeBatchSize,
                Domains = batchDomains
            };
        }

        public LegitimateDomainBatchProgress GetProgress(int batchSize, int runLimit)
        {
            lock (StateLock)
            {
                var state = ReadState();
                var domains = LoadDomains();
                NormalizeState(state, domains.Count, runLimit);

                var nextBatch = state.IsRunActive && state.RunQueuedCount >= runLimit
                    ? BuildEmptyBatch(domains, state.NextStartIndex, batchSize)
                    : BuildBatch(domains, state.NextStartIndex, GetNextBatchSize(state, batchSize, runLimit));
                return BuildProgress(state, nextBatch, runLimit);
            }
        }

        public LegitimateDomainBatchReservation StartRun(int batchSize, int runLimit)
        {
            lock (StateLock)
            {
                var state = ReadState();
                var domains = LoadDomains();
                NormalizeState(state, domains.Count, runLimit);

                if (state.IsRunActive)
                {
                    return BuildReservation(state, new LegitimateDomainBatch(), runLimit);
                }

                state.IsRunActive = true;
                state.RunStartIndex = state.NextStartIndex;
                state.RunQueuedCount = 0;
                state.UpdatedAtUtc = DateTime.UtcNow;

                return ReserveNextBatch(state, domains, batchSize, runLimit, startedRun: true);
            }
        }

        public LegitimateDomainBatchReservation ReserveNextBatch(int batchSize, int runLimit)
        {
            lock (StateLock)
            {
                var state = ReadState();
                var domains = LoadDomains();
                NormalizeState(state, domains.Count, runLimit);

                if (!state.IsRunActive)
                {
                    return BuildReservation(state, new LegitimateDomainBatch(), runLimit);
                }

                return ReserveNextBatch(state, domains, batchSize, runLimit, startedRun: false);
            }
        }

        public void CompleteActiveRun()
        {
            lock (StateLock)
            {
                var state = ReadState();
                if (!state.IsRunActive)
                {
                    return;
                }

                state.IsRunActive = false;
                state.RunStartIndex = state.NextStartIndex;
                state.RunQueuedCount = 0;
                state.UpdatedAtUtc = DateTime.UtcNow;
                WriteState(state);
            }
        }

        public void ResetProgress()
        {
            lock (StateLock)
            {
                WriteState(new LegitimateDomainBatchState
                {
                    NextStartIndex = 0,
                    RunStartIndex = 0,
                    RunQueuedCount = 0,
                    IsRunActive = false,
                    UpdatedAtUtc = DateTime.UtcNow
                });
            }
        }

        private List<string> LoadDomains()
        {
            var path = Path.Combine(_hostEnvironment.ContentRootPath, LegitimateDomainsFileName);
            if (!File.Exists(path))
            {
                _logger.LogWarning("Legitimate domain batch file not found at path: {Path}", path);
                return new List<string>();
            }

            var domains = new List<string>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var line in File.ReadLines(path))
            {
                var normalized = NormalizeDomain(line);
                if (!string.IsNullOrWhiteSpace(normalized) && seen.Add(normalized))
                {
                    domains.Add(normalized);
                }
            }

            return domains;
        }

        private LegitimateDomainBatchReservation ReserveNextBatch(
            LegitimateDomainBatchState state,
            IReadOnlyList<string> domains,
            int batchSize,
            int runLimit,
            bool startedRun)
        {
            var remainingInRun = Math.Max(0, runLimit - state.RunQueuedCount);
            if (remainingInRun == 0 || state.NextStartIndex >= domains.Count)
            {
                state.IsRunActive = false;
                state.RunStartIndex = state.NextStartIndex;
                state.RunQueuedCount = 0;
                state.UpdatedAtUtc = DateTime.UtcNow;
                WriteState(state);

                return new LegitimateDomainBatchReservation
                {
                    Batch = BuildEmptyBatch(domains, state.NextStartIndex, batchSize),
                    CompletedRun = true,
                    RunStartIndex = state.RunStartIndex,
                    RunQueuedCount = state.RunQueuedCount,
                    RunLimit = runLimit
                };
            }

            var effectiveBatchSize = Math.Min(Math.Clamp(batchSize, 1, 100), remainingInRun);
            var batch = BuildBatch(domains, state.NextStartIndex, effectiveBatchSize);
            state.NextStartIndex = batch.NextStartIndex;
            state.RunQueuedCount += batch.Domains.Count;
            state.UpdatedAtUtc = DateTime.UtcNow;
            WriteState(state);

            return BuildReservation(state, batch, runLimit, startedRun);
        }

        private LegitimateDomainBatch BuildBatch(IReadOnlyList<string> domains, int startIndex, int batchSize)
        {
            var safeBatchSize = Math.Clamp(batchSize, 1, 100);
            var safeStartIndex = Math.Clamp(startIndex, 0, domains.Count);
            var batchDomains = domains
                .Skip(safeStartIndex)
                .Take(safeBatchSize)
                .ToList();

            return new LegitimateDomainBatch
            {
                StartIndex = safeStartIndex,
                NextStartIndex = Math.Min(safeStartIndex + batchDomains.Count, domains.Count),
                TotalCount = domains.Count,
                BatchSize = safeBatchSize,
                Domains = batchDomains
            };
        }

        private static LegitimateDomainBatchProgress BuildProgress(
            LegitimateDomainBatchState state,
            LegitimateDomainBatch nextBatch,
            int runLimit)
        {
            return new LegitimateDomainBatchProgress
            {
                NextStartIndex = state.NextStartIndex,
                RunStartIndex = state.IsRunActive ? state.RunStartIndex : state.NextStartIndex,
                RunQueuedCount = state.IsRunActive ? state.RunQueuedCount : 0,
                RunLimit = runLimit,
                IsRunActive = state.IsRunActive,
                UpdatedAtUtc = state.UpdatedAtUtc,
                NextBatch = nextBatch
            };
        }

        private static LegitimateDomainBatchReservation BuildReservation(
            LegitimateDomainBatchState state,
            LegitimateDomainBatch batch,
            int runLimit,
            bool startedRun = false)
        {
            return new LegitimateDomainBatchReservation
            {
                Batch = batch,
                IsRunActive = state.IsRunActive,
                StartedRun = startedRun,
                RunStartIndex = state.RunStartIndex,
                RunQueuedCount = state.RunQueuedCount,
                RunLimit = runLimit
            };
        }

        private static LegitimateDomainBatch BuildEmptyBatch(
            IReadOnlyList<string> domains,
            int startIndex,
            int batchSize)
        {
            var safeStartIndex = Math.Clamp(startIndex, 0, domains.Count);
            return new LegitimateDomainBatch
            {
                StartIndex = safeStartIndex,
                NextStartIndex = safeStartIndex,
                TotalCount = domains.Count,
                BatchSize = Math.Clamp(batchSize, 1, 100)
            };
        }

        private static int GetNextBatchSize(LegitimateDomainBatchState state, int batchSize, int runLimit)
        {
            if (!state.IsRunActive)
            {
                return batchSize;
            }

            var remainingInRun = Math.Max(0, runLimit - state.RunQueuedCount);
            return Math.Max(1, Math.Min(batchSize, remainingInRun));
        }

        private static void NormalizeState(
            LegitimateDomainBatchState state,
            int totalDomains,
            int runLimit)
        {
            state.NextStartIndex = Math.Clamp(state.NextStartIndex, 0, totalDomains);
            state.RunStartIndex = Math.Clamp(state.RunStartIndex, 0, totalDomains);
            state.RunQueuedCount = Math.Clamp(state.RunQueuedCount, 0, runLimit);

            if (!state.IsRunActive)
            {
                state.RunStartIndex = state.NextStartIndex;
                state.RunQueuedCount = 0;
            }
        }

        private LegitimateDomainBatchState ReadState()
        {
            var path = GetStatePath();
            if (!File.Exists(path))
            {
                return new LegitimateDomainBatchState();
            }

            try
            {
                var json = File.ReadAllText(path);
                return JsonSerializer.Deserialize<LegitimateDomainBatchState>(json, JsonOptions)
                    ?? new LegitimateDomainBatchState();
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Could not read legitimate domain batch state. Starting from the first domain.");
                return new LegitimateDomainBatchState();
            }
        }

        private void WriteState(LegitimateDomainBatchState state)
        {
            var path = GetStatePath();
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, JsonSerializer.Serialize(state, JsonOptions));
        }

        private string GetStatePath()
        {
            return Path.Combine(_hostEnvironment.ContentRootPath, StateDirectoryName, StateFileName);
        }

        private static string? NormalizeDomain(string? rawDomain)
        {
            if (string.IsNullOrWhiteSpace(rawDomain))
            {
                return null;
            }

            var value = rawDomain.Trim();
            if (value.StartsWith('#'))
            {
                return null;
            }

            if (!value.Contains("://", StringComparison.Ordinal))
            {
                value = "http://" + value;
            }

            if (!Uri.TryCreate(value, UriKind.Absolute, out var uri))
            {
                return null;
            }

            var host = uri.Host.Trim().TrimEnd('.');
            if (host.StartsWith("www.", StringComparison.OrdinalIgnoreCase))
            {
                host = host[4..];
            }

            if (IPAddress.TryParse(host, out _))
            {
                return null;
            }

            return string.IsNullOrWhiteSpace(host) ? null : host.ToLowerInvariant();
        }

        private sealed class LegitimateDomainBatchState
        {
            public int NextStartIndex { get; set; }
            public int RunStartIndex { get; set; }
            public int RunQueuedCount { get; set; }
            public bool IsRunActive { get; set; }
            public DateTime UpdatedAtUtc { get; set; } = DateTime.UtcNow;
        }
    }
}
