// Streams newly observed certificate domains from CertStream and queues suspicious
// candidates for direct analysis. OpenPhish remains the blocklist used by the
// analyzer when each queued domain is scored.

using SSA_Final.Interfaces;
using SSA_Final.Models;
using System.Net;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using System.Threading.Channels;

namespace SSA_Final.Services
{
    public class CertStreamIngestionBackgroundService : BackgroundService
    {
        private static readonly string[] DefaultSuspiciousKeywords =
        [
            "login",
            "secure",
            "verify",
            "account",
            "signin",
            "auth",
            "sso",
            "password",
            "reset",
            "mfa",
            "support",
            "billing",
            "payment",
            "invoice",
            "wallet",
            "confirm",
            "update",
            "recovery",
            "admin",
            "portal",
            "webmail",
            "cloud",
            "download",
            "service"
        ];

        private static readonly string[] DefaultBrandRoots =
        [
            "paypal",
            "microsoft",
            "amazon"
        ];

        private readonly IServiceScopeFactory _scopeFactory;
        private readonly ChannelWriter<Guid> _channelWriter;
        private readonly ILogger<CertStreamIngestionBackgroundService> _logger;
        private readonly IHostApplicationLifetime _appLifetime;
        private readonly Uri _streamUri;
        private readonly TimeSpan _deduplicationWindow;
        private readonly TimeSpan _startupDelay;
        private readonly TimeSpan _reconnectDelay;
        private readonly int _maxQueuedPerMinute;
        private readonly bool _queueOnlySuspiciousCandidates;
        private readonly HashSet<string> _suspiciousKeywords;
        private readonly HashSet<string> _monitoredBrandRoots;

        private DateTime _rateWindowStartedUtc = DateTime.UtcNow;
        private int _queuedThisWindow;

        public CertStreamIngestionBackgroundService(
            IServiceScopeFactory scopeFactory,
            ChannelWriter<Guid> channelWriter,
            ILogger<CertStreamIngestionBackgroundService> logger,
            IConfiguration configuration,
            IHostApplicationLifetime appLifetime)
        {
            _scopeFactory = scopeFactory;
            _channelWriter = channelWriter;
            _logger = logger;
            _appLifetime = appLifetime;

            var streamUrl = configuration["CertStream:Url"] ?? "wss://certstream.calidog.io/";
            _streamUri = Uri.TryCreate(streamUrl, UriKind.Absolute, out var parsedUri)
                ? parsedUri
                : new Uri("wss://certstream.calidog.io/");

            var dedupHours = configuration.GetValue<int>("CertStream:DeduplicationWindowHours");
            _deduplicationWindow = TimeSpan.FromHours(dedupHours > 0 ? dedupHours : 24);

            var startupDelaySecs = configuration.GetValue<int>("CertStream:StartupDelaySeconds");
            _startupDelay = TimeSpan.FromSeconds(startupDelaySecs > 0 ? startupDelaySecs : 15);

            var reconnectDelaySecs = configuration.GetValue<int>("CertStream:ReconnectDelaySeconds");
            _reconnectDelay = TimeSpan.FromSeconds(reconnectDelaySecs > 0 ? reconnectDelaySecs : 30);

            var maxQueuedPerMinute = configuration.GetValue<int>("CertStream:MaxQueuedPerMinute");
            _maxQueuedPerMinute = maxQueuedPerMinute > 0 ? maxQueuedPerMinute : 60;

            _queueOnlySuspiciousCandidates = configuration.GetValue(
                "CertStream:QueueOnlySuspiciousCandidates",
                true);

            _suspiciousKeywords = LoadConfiguredSet(
                configuration,
                "CertStream:SuspiciousKeywords",
                DefaultSuspiciousKeywords);

            var configuredBrandRoots = LoadMonitoredBrandRoots(configuration).ToArray();
            _monitoredBrandRoots = LoadConfiguredSet(
                configuration,
                "CertStream:MonitoredBrandRoots",
                configuredBrandRoots);

            if (_monitoredBrandRoots.Count == 0)
            {
                _monitoredBrandRoots.UnionWith(DefaultBrandRoots);
            }
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation(
                "CertStreamIngestionBackgroundService started. Url={Url}, DeduplicationWindow={Window}, " +
                "StartupDelay={StartupDelay}, ReconnectDelay={ReconnectDelay}, MaxQueuedPerMinute={MaxQueued}, " +
                "QueueOnlySuspiciousCandidates={FilterEnabled}.",
                _streamUri,
                _deduplicationWindow,
                _startupDelay,
                _reconnectDelay,
                _maxQueuedPerMinute,
                _queueOnlySuspiciousCandidates);

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

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await ProcessStreamAsync(stoppingToken);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(
                        ex,
                        "CertStream: stream processing failed; reconnecting after {Delay}.",
                        _reconnectDelay);
                }

                try
                {
                    await Task.Delay(_reconnectDelay, stoppingToken);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }

            _logger.LogInformation("CertStreamIngestionBackgroundService stopped.");
        }

        private async Task ProcessStreamAsync(CancellationToken stoppingToken)
        {
            using var webSocket = new ClientWebSocket();
            await webSocket.ConnectAsync(_streamUri, stoppingToken);

            _logger.LogInformation("CertStream: connected to {Url}.", _streamUri);

            while (webSocket.State == WebSocketState.Open && !stoppingToken.IsCancellationRequested)
            {
                var message = await ReceiveMessageAsync(webSocket, stoppingToken);
                if (message is null)
                {
                    _logger.LogInformation("CertStream: websocket closed by remote endpoint.");
                    return;
                }

                var domains = ExtractDomains(message)
                    .Select(NormalizeDomain)
                    .Where(domain => domain is not null)
                    .Select(domain => domain!)
                    .Distinct(StringComparer.OrdinalIgnoreCase);

                foreach (var domain in domains)
                {
                    if (stoppingToken.IsCancellationRequested)
                    {
                        return;
                    }

                    if (!ShouldQueueForAnalysis(domain))
                    {
                        continue;
                    }

                    await QueueScanAsync(domain, stoppingToken);
                }
            }
        }

        private async Task QueueScanAsync(string domain, CancellationToken stoppingToken)
        {
            using var scope = _scopeFactory.CreateScope();
            var scanStore = scope.ServiceProvider.GetRequiredService<IScanStore>();

            if (await scanStore.WasRecentlyScannedAsync(domain, _deduplicationWindow))
            {
                return;
            }

            if (!TryReserveQueueSlot())
            {
                return;
            }

            var scan = new DomainScan
            {
                BaseDomain = domain,
                CreatedAt = DateTime.UtcNow,
                Status = DomainScanStatus.Pending,
                ScanTrigger = ScanTrigger.CertStream,
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
                    "CertStream: failed to persist scan for '{Domain}' - skipping.",
                    domain);
                return;
            }

            if (!_channelWriter.TryWrite(scan.Id))
            {
                _logger.LogWarning(
                    "CertStream: scan {ScanId} for '{Domain}' could not be queued.",
                    scan.Id,
                    domain);
                return;
            }

            _logger.LogInformation(
                "CertStream: queued scan {ScanId} for '{Domain}'.",
                scan.Id,
                domain);
        }

        private bool TryReserveQueueSlot()
        {
            var now = DateTime.UtcNow;
            if (now - _rateWindowStartedUtc >= TimeSpan.FromMinutes(1))
            {
                _rateWindowStartedUtc = now;
                _queuedThisWindow = 0;
            }

            if (_queuedThisWindow >= _maxQueuedPerMinute)
            {
                return false;
            }

            _queuedThisWindow++;
            return true;
        }

        private bool ShouldQueueForAnalysis(string domain)
        {
            if (!_queueOnlySuspiciousCandidates)
            {
                return true;
            }

            var labels = domain.Split('.', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (labels.Length < 2)
            {
                return false;
            }

            var rootLabel = labels[^2];
            var hasKeyword = ContainsSuspiciousKeyword(labels, rootLabel);
            var hasCloseBrand = _monitoredBrandRoots.Any(brand => HasCloseBrandSignal(rootLabel, brand));
            var hasBrand = hasCloseBrand || _monitoredBrandRoots.Any(brand =>
                domain.Contains(brand, StringComparison.OrdinalIgnoreCase));

            if (hasCloseBrand)
            {
                return true;
            }

            if (hasBrand && hasKeyword)
            {
                return true;
            }

            return hasKeyword && HasSuspiciousStructure(labels, rootLabel);
        }

        private bool ContainsSuspiciousKeyword(IEnumerable<string> labels, string rootLabel)
        {
            var tokens = labels
                .Concat(rootLabel.Split('-', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));

            foreach (var token in tokens)
            {
                foreach (var keyword in _suspiciousKeywords)
                {
                    if (token.Equals(keyword, StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }

                    if (keyword.Length >= 4 && token.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        private static bool HasSuspiciousStructure(IReadOnlyCollection<string> labels, string rootLabel)
        {
            var subdomainCount = Math.Max(labels.Count - 2, 0);
            if (subdomainCount >= 2)
            {
                return true;
            }

            if (rootLabel.Count(ch => ch == '-') >= 2)
            {
                return true;
            }

            var digitRatio = rootLabel.Length == 0
                ? 0
                : rootLabel.Count(char.IsDigit) / (double)rootLabel.Length;

            if (rootLabel.Length >= 8 && digitRatio >= 0.25)
            {
                return true;
            }

            return rootLabel.Length >= 12 && ComputeShannonEntropy(rootLabel) >= 3.5;
        }

        private static bool HasCloseBrandSignal(string rootLabel, string brand)
        {
            if (string.IsNullOrWhiteSpace(rootLabel) || string.IsNullOrWhiteSpace(brand))
            {
                return false;
            }

            var rootTokens = rootLabel.Split('-', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            foreach (var token in rootTokens.Append(rootLabel))
            {
                if (Math.Abs(token.Length - brand.Length) > 1)
                {
                    continue;
                }

                if (CalculateEditDistance(token, brand) <= 1)
                {
                    return true;
                }
            }

            return false;
        }

        private static async Task<string?> ReceiveMessageAsync(
            ClientWebSocket webSocket,
            CancellationToken stoppingToken)
        {
            var buffer = new byte[8192];
            using var message = new MemoryStream();

            WebSocketReceiveResult result;
            do
            {
                result = await webSocket.ReceiveAsync(new ArraySegment<byte>(buffer), stoppingToken);
                if (result.MessageType == WebSocketMessageType.Close)
                {
                    return null;
                }

                message.Write(buffer, 0, result.Count);
            }
            while (!result.EndOfMessage);

            return Encoding.UTF8.GetString(message.ToArray());
        }

        private static IEnumerable<string> ExtractDomains(string json)
        {
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;

            foreach (var domain in ExtractDomainsFromElement(root))
            {
                yield return domain;
            }

            if (root.ValueKind != JsonValueKind.Object)
            {
                yield break;
            }

            if (root.TryGetProperty("data", out var data))
            {
                foreach (var domain in ExtractDomainsFromElement(data))
                {
                    yield return domain;
                }

                if (data.TryGetProperty("leaf_cert", out var leafCert))
                {
                    foreach (var domain in ExtractDomainsFromElement(leafCert))
                    {
                        yield return domain;
                    }
                }
            }
        }

        private static IEnumerable<string> ExtractDomainsFromElement(JsonElement element)
        {
            if (element.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in element.EnumerateArray())
                {
                    if (item.ValueKind == JsonValueKind.String)
                    {
                        var value = item.GetString();
                        if (!string.IsNullOrWhiteSpace(value))
                        {
                            yield return value;
                        }
                    }
                }
            }

            if (element.ValueKind != JsonValueKind.Object)
            {
                yield break;
            }

            foreach (var propertyName in new[] { "domains", "all_domains" })
            {
                if (!element.TryGetProperty(propertyName, out var domains) ||
                    domains.ValueKind != JsonValueKind.Array)
                {
                    continue;
                }

                foreach (var item in domains.EnumerateArray())
                {
                    if (item.ValueKind == JsonValueKind.String)
                    {
                        var value = item.GetString();
                        if (!string.IsNullOrWhiteSpace(value))
                        {
                            yield return value;
                        }
                    }
                }
            }
        }

        private static string? NormalizeDomain(string? raw)
        {
            if (string.IsNullOrWhiteSpace(raw))
            {
                return null;
            }

            var value = raw.Trim().TrimEnd('.').ToLowerInvariant();

            if (Uri.TryCreate(value, UriKind.Absolute, out var parsed))
            {
                value = parsed.Host;
            }

            if (value.StartsWith("*.", StringComparison.Ordinal))
            {
                value = value[2..];
            }

            if (value.StartsWith("www.", StringComparison.Ordinal))
            {
                value = value[4..];
            }

            return IsValidDomain(value) ? value : null;
        }

        private static bool IsValidDomain(string domain)
        {
            if (string.IsNullOrWhiteSpace(domain) ||
                domain.Length > 253 ||
                domain.Contains(' ') ||
                IPAddress.TryParse(domain, out _))
            {
                return false;
            }

            var labels = domain.Split('.', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (labels.Length < 2)
            {
                return false;
            }

            foreach (var label in labels)
            {
                if (label.Length is 0 or > 63 ||
                    label.StartsWith('-') ||
                    label.EndsWith('-'))
                {
                    return false;
                }

                foreach (var ch in label)
                {
                    if (!(char.IsLetterOrDigit(ch) || ch == '-'))
                    {
                        return false;
                    }
                }
            }

            return labels[^1].Length >= 2;
        }

        private static HashSet<string> LoadConfiguredSet(
            IConfiguration configuration,
            string sectionName,
            IReadOnlyCollection<string> fallback)
        {
            var configured = configuration
                .GetSection(sectionName)
                .Get<string[]>();

            var values = configured is { Length: > 0 }
                ? configured
                : fallback;

            return values
                .Where(value => !string.IsNullOrWhiteSpace(value))
                .Select(value => value.Trim().ToLowerInvariant())
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
        }

        private static IEnumerable<string> LoadMonitoredBrandRoots(IConfiguration configuration)
        {
            var domains = configuration
                .GetSection("MonitoredBrands:Domains")
                .Get<string[]>() ?? [];

            foreach (var domain in domains)
            {
                var normalized = NormalizeDomain(domain);
                if (normalized is null)
                {
                    continue;
                }

                var labels = normalized.Split('.', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                if (labels.Length >= 2)
                {
                    yield return labels[^2];
                }
            }
        }

        private static int CalculateEditDistance(string left, string right)
        {
            var distances = new int[left.Length + 1, right.Length + 1];

            for (var i = 0; i <= left.Length; i++)
            {
                distances[i, 0] = i;
            }

            for (var j = 0; j <= right.Length; j++)
            {
                distances[0, j] = j;
            }

            for (var i = 1; i <= left.Length; i++)
            {
                for (var j = 1; j <= right.Length; j++)
                {
                    var cost = left[i - 1] == right[j - 1] ? 0 : 1;

                    distances[i, j] = Math.Min(
                        Math.Min(distances[i - 1, j] + 1, distances[i, j - 1] + 1),
                        distances[i - 1, j - 1] + cost);
                }
            }

            return distances[left.Length, right.Length];
        }

        private static double ComputeShannonEntropy(string value)
        {
            if (string.IsNullOrEmpty(value))
            {
                return 0;
            }

            var frequencies = value
                .GroupBy(ch => ch)
                .Select(group => (double)group.Count() / value.Length);

            var entropy = 0.0;
            foreach (var probability in frequencies)
            {
                entropy -= probability * Math.Log2(probability);
            }

            return entropy;
        }
    }
}
