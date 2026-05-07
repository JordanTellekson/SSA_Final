// Abstraction for external domain feed sources used as scan targets.
// Implementations fetch a list of suspected phishing hostnames from a remote feed.
// Consumers (e.g. FeedIngestionBackgroundService) inject IEnumerable<IDomainFeedSource>
// to enumerate all registered sources without knowing their concrete types.

namespace SSA_Final.Interfaces
{
    public interface IDomainFeedSource
    {
        /// <summary>
        /// Human-readable name for this feed source, used in logging and diagnostics.
        /// </summary>
        string Name { get; }

        /// <summary>
        /// Fetches the current list of suspected phishing hostnames from the feed.
        /// Implementations must handle fetch failures gracefully and return an empty
        /// enumerable rather than propagating exceptions.
        /// </summary>
        Task<IEnumerable<string>> FetchDomainsAsync(CancellationToken ct);
    }
}
