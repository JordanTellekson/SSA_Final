namespace SSA_Final.Interfaces
{
    /// <summary>
    /// Inspects the SSL/TLS certificate of a domain and returns a list of
    /// human-readable indicator strings for any problems found.
    /// </summary>
    public interface ISslCertificateChecker
    {
        /// <summary>
        /// Connects to <paramref name="domain"/> on port 443 and evaluates the
        /// server certificate for expiry, self-signing, and hostname mismatch.
        /// Returns an empty list when the certificate is valid.
        /// </summary>
        Task<IReadOnlyList<string>> GetSslIndicatorsAsync(
            string domain,
            CancellationToken cancellationToken);
    }
}