using SSA_Final.Interfaces;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace SSA_Final.Services
{
    /// <summary>
    /// Connects directly to port 443 via <see cref="SslStream"/> so that the raw
    /// certificate can be inspected even when it is invalid, without the connection
    /// being blocked by normal TLS validation.
    /// </summary>
    public class SslCertificateChecker : ISslCertificateChecker
    {
        private readonly ILogger<SslCertificateChecker> _logger;

        public SslCertificateChecker(ILogger<SslCertificateChecker> logger)
        {
            _logger = logger;
        }

        public async Task<IReadOnlyList<string>> GetSslIndicatorsAsync(
            string domain,
            CancellationToken cancellationToken)
        {
            var indicators = new List<string>();

            try
            {
                using var tcp = new TcpClient();
                await tcp.ConnectAsync(domain, 443, cancellationToken);

                // Accept any certificate so that we can inspect it ourselves rather
                // than letting the runtime reject the connection before we can read it.
                using var ssl = new SslStream(
                        tcp.GetStream(),
                        leaveInnerStreamOpen: false);

                await ssl.AuthenticateAsClientAsync(
                    new SslClientAuthenticationOptions
                    {
                        TargetHost = domain,
                        RemoteCertificateValidationCallback = (_, _, _, _) => true
                    },
                    cancellationToken);

                // Prefer the already-typed X509Certificate2; fall back to raw bytes.
                var cert = ssl.RemoteCertificate as X509Certificate2
                           ?? (ssl.RemoteCertificate is not null
                               ? new X509Certificate2(ssl.RemoteCertificate.GetRawCertData())
                               : null);

                if (cert is null)
                {
                    indicators.Add("SSL certificate could not be retrieved");
                    return indicators;
                }

                // Expired certificate
                if (cert.NotAfter < DateTime.UtcNow)
                    indicators.Add($"SSL certificate expired on {cert.NotAfter:yyyy-MM-dd}");

                // Self-signed certificate (issuer equals subject)
                if (cert.Issuer.Equals(cert.Subject, StringComparison.OrdinalIgnoreCase))
                    indicators.Add("Self-signed SSL certificate detected");

                // Hostname mismatch
                if (!CertMatchesDomain(cert, domain))
                {
                    var cn = cert.GetNameInfo(X509NameType.SimpleName, false);
                    indicators.Add($"SSL certificate hostname mismatch (cert issued for '{cn}')");
                }
            }
            catch (SocketException)
            {
                // Port 443 not open — not itself suspicious; skip SSL indicators.
                _logger.LogInformation(
                    "[SslCertificateChecker] Port 443 not open on {Domain}; SSL check skipped.", domain);
            }
            catch (AuthenticationException ex)
            {
                _logger.LogWarning(ex,
                    "[SslCertificateChecker] SSL handshake failed for {Domain}.", domain);
                indicators.Add("SSL handshake failed — certificate may be invalid");
            }

            return indicators;
        }

        /// <summary>
        /// Returns true when the certificate covers <paramref name="domain"/> via
        /// its Subject Alternative Names or, as a fallback, its Common Name.
        /// </summary>
        private static bool CertMatchesDomain(X509Certificate2 cert, string domain)
        {
            // Check Subject Alternative Names first (RFC 2818 preference).
            var san = cert.Extensions["2.5.29.17"]; // OID for SubjectAltName
            if (san is not null)
            {
                foreach (var entry in san.Format(false).Split(',', StringSplitOptions.TrimEntries))
                {
                    if (!entry.StartsWith("DNS Name=", StringComparison.OrdinalIgnoreCase))
                        continue;

                    var dnsName = entry["DNS Name=".Length..];
                    if (WildcardMatch(dnsName, domain))
                        return true;
                }
            }

            // Fall back to the Common Name.
            var cn = cert.GetNameInfo(X509NameType.SimpleName, false);
            return WildcardMatch(cn, domain);
        }

        private static bool WildcardMatch(string pattern, string host)
        {
            // *.example.com matches sub.example.com but not example.com itself.
            if (pattern.StartsWith("*.", StringComparison.Ordinal))
                return host.EndsWith(pattern[1..], StringComparison.OrdinalIgnoreCase);

            return pattern.Equals(host, StringComparison.OrdinalIgnoreCase);
        }
    }
}