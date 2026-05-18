using System.Net;
using SSA_Final.Interfaces;

namespace SSA_Final.Services
{
    public class SystemDnsResolver : IDnsResolver
    {
        public async Task<bool> HasRecordsAsync(string domain)
        {
            try
            {
                var addresses = await Dns.GetHostAddressesAsync(domain);
                return addresses.Length > 0;
            }
            catch
            {
                return false;
            }
        }
    }
}
