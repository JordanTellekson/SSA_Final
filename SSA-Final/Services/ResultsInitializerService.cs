using SSA_Final.Models;
using SSA_Final.Interfaces;

namespace SSA_Final.Services
{
    /// <summary>
    /// This service is meant to be used to initialize 
    /// a data set for the Scan Results page
    /// using the DiscoveredDomain model. 
    /// 
    /// It is a placeholder for the actual transfer
    /// of data from the DomainAnalyzer to the ScanResults.
    /// </summary>
    public class ResultsInitializerService : IResultsInitializer
    {
        public List<DiscoveredDomain> GetInitialResults()
        {
            return new List<DiscoveredDomain>
            {
                new DiscoveredDomain
                {
                    DomainName = "example.com",
                    IsMalicious = false,
                    Reason = "Trusted domain"
                },
                new DiscoveredDomain
                {
                    DomainName = "phishy-site.net",
                    IsMalicious = true,
                    Reason = "Known phishing patterns"
                },
                new DiscoveredDomain
                {
                    DomainName = "weird-domain.xyz",
                    IsMalicious = true,
                    Reason = "Unusual TLD and behavior"
                }
            };
        }
    }
}
