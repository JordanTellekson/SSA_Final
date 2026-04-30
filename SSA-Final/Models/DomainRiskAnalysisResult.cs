// Immutable response model containing risk score signals for a domain.

namespace SSA_Final.Models
{
    // Immutable payload returned by phishing-risk analysis.
    public class DomainRiskAnalysisResult
    {
        public DomainRiskAnalysisResult(
            string inputDomain,
            bool isKnownActiveDomain,
            bool isValidDomain,
            int overallRiskScore,
            DomainRiskSignalScore typosquattingEditDistance,
            DomainRiskSignalScore excessiveSubdomains,
            DomainRiskSignalScore hyphenAbuse,
            DomainRiskSignalScore shannonEntropy,
            bool isBlocklistMatch = false,
            string? blocklistSource = null,
            bool usedBlocklistFallback = false)
        {
            InputDomain = inputDomain;
            IsKnownActiveDomain = isKnownActiveDomain;
            IsValidDomain = isValidDomain;
            OverallRiskScore = overallRiskScore;
            TyposquattingEditDistance = typosquattingEditDistance;
            ExcessiveSubdomains = excessiveSubdomains;
            HyphenAbuse = hyphenAbuse;
            ShannonEntropy = shannonEntropy;
            IsBlocklistMatch = isBlocklistMatch;
            BlocklistSource = blocklistSource;
            UsedBlocklistFallback = usedBlocklistFallback;
        }

        public string InputDomain { get; }

        public bool IsKnownActiveDomain { get; }

        public bool IsValidDomain { get; }

        public int OverallRiskScore { get; }

        public DomainRiskSignalScore TyposquattingEditDistance { get; }

        public DomainRiskSignalScore ExcessiveSubdomains { get; }

        public DomainRiskSignalScore HyphenAbuse { get; }

        public DomainRiskSignalScore ShannonEntropy { get; }

        // Extension properties to help connect to the PhishingBlocklistService
        public bool IsBlocklistMatch { get; }

        public string? BlocklistSource { get; }

        public bool UsedBlocklistFallback { get; }

        public static DomainRiskAnalysisResult InvalidInput()
        {
            // Keeps consumer code simple by returning a fully-shaped object for invalid input.
            var emptySignal = new DomainRiskSignalScore("N/A", 0, false, "Invalid input.");
            return new DomainRiskAnalysisResult(
                inputDomain: string.Empty,
                isKnownActiveDomain: false,
                isValidDomain: false,
                overallRiskScore: 0,
                typosquattingEditDistance: emptySignal,
                excessiveSubdomains: emptySignal,
                hyphenAbuse: emptySignal,
                shannonEntropy: emptySignal,
                isBlocklistMatch: false);
        }

        public static DomainRiskAnalysisResult ForKnownActiveDomain(string domain)
        {
            // Active-domain matches short-circuit risk scoring by design.
            var noRisk = new DomainRiskSignalScore("N/A", 0, false, "Domain is already in Active_Domains.txt.");
            return new DomainRiskAnalysisResult(
                inputDomain: domain,
                isKnownActiveDomain: true,
                isValidDomain: true,
                overallRiskScore: 0,
                typosquattingEditDistance: noRisk,
                excessiveSubdomains: noRisk,
                hyphenAbuse: noRisk,
                shannonEntropy: noRisk,
                isBlocklistMatch: false);
        }
    }
}


