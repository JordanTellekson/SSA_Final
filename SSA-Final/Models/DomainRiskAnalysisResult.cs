namespace SSA_Final.Models
{
    // Immutable payload returned by the model's phishing-risk analysis.
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
            DomainRiskSignalScore shannonEntropy)
        {
            InputDomain = inputDomain;
            IsKnownActiveDomain = isKnownActiveDomain;
            IsValidDomain = isValidDomain;
            OverallRiskScore = overallRiskScore;
            TyposquattingEditDistance = typosquattingEditDistance;
            ExcessiveSubdomains = excessiveSubdomains;
            HyphenAbuse = hyphenAbuse;
            ShannonEntropy = shannonEntropy;
        }

        public string InputDomain { get; }

        public bool IsKnownActiveDomain { get; }

        public bool IsValidDomain { get; }

        public int OverallRiskScore { get; }

        public DomainRiskSignalScore TyposquattingEditDistance { get; }

        public DomainRiskSignalScore ExcessiveSubdomains { get; }

        public DomainRiskSignalScore HyphenAbuse { get; }

        public DomainRiskSignalScore ShannonEntropy { get; }

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
                shannonEntropy: emptySignal);
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
                shannonEntropy: noRisk);
        }
    }

    // Individual risk-signal score (one of the four checks) with context details.
    public class DomainRiskSignalScore
    {
        public DomainRiskSignalScore(string signal, int score, bool triggered, string detail)
        {
            Signal = signal;
            Score = score;
            Triggered = triggered;
            Detail = detail;
        }

        public string Signal { get; }

        public int Score { get; }

        public bool Triggered { get; }

        public string Detail { get; }
    }
}
