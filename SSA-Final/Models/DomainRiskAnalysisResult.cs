namespace SSA_Final.Models
{
    /// <summary>
    /// Immutable result payload returned by risk analysis endpoints/services.
    /// </summary>
    public class DomainRiskAnalysisResult
    {
        /// <summary>
        /// Creates a full risk-analysis result object.
        /// </summary>
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

        /// <summary>
        /// Normalized input domain used for scoring.
        /// </summary>
        public string InputDomain { get; }

        /// <summary>
        /// Indicates whether the domain was found in the active-domain allow-list.
        /// </summary>
        public bool IsKnownActiveDomain { get; }

        /// <summary>
        /// Indicates whether the input could be parsed as a valid domain.
        /// </summary>
        public bool IsValidDomain { get; }

        /// <summary>
        /// Total score across all signal categories.
        /// </summary>
        public int OverallRiskScore { get; }

        /// <summary>
        /// Typosquatting edit-distance signal score.
        /// </summary>
        public DomainRiskSignalScore TyposquattingEditDistance { get; }

        /// <summary>
        /// Excessive-subdomains signal score.
        /// </summary>
        public DomainRiskSignalScore ExcessiveSubdomains { get; }

        /// <summary>
        /// Hyphen-abuse signal score.
        /// </summary>
        public DomainRiskSignalScore HyphenAbuse { get; }

        /// <summary>
        /// Shannon-entropy signal score.
        /// </summary>
        public DomainRiskSignalScore ShannonEntropy { get; }

        /// <summary>
        /// Returns a sentinel result representing invalid input.
        /// </summary>
        public static DomainRiskAnalysisResult InvalidInput()
        {
            // Keep consumer code simple by returning a fully-shaped object for invalid input.
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

        /// <summary>
        /// Returns a zero-risk result for domains that are explicitly allow-listed.
        /// </summary>
        /// <param name="domain">Known active domain.</param>
        /// <returns>Risk result with all signal scores set to zero.</returns>
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
}
