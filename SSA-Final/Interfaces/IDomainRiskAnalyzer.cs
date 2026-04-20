using SSA_Final.Models;

namespace SSA_Final.Interfaces
{
    /// <summary>
    /// Scores a domain for phishing/typosquatting risk signals.
    /// </summary>
    public interface IDomainRiskAnalyzer
    {
        /// <summary>
        /// Checks whether the supplied domain is present in the active-domain allow-list.
        /// </summary>
        /// <param name="domainInput">Raw domain input from user or API caller.</param>
        /// <returns><c>true</c> when the domain is known active; otherwise <c>false</c>.</returns>
        bool IsKnownActiveDomain(string? domainInput);

        /// <summary>
        /// Calculates a detailed risk result for the supplied domain.
        /// </summary>
        /// <param name="domainInput">Raw domain input from user or API caller.</param>
        /// <returns>Aggregated risk analysis output.</returns>
        DomainRiskAnalysisResult AnalyzeDomainRisk(string? domainInput);
    }
}
