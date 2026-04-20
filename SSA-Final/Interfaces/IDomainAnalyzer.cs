using SSA_Final.Models;

namespace SSA_Final.Interfaces
{
    /// <summary>
    /// Analyzes a candidate domain and returns suspiciousness details.
    /// </summary>
    public interface IDomainAnalyzer
    {
        /// <summary>
        /// Runs analysis against a single domain string.
        /// </summary>
        /// <param name="domain">Domain to analyze.</param>
        /// <returns>Structured analysis result for the provided domain.</returns>
        Task<DomainAnalysisResult> Analyze(string domain);
    }
}
