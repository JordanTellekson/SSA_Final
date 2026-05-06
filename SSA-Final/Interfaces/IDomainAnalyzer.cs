// Contract for asynchronous phishing/suspicion analysis of a single domain.

using SSA_Final.Models;

namespace SSA_Final.Interfaces
{
    public interface IDomainAnalyzer
    {
        Task<DomainAnalysisResult> Analyze(string domain);

        bool IsKnownActiveDomain(string? domainInput);

        Task<DomainAnalysisResult> AnalyzeDomainRiskAsync(string? domainInput);
    }
}

