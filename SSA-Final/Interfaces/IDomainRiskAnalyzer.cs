using SSA_Final.Models;

namespace SSA_Final.Interfaces
{
    public interface IDomainRiskAnalyzer
    {
        bool IsKnownActiveDomain(string? domainInput);

        Task<DomainRiskAnalysisResult> AnalyzeDomainRiskAsync(string? domainInput);
    }
}
