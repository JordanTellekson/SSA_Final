using SSA_Final.Models;

namespace SSA_Final.Interfaces
{
    public interface IDomainRiskAnalyzer
    {
        bool IsKnownActiveDomain(string? domainInput);

        DomainRiskAnalysisResult AnalyzeDomainRisk(string? domainInput);
    }
}
