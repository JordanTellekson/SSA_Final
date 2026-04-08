using SSA_Final.Models;

namespace SSA_Final.Interfaces
{
    public interface IDomainAnalyzer
    {
        Task<DomainAnalysisResult> Analyze(string domain);
    }
}