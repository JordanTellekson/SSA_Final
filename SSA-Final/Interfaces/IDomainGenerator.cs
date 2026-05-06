// Contract for producing typosquatting-like domain variations from a base domain.

namespace SSA_Final.Interfaces
{
    public interface IDomainGenerator
    {
        IEnumerable<string> GenerateVariations(string baseDomain);
    }
}

