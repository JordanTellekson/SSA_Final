namespace SSA_Final.Interfaces
{
    public interface IDomainGenerator
    {
        IEnumerable<string> GenerateVariations(string baseDomain);
    }
}