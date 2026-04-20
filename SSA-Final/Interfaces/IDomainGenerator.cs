namespace SSA_Final.Interfaces
{
    /// <summary>
    /// Generates potential typosquatting variations for a base domain.
    /// </summary>
    public interface IDomainGenerator
    {
        /// <summary>
        /// Produces candidate domain variations for a supplied base domain.
        /// </summary>
        /// <param name="baseDomain">Input domain such as <c>example.com</c>.</param>
        /// <returns>A sequence of generated variation domains.</returns>
        IEnumerable<string> GenerateVariations(string baseDomain);
    }
}
