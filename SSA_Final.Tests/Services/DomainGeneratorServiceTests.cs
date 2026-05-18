using Microsoft.Extensions.Logging.Abstractions;
using SSA_Final.Services;

namespace SSA_Final.Tests.Services;

public class DomainGeneratorServiceTests
{
    private static readonly DomainGeneratorService Service =
        new(NullLogger<DomainGeneratorService>.Instance);

    [Fact]
    public void GenerateVariations_IncludesExpandedSubdomainPrefixes()
    {
        var variations = Service.GenerateVariations("paypal.com").ToHashSet(StringComparer.OrdinalIgnoreCase);

        Assert.Contains("portal.paypal.com", variations);
        Assert.Contains("billing.paypal.com", variations);
        Assert.Contains("sso.login.paypal.com", variations);
        Assert.Contains("paypal-billing.com", variations);
    }

    [Fact]
    public void GenerateVariations_AddsExtraHyphensToSubdomainPrefixFormsOnly()
    {
        var variations = Service.GenerateVariations("paypal.com").ToHashSet(StringComparer.OrdinalIgnoreCase);

        Assert.Contains("secure-paypal.com", variations);
        Assert.Contains("secure--paypal.com", variations);
        Assert.Contains("paypal-secure.com", variations);
        Assert.Contains("paypal--secure.com", variations);

        Assert.DoesNotContain("pay-pal.com", variations);
        Assert.DoesNotContain("p-aypal.com", variations);
    }

    [Theory]
    [InlineData("secure-paypal.net", "secure--paypal.net", "secure--paypal.com")]
    [InlineData("login.secure-paypal.co", "login.secure--paypal.co", "login.secure--paypal.com")]
    [InlineData("account.verify.paypal-login.io", "account.verify.paypal--login.io", "account.verify.paypal--login.net")]
    public void GenerateVariations_AddsExtraHyphensForSubdomainsAndAlternateTlds(
        string input,
        string sameTldVariant,
        string alternateTldVariant)
    {
        var variations = Service.GenerateVariations(input).ToHashSet(StringComparer.OrdinalIgnoreCase);

        Assert.Contains(sameTldVariant, variations);
        Assert.Contains(alternateTldVariant, variations);
        Assert.All(variations, variation => Assert.DoesNotContain("---", variation));
    }

    [Fact]
    public void GenerateVariations_AddsCappedCombinedTypoSubdomainAlternateTldVariants()
    {
        var variations = Service.GenerateVariations("paypal.com").ToHashSet(StringComparer.OrdinalIgnoreCase);

        var combinedVariants = GetSubdomainAlternateTldTypoVariants(variations, "paypal", "com");

        Assert.Equal(150, combinedVariants.Count);
        Assert.All(combinedVariants, variation =>
        {
            var parts = variation.Split('.', StringSplitOptions.RemoveEmptyEntries);
            Assert.True(parts.Length >= 3);
            Assert.NotEqual("paypal", parts[^2], StringComparer.OrdinalIgnoreCase);
            Assert.NotEqual("com", parts[^1], StringComparer.OrdinalIgnoreCase);
        });
    }

    [Fact]
    public void GenerateVariations_CombinedTypoVariantsPreserveExistingSubdomains()
    {
        var variations = Service.GenerateVariations("login.paypal.com").ToHashSet(StringComparer.OrdinalIgnoreCase);

        var combinedVariants = GetSubdomainAlternateTldTypoVariants(variations, "paypal", "com");

        Assert.NotEmpty(combinedVariants);
        Assert.Contains(combinedVariants, variation =>
        {
            var parts = variation.Split('.', StringSplitOptions.RemoveEmptyEntries);
            return parts.Length >= 4 &&
                   parts[^3].Equals("login", StringComparison.OrdinalIgnoreCase);
        });
    }

    private static List<string> GetSubdomainAlternateTldTypoVariants(
        IEnumerable<string> variations,
        string baseLabel,
        string baseTld)
    {
        return variations
            .Where(variation =>
            {
                var parts = variation.Split('.', StringSplitOptions.RemoveEmptyEntries);
                return parts.Length >= 3 &&
                       !parts[^2].Equals(baseLabel, StringComparison.OrdinalIgnoreCase) &&
                       !parts[^1].Equals(baseTld, StringComparison.OrdinalIgnoreCase);
            })
            .ToList();
    }
}
