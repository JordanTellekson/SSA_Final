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
}
