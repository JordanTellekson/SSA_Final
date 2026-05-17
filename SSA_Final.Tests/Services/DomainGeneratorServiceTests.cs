using Microsoft.Extensions.Logging.Abstractions;
using SSA_Final.Services;

namespace SSA_Final.Tests.Services;

public class DomainGeneratorServiceTests
{
    [Fact]
    public void GenerateVariations_IncludesExpandedSubdomainPrefixes()
    {
        var service = new DomainGeneratorService(NullLogger<DomainGeneratorService>.Instance);

        var variations = service.GenerateVariations("paypal.com").ToHashSet(StringComparer.OrdinalIgnoreCase);

        Assert.Contains("portal.paypal.com", variations);
        Assert.Contains("billing.paypal.com", variations);
        Assert.Contains("sso.login.paypal.com", variations);
        Assert.Contains("paypal-billing.com", variations);
    }
}
