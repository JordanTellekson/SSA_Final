using SSA_Final.Models;
using Xunit;

namespace SSA_Final.Tests.Models
{
    /// <summary>
    /// Verifies domain model classes preserve expected field behavior.
    /// </summary>
    public class DomainModelsTests
    {
        [Fact]
        /// <summary>
        /// Confirms all domain analysis fields can be assigned and read back.
        /// </summary>
        public void DomainAnalysisResult_Should_Assign_All_UserStory_Fields()
        {
            var result = new DomainAnalysisResult
            {
                DomainName = "example.com",
                IsSuspicious = true,
                Reason = "Suspicious MX records",
                Notes = "Observed DNS pattern associated with phishing kits.",
                Indicators = new List<string> { "Suspicious MX", "Low reputation ASN" }
            };

            Assert.Equal("example.com", result.DomainName);
            Assert.True(result.IsSuspicious);
            Assert.Equal("Suspicious MX records", result.Reason);
            Assert.Equal("Observed DNS pattern associated with phishing kits.", result.Notes);
            Assert.Equal(2, result.Indicators.Count);
        }

        [Fact]
        /// <summary>
        /// Confirms scan aggregate fields and malicious-count projection work as expected.
        /// </summary>
        public void DomainScan_Should_Store_BaseDomain_ScanDate_And_ResultsCollection()
        {
            var scan = new DomainScan
            {
                BaseDomain = "example.com",
                ScanDate = new DateTime(2026, 4, 10, 12, 0, 0, DateTimeKind.Utc),
                Results = new List<DomainAnalysisResult>
                {
                    new() { DomainName = "example.com", IsSuspicious = false, Reason = "No indicators", Notes = "Clean result" },
                    new() { DomainName = "examp1e.com", IsSuspicious = true, Reason = "Typosquatting", Notes = "One-char substitution" }
                },
                RiskAnalyses = new List<DomainRiskAnalysis>
                {
                    new() { DomainName = "example.com", IsSuspicious = false, Reason = "No indicators", Notes = "Clean result" },
                    new() { DomainName = "examp1e.com", IsSuspicious = true, Reason = "Typosquatting", Notes = "One-char substitution" }
                }
            };

            Assert.Equal("example.com", scan.BaseDomain);
            Assert.Equal(new DateTime(2026, 4, 10, 12, 0, 0, DateTimeKind.Utc), scan.ScanDate);
            Assert.Equal(2, scan.Results.Count);
            Assert.Equal(2, scan.RiskAnalyses.Count);
            Assert.Equal(1, scan.NumMaliciousDomains);
        }

        [Fact]
        /// <summary>
        /// Confirms risk-analysis model stores decision and explanatory fields correctly.
        /// </summary>
        public void DomainRiskAnalysis_Should_Assign_DomainName_Suspicious_Reason_And_Notes()
        {
            var risk = new DomainRiskAnalysis
            {
                DomainName = "examp1e-login.com",
                IsSuspicious = true,
                Reason = "Typosquatting pattern detected",
                Notes = "Closest match is example.com with edit distance 1."
            };

            Assert.Equal("examp1e-login.com", risk.DomainName);
            Assert.True(risk.IsSuspicious);
            Assert.Equal("Typosquatting pattern detected", risk.Reason);
            Assert.Equal("Closest match is example.com with edit distance 1.", risk.Notes);
        }
    }
}
