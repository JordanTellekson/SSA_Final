using Microsoft.Extensions.Configuration;

namespace SSA_Final.Models
{
    public sealed class RiskThresholdOptions
    {
        public const string SectionName = "RiskThresholds";

        public int SuspiciousMinScore { get; set; } = 1;

        public int BlocklistMatchScore { get; set; } = 100;

        public TyposquattingScoreOptions Typosquatting { get; set; } = new();

        public SubdomainScoreOptions Subdomains { get; set; } = new();

        public HyphenAbuseScoreOptions HyphenAbuse { get; set; } = new();

        public ShannonEntropyScoreOptions ShannonEntropy { get; set; } = new();

        public RepeatedSegmentScoreOptions RepeatedSegment { get; set; } = new();

        public KeywordAbuseScoreOptions KeywordAbuse { get; set; } = new();

        public RegistrationAgeScoreOptions DomainRegistrationAge { get; set; } = new();

        public RegistrationLifespanScoreOptions DomainRegistrationLifespan { get; set; } = new();

        public WhoisPrivacyScoreOptions WhoisPrivacyProtection { get; set; } = new();

        public CharacterCompositionScoreOptions CharacterCompositionAnomaly { get; set; } = new();

        public int EffectiveSuspiciousMinScore => Math.Clamp(SuspiciousMinScore, 1, 100);

        public static RiskThresholdOptions FromConfiguration(IConfiguration configuration)
        {
            var options = new RiskThresholdOptions();
            configuration.GetSection(SectionName).Bind(options);
            options.Normalize();
            return options;
        }

        private void Normalize()
        {
            SuspiciousMinScore = Math.Clamp(SuspiciousMinScore, 1, 100);
            BlocklistMatchScore = Math.Clamp(BlocklistMatchScore, 0, 100);
            Typosquatting.Normalize();
            Subdomains.Normalize();
            HyphenAbuse.Normalize();
            ShannonEntropy.Normalize();
            RepeatedSegment.Normalize();
            KeywordAbuse.Normalize();
            DomainRegistrationAge.Normalize();
            DomainRegistrationLifespan.Normalize();
            WhoisPrivacyProtection.Normalize();
            CharacterCompositionAnomaly.Normalize();
        }
    }

    public sealed class TyposquattingScoreOptions
    {
        public int EditDistanceOne { get; set; } = 20;

        public int EditDistanceTwo { get; set; } = 14;

        public int EditDistanceThree { get; set; } = 8;

        public void Normalize()
        {
            EditDistanceOne = Math.Max(0, EditDistanceOne);
            EditDistanceTwo = Math.Max(0, EditDistanceTwo);
            EditDistanceThree = Math.Max(0, EditDistanceThree);
        }
    }

    public sealed class SubdomainScoreOptions
    {
        public int TwoSubdomains { get; set; } = 6;

        public int ThreeSubdomains { get; set; } = 10;

        public int FourOrMoreSubdomains { get; set; } = 14;

        public void Normalize()
        {
            TwoSubdomains = Math.Max(0, TwoSubdomains);
            ThreeSubdomains = Math.Max(0, ThreeSubdomains);
            FourOrMoreSubdomains = Math.Max(0, FourOrMoreSubdomains);
        }
    }

    public sealed class HyphenAbuseScoreOptions
    {
        public int OneHyphen { get; set; } = 4;

        public int TwoHyphens { get; set; } = 8;

        public int ThreeHyphens { get; set; } = 12;

        public int FourOrMoreHyphens { get; set; } = 16;

        public int RepeatedHyphenBonus { get; set; } = 2;

        public int MaxScore { get; set; } = 16;

        public void Normalize()
        {
            OneHyphen = Math.Max(0, OneHyphen);
            TwoHyphens = Math.Max(0, TwoHyphens);
            ThreeHyphens = Math.Max(0, ThreeHyphens);
            FourOrMoreHyphens = Math.Max(0, FourOrMoreHyphens);
            RepeatedHyphenBonus = Math.Max(0, RepeatedHyphenBonus);
            MaxScore = Math.Max(0, MaxScore);
        }
    }

    public sealed class ShannonEntropyScoreOptions
    {
        public int ModerateEntropy { get; set; } = 6;

        public int HighEntropy { get; set; } = 12;

        public int VeryHighEntropy { get; set; } = 16;

        public int LongLabelBonus { get; set; } = 4;

        public int MaxScore { get; set; } = 16;

        public void Normalize()
        {
            ModerateEntropy = Math.Max(0, ModerateEntropy);
            HighEntropy = Math.Max(0, HighEntropy);
            VeryHighEntropy = Math.Max(0, VeryHighEntropy);
            LongLabelBonus = Math.Max(0, LongLabelBonus);
            MaxScore = Math.Max(0, MaxScore);
        }
    }

    public sealed class RepeatedSegmentScoreOptions
    {
        public int OneRepeatedSegment { get; set; } = 10;

        public int MultipleRepeatedSegments { get; set; } = 14;

        public void Normalize()
        {
            OneRepeatedSegment = Math.Max(0, OneRepeatedSegment);
            MultipleRepeatedSegments = Math.Max(0, MultipleRepeatedSegments);
        }
    }

    public sealed class KeywordAbuseScoreOptions
    {
        public int RootLabelKeyword { get; set; } = 10;

        public int SubdomainKeyword { get; set; } = 5;

        public int MaxScore { get; set; } = 12;

        public void Normalize()
        {
            RootLabelKeyword = Math.Max(0, RootLabelKeyword);
            SubdomainKeyword = Math.Max(0, SubdomainKeyword);
            MaxScore = Math.Max(0, MaxScore);
        }
    }

    public sealed class RegistrationAgeScoreOptions
    {
        public int ThirtyDaysOrLess { get; set; } = 25;

        public int NinetyDaysOrLess { get; set; } = 15;

        public void Normalize()
        {
            ThirtyDaysOrLess = Math.Max(0, ThirtyDaysOrLess);
            NinetyDaysOrLess = Math.Max(0, NinetyDaysOrLess);
        }
    }

    public sealed class RegistrationLifespanScoreOptions
    {
        public int OneYearOrLess { get; set; } = 10;

        public int TwoYearsOrLess { get; set; } = 5;

        public void Normalize()
        {
            OneYearOrLess = Math.Max(0, OneYearOrLess);
            TwoYearsOrLess = Math.Max(0, TwoYearsOrLess);
        }
    }

    public sealed class WhoisPrivacyScoreOptions
    {
        public int PrivacyProtected { get; set; } = 5;

        public void Normalize()
        {
            PrivacyProtected = Math.Max(0, PrivacyProtected);
        }
    }

    public sealed class CharacterCompositionScoreOptions
    {
        public int HighDigitRatio { get; set; } = 8;

        public int ModerateDigitRatio { get; set; } = 5;

        public int HighConsonantRatio { get; set; } = 5;

        public int LongRepeatedRun { get; set; } = 5;

        public int ModerateRepeatedRun { get; set; } = 3;

        public int LongLabel { get; set; } = 4;

        public int MaxScore { get; set; } = 12;

        public void Normalize()
        {
            HighDigitRatio = Math.Max(0, HighDigitRatio);
            ModerateDigitRatio = Math.Max(0, ModerateDigitRatio);
            HighConsonantRatio = Math.Max(0, HighConsonantRatio);
            LongRepeatedRun = Math.Max(0, LongRepeatedRun);
            ModerateRepeatedRun = Math.Max(0, ModerateRepeatedRun);
            LongLabel = Math.Max(0, LongLabel);
            MaxScore = Math.Max(0, MaxScore);
        }
    }
}
