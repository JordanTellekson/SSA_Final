// Variation generator service that creates domain permutations for scanning.
// Only plausible variants that a real phisher might register are emitted.

using SSA_Final.Interfaces;

namespace SSA_Final.Services
{
    public class DomainGeneratorService : IDomainGenerator
    {
        private readonly ILogger<DomainGeneratorService> _logger;

        // Subdomain depth cap: real phishing campaigns rarely exceed 2 stacked prefix labels.
        private const int MaxAddedSubdomains = 2;

        // Extra hyphen insertion cap: more than 3 injected hyphens produces implausible labels.
        private const int MaxAddedHyphens = 3;

        // Per-label cap on extra-hyphen variants.
        private const int MaxHyphenVariantsPerLabel = 250;

        // Per-domain cap on combined two-technique typo variants with subdomains and alternate TLDs.
        private const int MaxCombinedTypoSubdomainTldVariants = 150;

        private enum TypoMutation
        {
            Omission,
            Duplication,
            AdjacentKey,
            Transposition,
            Homoglyph
        }

        private static readonly TypoMutation[] CombinedTypoMutations =
        [
            TypoMutation.Omission,
            TypoMutation.Duplication,
            TypoMutation.AdjacentKey,
            TypoMutation.Transposition,
            TypoMutation.Homoglyph
        ];

        private static readonly string[] CommonTlds =
        [
            "com", "net", "org", "co", "io", "xyz", "top", "tk", "ru", "pw", "cc",
            "buzz", "gq", "ml", "cf", "ga", "info", "biz", "online", "site", "club", "vip", "shop", "website"
        ];

        private static readonly string[] SubdomainPrefixes =
        [
            "secure",
            "login",
            "account",
            "verify",
            "signin",
            "auth",
            "sso",
            "id",
            "portal",
            "admin",
            "dashboard",
            "support",
            "help",
            "service",
            "billing",
            "payment",
            "invoice",
            "wallet",
            "update",
            "confirm",
            "recovery",
            "password",
            "reset",
            "mfa",
            "webmail",
            "mail",
            "cloud",
            "docs",
            "blog",
            "download",
            "app",
            "my"
        ];

        // QWERTY-adjacent keys for likely typo substitutions.
        private static readonly Dictionary<char, char[]> AdjacentKeys = new()
        {
            ['a'] = ['q', 'w', 's', 'z'],
            ['b'] = ['v', 'g', 'h', 'n'],
            ['c'] = ['x', 'd', 'f', 'v'],
            ['d'] = ['s', 'e', 'r', 'f', 'c', 'x'],
            ['e'] = ['w', 's', 'd', 'r'],
            ['f'] = ['d', 'r', 't', 'g', 'v', 'c'],
            ['g'] = ['f', 't', 'y', 'h', 'b', 'v'],
            ['h'] = ['g', 'y', 'u', 'j', 'n', 'b'],
            ['i'] = ['u', 'j', 'k', 'o'],
            ['j'] = ['h', 'u', 'i', 'k', 'm', 'n'],
            ['k'] = ['j', 'i', 'o', 'l', 'm'],
            ['l'] = ['k', 'o', 'p'],
            ['m'] = ['n', 'j', 'k'],
            ['n'] = ['b', 'h', 'j', 'm'],
            ['o'] = ['i', 'k', 'l', 'p'],
            ['p'] = ['o', 'l'],
            ['q'] = ['w', 'a'],
            ['r'] = ['e', 'd', 'f', 't'],
            ['s'] = ['a', 'w', 'e', 'd', 'x', 'z'],
            ['t'] = ['r', 'f', 'g', 'y'],
            ['u'] = ['y', 'h', 'j', 'i'],
            ['v'] = ['c', 'f', 'g', 'b'],
            ['w'] = ['q', 'a', 's', 'e'],
            ['x'] = ['z', 's', 'd', 'c'],
            ['y'] = ['t', 'g', 'h', 'u'],
            ['z'] = ['a', 's', 'x'],
            ['0'] = ['9', 'o'],
            ['1'] = ['2', 'l', 'i'],
            ['2'] = ['1', '3', 'q', 'w'],
            ['3'] = ['2', '4', 'e', 'w'],
            ['4'] = ['3', '5', 'r', 'e'],
            ['5'] = ['4', '6', 't', 'r'],
            ['6'] = ['5', '7', 'y', 't'],
            ['7'] = ['6', '8', 'u', 'y'],
            ['8'] = ['7', '9', 'i', 'u'],
            ['9'] = ['8', '0', 'o', 'i']
        };

        // One-char and multi-char visual substitutions used by phishers.
        private static readonly Dictionary<string, string[]> HomoglyphMap = new(StringComparer.Ordinal)
        {
            ["0"] = ["O"],
            ["1"] = ["l", "I"],
            ["3"] = ["E"],
            ["4"] = ["A"],
            ["5"] = ["S"],
            ["7"] = ["T"],
            ["8"] = ["B"],
            ["a"] = ["4"],
            ["e"] = ["3"],
            ["i"] = ["1", "l"],
            ["l"] = ["1", "I"],
            ["m"] = ["rn"],
            ["o"] = ["0"],
            ["s"] = ["5"],
            ["w"] = ["vv"],
            ["d"] = ["cl"],
            ["rn"] = ["m"],
            ["vv"] = ["w"],
            ["cl"] = ["d"],
            ["I"] = ["1", "l"],
            ["O"] = ["0"],
            ["S"] = ["5"],
            ["E"] = ["3"],
            ["A"] = ["4"],
            ["T"] = ["7"],
            ["B"] = ["8"]
        };

        public DomainGeneratorService(ILogger<DomainGeneratorService> logger)
        {
            _logger = logger;
        }

        /// <inheritdoc />
        public IEnumerable<string> GenerateVariations(string baseDomain)
        {
            _logger.LogInformation(
                "[DomainGeneratorService] GenerateVariations called for domain: {Domain}",
                baseDomain);

            if (string.IsNullOrWhiteSpace(baseDomain))
            {
                _logger.LogWarning(
                    "[DomainGeneratorService] GenerateVariations received null or empty domain.");
                return Enumerable.Empty<string>();
            }

            var normalized = baseDomain.Trim().Trim('.').ToLowerInvariant();
            if (!SplitDomain(normalized, out var subdomains, out var label, out var tld))
            {
                _logger.LogWarning(
                    "[DomainGeneratorService] Domain '{Domain}' could not be split into label + TLD.",
                    normalized);
                return Enumerable.Empty<string>();
            }

            var variations = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            AddTyposquatting(subdomains, label, tld, variations);
            AddSubdomains(subdomains, label, tld, variations);
            AddHyphenExpansionsFromExistingVariants(variations);
            AddHyphen(subdomains, label, tld, variations);
            AddCombinedTypoSubdomainTldVariants(subdomains, label, tld, variations);

            // Remove the original input from the output set.
            variations.Remove(normalized);

            // Apply the plausibility filter to strip implausible generated variants.
            var output = variations
                .Where(v => !string.IsNullOrWhiteSpace(v) && IsPlausibleVariant(v))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            _logger.LogInformation(
                "[DomainGeneratorService] Generated {Count} variation(s) for domain: {Domain}. LabelEntropy={Entropy:F2}",
                output.Count, normalized, ComputeShannonEntropy(label));

            return output;
        }

        // Adds subdomain- and prefix-based lookalikes such as secure.example.com.
        // Hyphen-prefix forms cover one- and two-prefix sequences such as login-paypal.com
        // and login-secure-paypal.com while avoiding deeper implausible chains.
        private static void AddSubdomains(string subdomains, string label, string tld, ISet<string> variations)
        {
            if (string.IsNullOrWhiteSpace(label) || string.IsNullOrWhiteSpace(tld))
            {
                return;
            }

            var rootDomain = BuildDomain(subdomains, label, tld);
            if (string.IsNullOrWhiteSpace(rootDomain))
            {
                return;
            }

            for (var depth = 1; depth <= MaxAddedSubdomains; depth++)
            {
                foreach (var prefixSequence in EnumeratePrefixSequences(depth))
                {
                    // Dot-subdomain form is always emitted (e.g., login.paypal.com, login.secure.paypal.com).
                    var dotPrefix = string.Join('.', prefixSequence);
                    variations.Add($"{dotPrefix}.{rootDomain}");

                    // Hyphen forms are only realistic for single- and two-prefix sequences.
                    if (depth == 1)
                    {
                        var prefix = prefixSequence[0];
                        variations.Add(BuildDomain(subdomains, $"{prefix}-{label}", tld));
                        variations.Add(BuildDomain(subdomains, $"{label}-{prefix}", tld));
                    }
                    else if (depth == 2)
                    {
                        // Two-prefix hyphen chains cover realistic patterns such as
                        // paypal-secure-login.com and secure-login-paypal.com.
                        var prefix1 = prefixSequence[0];
                        var prefix2 = prefixSequence[1];
                        variations.Add(BuildDomain(subdomains, $"{label}-{prefix1}-{prefix2}", tld));
                        variations.Add(BuildDomain(subdomains, $"{prefix1}-{prefix2}-{label}", tld));
                    }
                }
            }
        }

        // Inserts additional hyphens only next to hyphens already present in the label.
        // This keeps clean labels like paypal.com from becoming pay-pal.com while allowing
        // already-hyphenated variants such as secure-paypal.com -> secure--paypal.com.
        private static void AddHyphen(string subdomains, string label, string tld, ISet<string> variations)
        {
            if (label.Length < 2 || !label.Contains('-', StringComparison.Ordinal))
            {
                return;
            }

            var hyphenSlots = label.Count(ch => ch == '-');
            var created = 0;

            for (var hyphensToInsert = 1; hyphensToInsert <= MaxAddedHyphens; hyphensToInsert++)
            {
                var distribution = new int[hyphenSlots];
                AddHyphenPatterns(0, hyphensToInsert, distribution);

                if (created >= MaxHyphenVariantsPerLabel)
                {
                    break;
                }
            }

            void AddHyphenPatterns(int gapIndex, int remaining, int[] distribution)
            {
                if (created >= MaxHyphenVariantsPerLabel)
                {
                    return;
                }

                if (gapIndex == hyphenSlots)
                {
                    if (remaining != 0)
                    {
                        return;
                    }

                    var mutated = BuildExtraHyphenatedLabel(label, distribution);
                    var domain = BuildDomain(subdomains, mutated, tld);
                    if (!string.IsNullOrWhiteSpace(domain) && variations.Add(domain))
                    {
                        created++;
                    }

                    return;
                }

                for (var insertionsAtGap = 0; insertionsAtGap <= remaining; insertionsAtGap++)
                {
                    distribution[gapIndex] = insertionsAtGap;
                    AddHyphenPatterns(gapIndex + 1, remaining - insertionsAtGap, distribution);

                    if (created >= MaxHyphenVariantsPerLabel)
                    {
                        break;
                    }
                }

                distribution[gapIndex] = 0;
            }
        }

        private static void AddHyphenExpansionsFromExistingVariants(ISet<string> variations)
        {
            foreach (var domain in variations.ToArray())
            {
                if (SplitDomain(domain, out var subdomains, out var label, out var tld))
                {
                    AddHyphen(subdomains, label, tld, variations);
                }
            }
        }

        // Generates typosquatting variants via omission, duplication, adjacent keys, transposition,
        // homoglyphs, and common TLD swaps.
        private static void AddTyposquatting(string subdomains, string label, string tld, ISet<string> variations)
        {
            if (string.IsNullOrWhiteSpace(label) || string.IsNullOrWhiteSpace(tld))
            {
                return;
            }

            // Character omission
            foreach (var omitted in GenerateTypoLabels(label, TypoMutation.Omission))
            {
                variations.Add(BuildDomain(subdomains, omitted, tld));
            }

            // Character duplication
            foreach (var duplicated in GenerateTypoLabels(label, TypoMutation.Duplication))
            {
                variations.Add(BuildDomain(subdomains, duplicated, tld));
            }

            // Character transposition
            foreach (var transposed in GenerateTypoLabels(label, TypoMutation.Transposition))
            {
                variations.Add(BuildDomain(subdomains, transposed, tld));
            }

            // Adjacent key substitutions
            foreach (var adjacentKey in GenerateTypoLabels(label, TypoMutation.AdjacentKey))
            {
                variations.Add(BuildDomain(subdomains, adjacentKey, tld));
            }

            // Homoglyph substitutions for both one-char and multi-char keys.
            foreach (var homoglyph in GenerateTypoLabels(label, TypoMutation.Homoglyph))
            {
                variations.Add(BuildDomain(subdomains, homoglyph, tld));
            }

            // TLD swaps
            foreach (var altTld in CommonTlds)
            {
                if (!altTld.Equals(tld, StringComparison.OrdinalIgnoreCase))
                {
                    variations.Add(BuildDomain(subdomains, label, altTld));
                }
            }
        }

        private static void AddCombinedTypoSubdomainTldVariants(
            string subdomains,
            string label,
            string tld,
            ISet<string> variations)
        {
            if (string.IsNullOrWhiteSpace(label) || string.IsNullOrWhiteSpace(tld))
            {
                return;
            }

            var alternateTlds = CommonTlds
                .Where(altTld => !altTld.Equals(tld, StringComparison.OrdinalIgnoreCase))
                .ToArray();

            if (alternateTlds.Length == 0)
            {
                return;
            }

            var singleTypoLabels = CombinedTypoMutations
                .SelectMany(mutation => GenerateTypoLabels(label, mutation))
                .Where(IsValidLabel)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            var combinedLabels = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var firstMutation in CombinedTypoMutations)
            {
                foreach (var firstPassLabel in GenerateTypoLabels(label, firstMutation))
                {
                    if (!IsValidLabel(firstPassLabel))
                    {
                        continue;
                    }

                    foreach (var secondMutation in CombinedTypoMutations)
                    {
                        if (secondMutation == firstMutation)
                        {
                            continue;
                        }

                        foreach (var combinedLabel in GenerateTypoLabels(firstPassLabel, secondMutation))
                        {
                            if (!IsValidLabel(combinedLabel) ||
                                combinedLabel.Equals(label, StringComparison.OrdinalIgnoreCase) ||
                                singleTypoLabels.Contains(combinedLabel))
                            {
                                continue;
                            }

                            combinedLabels.Add(combinedLabel);
                        }
                    }
                }
            }

            var rootDomain = BuildDomain(subdomains, label, tld);
            var created = 0;
            foreach (var combinedLabel in OrderPseudoRandomly(combinedLabels, rootDomain))
            {
                var labelSeed = $"{rootDomain}|{combinedLabel}";
                foreach (var prefix in OrderPseudoRandomly(SubdomainPrefixes, labelSeed))
                {
                    var combinedSubdomains = PrependSubdomain(prefix, subdomains);
                    foreach (var alternateTld in OrderPseudoRandomly(alternateTlds, $"{labelSeed}|{prefix}"))
                    {
                        var domain = BuildDomain(combinedSubdomains, combinedLabel, alternateTld);
                        if (!string.IsNullOrWhiteSpace(domain) && variations.Add(domain))
                        {
                            created++;
                        }

                        if (created >= MaxCombinedTypoSubdomainTldVariants)
                        {
                            return;
                        }
                    }
                }
            }
        }

        // Returns false for structurally implausible domains that no real phisher would register:
        //   — registrable labels exceeding 40 characters
        //   — labels containing three or more consecutive hyphens
        //   — hyphen-delimited label tokens that repeat consecutively (e.g., login-login-paypal)
        //   — subdomain chain labels that repeat consecutively (e.g., login.login.paypal.com)
        private static bool IsPlausibleVariant(string domain)
        {
            if (!SplitDomain(domain, out _, out var label, out _))
            {
                return false;
            }

            if (label.Length > 40)
            {
                return false;
            }

            if (label.Contains("---", StringComparison.Ordinal))
            {
                return false;
            }

            // Reject hyphen-delimited tokens that repeat consecutively.
            var hyphenTokens = label.Split('-', StringSplitOptions.RemoveEmptyEntries);
            for (var i = 0; i < hyphenTokens.Length - 1; i++)
            {
                if (hyphenTokens[i].Equals(hyphenTokens[i + 1], StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }
            }

            // Reject subdomain chain labels that repeat consecutively.
            var allLabels = domain.Split('.', StringSplitOptions.RemoveEmptyEntries);
            for (var i = 0; i < allLabels.Length - 1; i++)
            {
                if (allLabels[i].Equals(allLabels[i + 1], StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }
            }

            return true;
        }

        // Shannon entropy helper used for diagnostic logging.
        private static double ComputeShannonEntropy(string value)
        {
            if (string.IsNullOrEmpty(value))
            {
                return 0;
            }

            var frequencies = value
                .GroupBy(ch => ch)
                .Select(g => (double)g.Count() / value.Length);

            var entropy = 0.0;
            foreach (var p in frequencies)
            {
                entropy -= p * Math.Log2(p);
            }

            return entropy;
        }

        private static bool SplitDomain(string domain, out string subdomains, out string label, out string tld)
        {
            subdomains = string.Empty;
            label = string.Empty;
            tld = string.Empty;

            var parts = domain
                .Split('.', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

            if (parts.Length < 2)
            {
                return false;
            }

            tld = parts[^1];
            label = parts[^2];
            subdomains = parts.Length > 2
                ? string.Join('.', parts.Take(parts.Length - 2))
                : string.Empty;

            return !string.IsNullOrWhiteSpace(label) && !string.IsNullOrWhiteSpace(tld);
        }

        private static string BuildDomain(string subdomains, string label, string tld)
        {
            if (!IsValidLabel(label) || string.IsNullOrWhiteSpace(tld))
            {
                return string.Empty;
            }

            return string.IsNullOrWhiteSpace(subdomains)
                ? $"{label}.{tld}"
                : $"{subdomains}.{label}.{tld}";
        }

        private static string PrependSubdomain(string prefix, string subdomains)
        {
            return string.IsNullOrWhiteSpace(subdomains)
                ? prefix
                : $"{prefix}.{subdomains}";
        }

        private static bool IsValidLabel(string label)
        {
            if (string.IsNullOrWhiteSpace(label) || label.Length > 63)
            {
                return false;
            }

            if (label.StartsWith('-') || label.EndsWith('-'))
            {
                return false;
            }

            foreach (var ch in label)
            {
                if (!(char.IsLetterOrDigit(ch) || ch == '-'))
                {
                    return false;
                }
            }

            return true;
        }

        private static IEnumerable<string> GenerateTypoLabels(string label, TypoMutation mutation)
        {
            return mutation switch
            {
                TypoMutation.Omission => GenerateOmissionLabels(label),
                TypoMutation.Duplication => GenerateDuplicationLabels(label),
                TypoMutation.AdjacentKey => GenerateAdjacentKeyLabels(label),
                TypoMutation.Transposition => GenerateTranspositionLabels(label),
                TypoMutation.Homoglyph => GenerateHomoglyphLabels(label),
                _ => Enumerable.Empty<string>()
            };
        }

        private static IEnumerable<string> GenerateOmissionLabels(string label)
        {
            if (label.Length <= 1)
            {
                yield break;
            }

            for (var i = 0; i < label.Length; i++)
            {
                var omitted = label.Remove(i, 1);
                if (!string.IsNullOrWhiteSpace(omitted))
                {
                    yield return omitted;
                }
            }
        }

        private static IEnumerable<string> GenerateDuplicationLabels(string label)
        {
            for (var i = 0; i < label.Length; i++)
            {
                yield return label.Insert(i + 1, label[i].ToString());
            }
        }

        private static IEnumerable<string> GenerateAdjacentKeyLabels(string label)
        {
            for (var i = 0; i < label.Length; i++)
            {
                if (!AdjacentKeys.TryGetValue(label[i], out var adjacent))
                {
                    continue;
                }

                foreach (var replacement in adjacent)
                {
                    if (replacement == label[i])
                    {
                        continue;
                    }

                    var chars = label.ToCharArray();
                    chars[i] = replacement;
                    yield return new string(chars);
                }
            }
        }

        private static IEnumerable<string> GenerateTranspositionLabels(string label)
        {
            for (var i = 0; i < label.Length - 1; i++)
            {
                if (label[i] == label[i + 1])
                {
                    continue;
                }

                var chars = label.ToCharArray();
                (chars[i], chars[i + 1]) = (chars[i + 1], chars[i]);
                yield return new string(chars);
            }
        }

        private static IEnumerable<string> GenerateHomoglyphLabels(string label)
        {
            foreach (var pair in HomoglyphMap)
            {
                var search = pair.Key;
                var index = label.IndexOf(search, StringComparison.Ordinal);
                while (index >= 0)
                {
                    foreach (var replacement in pair.Value)
                    {
                        yield return label[..index] + replacement + label[(index + search.Length)..];
                    }

                    index = label.IndexOf(search, index + 1, StringComparison.Ordinal);
                }
            }
        }

        private static IEnumerable<string> OrderPseudoRandomly(IEnumerable<string> values, string seed)
        {
            var seedHash = ComputeStableHash(seed);
            return values
                .OrderBy(value => ComputeStableHash(value) ^ seedHash)
                .ThenBy(value => value, StringComparer.OrdinalIgnoreCase);
        }

        private static uint ComputeStableHash(string value)
        {
            const uint offsetBasis = 2166136261;
            const uint prime = 16777619;

            var hash = offsetBasis;
            foreach (var ch in value)
            {
                hash ^= ch;
                hash *= prime;
            }

            return hash;
        }

        private static string BuildExtraHyphenatedLabel(string label, IReadOnlyList<int> distribution)
        {
            if (distribution.Count != label.Count(ch => ch == '-'))
            {
                return label;
            }

            var result = new System.Text.StringBuilder();
            var hyphenSlot = 0;
            for (var i = 0; i < label.Length; i++)
            {
                result.Append(label[i]);
                if (label[i] == '-')
                {
                    var hyphenCount = distribution[hyphenSlot];
                    if (hyphenCount > 0)
                    {
                        result.Append('-', hyphenCount);
                    }

                    hyphenSlot++;
                }
            }

            return result.ToString();
        }

        // Enumerates prefix sequences of the requested depth using permutations without repetition.
        // Each prefix appears at most once per sequence, preventing degenerate patterns such as
        // ["login","login","login"] that produce implausible filler domains like login-login-login-paypal.net.
        private static IEnumerable<IReadOnlyList<string>> EnumeratePrefixSequences(int depth)
        {
            if (depth <= 0 || depth > SubdomainPrefixes.Length)
            {
                yield break;
            }

            var buffer = new string[depth];
            var used = new bool[SubdomainPrefixes.Length];

            foreach (var sequence in Enumerate(0))
            {
                yield return sequence;
            }

            IEnumerable<IReadOnlyList<string>> Enumerate(int index)
            {
                if (index == depth)
                {
                    yield return buffer.ToArray();
                    yield break;
                }

                for (var i = 0; i < SubdomainPrefixes.Length; i++)
                {
                    if (used[i])
                    {
                        continue;
                    }

                    used[i] = true;
                    buffer[index] = SubdomainPrefixes[i];

                    foreach (var item in Enumerate(index + 1))
                    {
                        yield return item;
                    }

                    used[i] = false;
                }
            }
        }
    }
}
