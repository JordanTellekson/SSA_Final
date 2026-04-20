using SSA_Final.Interfaces;

namespace SSA_Final.Services
{
    public class DomainGeneratorService : IDomainGenerator
    {
        private readonly ILogger<DomainGeneratorService> _logger;
        private const int MaxAddedSubdomains = 4;
        private const int MaxAddedHyphens = 6;
        private const int MaxHyphenVariantsPerDomain = 3000;
        private static readonly string[] CommonTlds = ["com", "net", "org", "co", "io"];
        private static readonly string[] SubdomainPrefixes = ["secure", "login", "account", "verify", "blog"];

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

        // Includes one-char and multi-char substitutions.
        private static readonly Dictionary<string, string[]> HomoglyphMap = new(StringComparer.Ordinal)
        {
            ["0"] = ["o"],
            ["1"] = ["l", "i"],
            ["3"] = ["e"],
            ["5"] = ["s"],
            ["7"] = ["t"],
            ["8"] = ["b"],
            ["9"] = ["g"],
            ["a"] = ["4"],
            ["e"] = ["3"],
            ["i"] = ["1", "l"],
            ["l"] = ["1", "i"],
            ["m"] = ["rn"],
            ["o"] = ["0"],
            ["s"] = ["5"],
            ["w"] = ["vv"],
            ["d"] = ["cl"],
            ["rn"] = ["m"],
            ["vv"] = ["w"],
            ["cl"] = ["d"]
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

            addTyposquatting(subdomains, label, tld, variations);
            addHyphen(subdomains, label, tld, variations);
            addSubdomains(subdomains, label, tld, variations);

            // Remove the original input from output set.
            variations.Remove(normalized);

            var output = variations
                .Where(v => !string.IsNullOrWhiteSpace(v))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            var entropy = testShannonEntropy(label);

            _logger.LogInformation(
                "[DomainGeneratorService] Generated {Count} variation(s) for domain: {Domain}. ShannonEntropy={Entropy:F2}",
                output.Count, normalized, entropy);

            return output;
        }

        // Adds subdomain- and prefix-based lookalikes such as secure.example.com and secure-example.com.
        private void addSubdomains(string subdomains, string label, string tld, ISet<string> variations)
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
                    var dotPrefix = string.Join('.', prefixSequence);
                    var hyphenPrefix = string.Join('-', prefixSequence);

                    variations.Add($"{dotPrefix}.{rootDomain}");
                    variations.Add(BuildDomain(subdomains, $"{hyphenPrefix}-{label}", tld));
                    variations.Add(BuildDomain(subdomains, $"{label}-{hyphenPrefix}", tld));
                }
            }
        }

        // Inserts additional hyphens into the label, including domains that already contain hyphens.
        private void addHyphen(string subdomains, string label, string tld, ISet<string> variations)
        {
            if (label.Length < 2)
            {
                return;
            }

            var gaps = label.Length - 1;
            var created = 0;
            var maxHyphens = MaxAddedHyphens;

            for (var hyphensToInsert = 1; hyphensToInsert <= maxHyphens; hyphensToInsert++)
            {
                var distribution = new int[gaps];
                addHyphenPatterns(0, hyphensToInsert, distribution);

                if (created >= MaxHyphenVariantsPerDomain)
                {
                    break;
                }
            }

            void addHyphenPatterns(int gapIndex, int remaining, int[] distribution)
            {
                if (created >= MaxHyphenVariantsPerDomain)
                {
                    return;
                }

                if (gapIndex == gaps)
                {
                    if (remaining != 0)
                    {
                        return;
                    }

                    var mutated = BuildHyphenatedLabel(label, distribution);
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
                    addHyphenPatterns(gapIndex + 1, remaining - insertionsAtGap, distribution);

                    if (created >= MaxHyphenVariantsPerDomain)
                    {
                        break;
                    }
                }

                distribution[gapIndex] = 0;
            }
        }

        // Generates typosquatting variants via omission, duplication, adjacent keys, transposition,
        // homoglyphs, and common TLD swaps.
        private void addTyposquatting(string subdomains, string label, string tld, ISet<string> variations)
        {
            if (string.IsNullOrWhiteSpace(label) || string.IsNullOrWhiteSpace(tld))
            {
                return;
            }

            // Character omission
            if (label.Length > 1)
            {
                for (var i = 0; i < label.Length; i++)
                {
                    var omitted = label.Remove(i, 1);
                    if (!string.IsNullOrWhiteSpace(omitted))
                    {
                        variations.Add(BuildDomain(subdomains, omitted, tld));
                    }
                }
            }

            // Character duplication
            for (var i = 0; i < label.Length; i++)
            {
                var duplicated = label.Insert(i + 1, label[i].ToString());
                variations.Add(BuildDomain(subdomains, duplicated, tld));
            }

            // Character transposition
            for (var i = 0; i < label.Length - 1; i++)
            {
                if (label[i] == label[i + 1])
                {
                    continue;
                }

                var chars = label.ToCharArray();
                (chars[i], chars[i + 1]) = (chars[i + 1], chars[i]);
                variations.Add(BuildDomain(subdomains, new string(chars), tld));
            }

            // Adjacent key substitutions
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
                    variations.Add(BuildDomain(subdomains, new string(chars), tld));
                }
            }

            // Homoglyph substitutions for both one-char and multi-char keys.
            foreach (var pair in HomoglyphMap)
            {
                var search = pair.Key;
                var index = label.IndexOf(search, StringComparison.Ordinal);
                while (index >= 0)
                {
                    foreach (var replacement in pair.Value)
                    {
                        var mutated = label[..index] + replacement + label[(index + search.Length)..];
                        variations.Add(BuildDomain(subdomains, mutated, tld));
                    }

                    index = label.IndexOf(search, index + 1, StringComparison.Ordinal);
                }
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

        // Shannon entropy helper for identifying highly random labels.
        private static double testShannonEntropy(string value)
        {
            if (string.IsNullOrEmpty(value))
            {
                return 0;
            }

            var frequencies = value
                .GroupBy(ch => ch)
                .Select(group => (double)group.Count() / value.Length);

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

        private static string BuildHyphenatedLabel(string label, IReadOnlyList<int> distribution)
        {
            if (distribution.Count != label.Length - 1)
            {
                return label;
            }

            var result = new System.Text.StringBuilder();
            for (var i = 0; i < label.Length; i++)
            {
                result.Append(label[i]);
                if (i < label.Length - 1)
                {
                    var hyphenCount = distribution[i];
                    if (hyphenCount > 0)
                    {
                        result.Append('-', hyphenCount);
                    }
                }
            }

            return result.ToString();
        }

        private static IEnumerable<IReadOnlyList<string>> EnumeratePrefixSequences(int depth)
        {
            if (depth <= 0)
            {
                yield break;
            }

            var buffer = new string[depth];
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

                foreach (var prefix in SubdomainPrefixes)
                {
                    buffer[index] = prefix;
                    foreach (var item in Enumerate(index + 1))
                    {
                        yield return item;
                    }
                }
            }
        }
    }
}

