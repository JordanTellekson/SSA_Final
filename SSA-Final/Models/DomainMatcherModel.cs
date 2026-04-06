using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace SSA_Final.Models
{
    // Model-only service for domain allow-list matching and phishing-risk signal scoring.
    public class DomainMatcherModel
    {
        public string DomainsFilePath { get; }

        private readonly Lazy<HashSet<string>> _activeDomains;
        private readonly Lazy<List<string>> _activeRootDomains;

        public DomainMatcherModel(string? domainsFilePath = null)
        {
            DomainsFilePath = domainsFilePath ?? Path.Combine(Directory.GetCurrentDirectory(), "Active_Domains.txt");
            _activeDomains = new Lazy<HashSet<string>>(LoadDomains);
            _activeRootDomains = new Lazy<List<string>>(() =>
                _activeDomains.Value
                    .Select(GetRootDomainLabel)
                    .Where(root => !string.IsNullOrWhiteSpace(root))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList());
        }

        public bool IsMatch(string? manualDomainInput)
        {
            var normalizedInput = NormalizeDomain(manualDomainInput);
            if (string.IsNullOrWhiteSpace(normalizedInput))
            {
                return false;
            }

            return _activeDomains.Value.Contains(normalizedInput);
        }

        public DomainRiskAnalysisResult AnalyzeDomainRisk(string? manualDomainInput)
        {
            var normalizedInput = NormalizeDomain(manualDomainInput);
            if (string.IsNullOrWhiteSpace(normalizedInput))
            {
                return DomainRiskAnalysisResult.InvalidInput();
            }

            // If this is in the trusted active-domain list, skip phishing scoring.
            if (_activeDomains.Value.Contains(normalizedInput))
            {
                return DomainRiskAnalysisResult.ForKnownActiveDomain(normalizedInput);
            }

            var typosquatting = CalculateTyposquattingScore(normalizedInput);
            var subdomains = CalculateSubdomainScore(normalizedInput);
            var hyphen = CalculateHyphenScore(normalizedInput);
            var entropy = CalculateEntropyScore(normalizedInput);

            var overallRisk = typosquatting.Score + subdomains.Score + hyphen.Score + entropy.Score;

            return new DomainRiskAnalysisResult(
                normalizedInput,
                isKnownActiveDomain: false,
                isValidDomain: true,
                overallRiskScore: overallRisk,
                typosquatting,
                subdomains,
                hyphen,
                entropy);
        }

        private HashSet<string> LoadDomains()
        {
            if (!File.Exists(DomainsFilePath))
            {
                throw new FileNotFoundException("Could not find Active_Domains.txt.", DomainsFilePath);
            }

            var domains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var line in File.ReadLines(DomainsFilePath))
            {
                var normalized = NormalizeDomain(line);
                if (!string.IsNullOrWhiteSpace(normalized))
                {
                    domains.Add(normalized);
                }
            }

            return domains;
        }

        private DomainRiskSignalScore CalculateTyposquattingScore(string normalizedInput)
        {
            var inputRoot = GetRootDomainLabel(normalizedInput);
            if (string.IsNullOrWhiteSpace(inputRoot))
            {
                return new DomainRiskSignalScore("Typosquatting/Edit Distance", 0, false, "Could not determine root label.");
            }

            var closest = string.Empty;
            var minDistance = int.MaxValue;

            foreach (var candidateRoot in _activeRootDomains.Value)
            {
                // Quick length gate: if lengths differ too much, edit distance <= 3 is impossible.
                if (Math.Abs(candidateRoot.Length - inputRoot.Length) > 3)
                {
                    continue;
                }

                var distance = CalculateLevenshteinDistance(inputRoot, candidateRoot, 3);
                if (distance < minDistance)
                {
                    minDistance = distance;
                    closest = candidateRoot;
                }

                if (minDistance == 0)
                {
                    break;
                }
            }

            var score = minDistance switch
            {
                // Higher score when one or two edits away from a known root (common typosquatting pattern).
                1 => 25,
                2 => 18,
                3 => 10,
                _ => 0
            };

            var triggered = score > 0;
            var detail = triggered
                ? $"Closest known root '{closest}' has edit distance {minDistance}."
                : "No close root-domain typosquatting pattern detected.";

            return new DomainRiskSignalScore("Typosquatting/Edit Distance", score, triggered, detail);
        }

        private static DomainRiskSignalScore CalculateSubdomainScore(string normalizedInput)
        {
            var labels = normalizedInput.Split('.', StringSplitOptions.RemoveEmptyEntries);
            // Approximation: treat the last two labels as base domain + TLD.
            var subdomainCount = Math.Max(labels.Length - 2, 0);

            var score = subdomainCount switch
            {
                <= 1 => 0,
                2 => 8,
                3 => 16,
                _ => 25
            };

            return new DomainRiskSignalScore(
                "Excessive Subdomains",
                score,
                score > 0,
                $"Detected {subdomainCount} subdomain label(s).");
        }

        private static DomainRiskSignalScore CalculateHyphenScore(string normalizedInput)
        {
            var hyphenCount = normalizedInput.Count(c => c == '-');
            var score = hyphenCount switch
            {
                0 => 0,
                1 => 6,
                2 => 12,
                3 => 18,
                _ => 25
            };

            if (normalizedInput.Contains("--", StringComparison.Ordinal))
            {
                score = Math.Min(25, score + 4);
            }

            return new DomainRiskSignalScore(
                "Hyphen Abuse",
                score,
                score > 0,
                $"Detected {hyphenCount} hyphen(s) in the domain.");
        }

        private static DomainRiskSignalScore CalculateEntropyScore(string normalizedInput)
        {
            // Entropy is based on alphanumeric characters only to reduce punctuation noise.
            var sample = new string(normalizedInput.Where(char.IsLetterOrDigit).ToArray());
            var entropy = CalculateShannonEntropy(sample);

            var score = entropy switch
            {
                < 3.0 => 0,
                < 3.4 => 8,
                < 3.8 => 16,
                _ => 25
            };

            var labels = normalizedInput.Split('.', StringSplitOptions.RemoveEmptyEntries);
            var longestLabel = labels.Length == 0 ? 0 : labels.Max(label => label.Length);
            // Long, high-entropy labels are more likely to be algorithmically generated.
            if (longestLabel >= 15 && entropy >= 3.5)
            {
                score = Math.Min(25, score + 4);
            }

            return new DomainRiskSignalScore(
                "Shannon Entropy",
                score,
                score > 0,
                $"Calculated entropy is {entropy:F2}.");
        }

        private static string GetRootDomainLabel(string normalizedDomain)
        {
            var labels = normalizedDomain.Split('.', StringSplitOptions.RemoveEmptyEntries);
            if (labels.Length == 0)
            {
                return string.Empty;
            }

            if (labels.Length == 1)
            {
                return labels[0].ToLowerInvariant();
            }

            return labels[^2].ToLowerInvariant();
        }

        private static int CalculateLevenshteinDistance(string a, string b, int maxDistance)
        {
            if (Math.Abs(a.Length - b.Length) > maxDistance)
            {
                // Early exit keeps comparisons fast on large allow-lists.
                return maxDistance + 1;
            }

            var previous = new int[b.Length + 1];
            var current = new int[b.Length + 1];

            for (var j = 0; j <= b.Length; j++)
            {
                previous[j] = j;
            }

            for (var i = 1; i <= a.Length; i++)
            {
                current[0] = i;
                var rowMin = current[0];

                for (var j = 1; j <= b.Length; j++)
                {
                    var cost = a[i - 1] == b[j - 1] ? 0 : 1;
                    current[j] = Math.Min(
                        Math.Min(current[j - 1] + 1, previous[j] + 1),
                        previous[j - 1] + cost);
                    rowMin = Math.Min(rowMin, current[j]);
                }

                if (rowMin > maxDistance)
                {
                    // Stop once this row can no longer recover below the configured threshold.
                    return maxDistance + 1;
                }

                (previous, current) = (current, previous);
            }

            return previous[b.Length];
        }

        private static double CalculateShannonEntropy(string input)
        {
            if (string.IsNullOrEmpty(input))
            {
                return 0;
            }

            var characterCounts = new Dictionary<char, int>();
            foreach (var c in input)
            {
                characterCounts[c] = characterCounts.TryGetValue(c, out var count) ? count + 1 : 1;
            }

            var length = input.Length;
            double entropy = 0;

            foreach (var count in characterCounts.Values)
            {
                var p = (double)count / length;
                entropy -= p * Math.Log2(p);
            }

            return entropy;
        }

        private static string? NormalizeDomain(string? rawDomain)
        {
            if (string.IsNullOrWhiteSpace(rawDomain))
            {
                return null;
            }

            var value = rawDomain.Trim();

            if (!value.Contains("://", StringComparison.Ordinal))
            {
                // Allow plain host input (for example: "example.com") by adding a temporary scheme.
                value = "http://" + value;
            }

            if (!Uri.TryCreate(value, UriKind.Absolute, out var uri))
            {
                return null;
            }

            var host = uri.Host.Trim().TrimEnd('.');
            if (host.StartsWith("www.", StringComparison.OrdinalIgnoreCase))
            {
                host = host[4..];
            }

            return string.IsNullOrWhiteSpace(host) ? null : host.ToLowerInvariant();
        }
    }
}
