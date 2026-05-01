// File: SearchService.cs
// Purpose: Defines project behavior and data flow for phishing-domain analysis and reporting.

using SSA_Final.Interfaces;
using SSA_Final.Models;
using System.Globalization;
using System.Text;

namespace SSA_Final.Services
{
    public class SearchService : ISearchService
    {
        public IEnumerable<(DomainScan Item, int Score)> Search(
            IEnumerable<DomainScan> source,
            string? query)
        {
            if (string.IsNullOrWhiteSpace(query))
                return source.Select(x => (x, 0));

            var normalizedQuery = Normalize(query);
            var queryTokens = Tokenize(normalizedQuery);

            return source
                .Select(scan =>
                {
                    var normalizedBase = Normalize(scan.BaseDomain);
                    var domainTokens = Tokenize(normalizedBase);

                    int score = ScoreDomain(domainTokens, queryTokens);

                    if (normalizedBase == normalizedQuery)
                        score += 200;

                    foreach (var variant in scan.Variants)
                    {
                        var variantNormalized = Normalize(variant.DiscoveredDomain);
                        var variantTokens = Tokenize(variantNormalized);

                        score += ScoreDomain(variantTokens, queryTokens) / 2;
                    }

                    return (scan, score);
                })
                .Where(x => x.score > 0);
        }

        private static int ScoreDomain(string[] domainTokens, string[] queryTokens)
        {
            int score = 0;

            foreach (var q in queryTokens)
            {
                var prefix = q.Length >= 4 ? q[..3] : null;

                foreach (var d in domainTokens)
                {
                    if (d == q)
                        score += 100;
                    else if (d.StartsWith(q))
                        score += 60;
                    else if (d.Contains(q))
                        score += 30;
                    else if (prefix != null && d.StartsWith(prefix))
                        score += 15;
                }
            }

            var joined = string.Join("", domainTokens);
            var queryJoined = string.Join("", queryTokens);

            if (joined.Contains(queryJoined))
                score += 40;

            score -= domainTokens.Length * 5;

            return score;
        }

        private static string Normalize(string input)
        {
            if (string.IsNullOrWhiteSpace(input))
                return string.Empty;

            input = input.ToLowerInvariant().Trim();

            input = input
                .Replace("https://", "")
                .Replace("http://", "")
                .Replace("www.", "");

            var slashIndex = input.IndexOf('/');
            if (slashIndex >= 0)
                input = input.Substring(0, slashIndex);

            var colonIndex = input.IndexOf(':');
            if (colonIndex >= 0)
                input = input.Substring(0, colonIndex);

            var normalized = input.Normalize(NormalizationForm.FormD);
            var sb = new StringBuilder();

            foreach (var c in normalized)
            {
                if (CharUnicodeInfo.GetUnicodeCategory(c) != UnicodeCategory.NonSpacingMark)
                    sb.Append(c);
            }

            return sb.ToString().Normalize(NormalizationForm.FormC);
        }

        private static string[] Tokenize(string input)
        {
            return input.Split(
                ['.', '-', '_', '/', '?', '&', '=', ':'],
                StringSplitOptions.RemoveEmptyEntries);
        }
    }
}
