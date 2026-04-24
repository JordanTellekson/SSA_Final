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
            var queryTokens = normalizedQuery
                .Split(' ', StringSplitOptions.RemoveEmptyEntries);

            return source
                .Select(scan =>
                {
                    var baseDomain = Normalize(scan.BaseDomain);
                    var domainTokens = baseDomain
                        .Split(' ', StringSplitOptions.RemoveEmptyEntries);

                    int score = ScoreDomain(domainTokens, queryTokens);

                    return (scan, score);
                })
                .Where(x => x.score > 0)
                .OrderByDescending(x => x.score);
        }

        private static int ScoreDomain(string[] domainTokens, string[] queryTokens)
        {
            int score = 0;

            foreach (var q in queryTokens)
            {
                foreach (var d in domainTokens)
                {
                    if (d == q)
                    {
                        score += 100; // exact match
                    }
                    else if (d.StartsWith(q))
                    {
                        score += 60; // prefix match
                    }
                    else if (d.Contains(q))
                    {
                        score += 30; // contains match
                    }
                    else if (q.Length >= 4 && d.Contains(q.Substring(0, 3)))
                    {
                        score += 10; // weak fallback
                    }
                }
            }

            // small boost if whole query appears anywhere
            var joined = string.Join(" ", domainTokens);
            if (joined.Contains(string.Join(" ", queryTokens)))
            {
                score += 40;
            }

            return score;
        }

        private static string Normalize(string input)
        {
            if (string.IsNullOrWhiteSpace(input))
                return string.Empty;

            var normalized = input.Normalize(NormalizationForm.FormD);
            var sb = new StringBuilder();

            foreach (var c in normalized)
            {
                var uc = CharUnicodeInfo.GetUnicodeCategory(c);
                if (uc != UnicodeCategory.NonSpacingMark)
                    sb.Append(c);
            }

            return sb.ToString()
                .Normalize(NormalizationForm.FormC)
                .ToLowerInvariant()
                .Replace("https://", "")
                .Replace("http://", "")
                .Replace("www.", "")
                .Trim();
        }
    }
}
