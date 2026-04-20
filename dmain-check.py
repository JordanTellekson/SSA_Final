using System;
using System.Text.RegularExpressions;
using Whois.NET;

class Program
{
    static void CheckDomain(string domain)
    {
        try
        {
            WhoisResponse response = WhoisClient.Query(domain);

            string rawWhois = response.Raw;

            DateTime? creationDate = ExtractCreationDate(rawWhois);

            if (creationDate.HasValue)
            {
                DateTime created = creationDate.Value;
                int ageDays = (DateTime.Now - created).Days;

                Console.WriteLine($"Domain: {domain}");
                Console.WriteLine($"Created: {created}");
                Console.WriteLine($"Age: {ageDays} days");

                if (ageDays < 30)
                {
                    Console.WriteLine("Suspicious: Recently registered domain");
                }
                else
                {
                    Console.WriteLine("Looks normal");
                }
            }
            else
            {
                Console.WriteLine("Could not determine creation date");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error checking domain: {ex.Message}");
        }
    }

    static DateTime? ExtractCreationDate(string rawWhois)
    {
        string[] patterns =
        {
            @"Creation Date:\s*(.+)",
            @"Created On:\s*(.+)",
            @"Created:\s*(.+)",
            @"Registration Date:\s*(.+)",
            @"Domain Registration Date:\s*(.+)"
        };

        foreach (string pattern in patterns)
        {
            Match match = Regex.Match(rawWhois, pattern, RegexOptions.IgnoreCase);

            if (match.Success)
            {
                string dateText = match.Groups[1].Value.Trim();

                if (DateTime.TryParse(dateText, out DateTime date))
                {
                    return date;
                }
            }
        }

        return null;
    }

    static void Main()
    {
        CheckDomain("google.com");
    }
}
