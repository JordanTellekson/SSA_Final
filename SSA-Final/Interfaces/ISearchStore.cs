// File: ISearchStore.cs
// Purpose: Defines project behavior and data flow for phishing-domain analysis and reporting.

using Microsoft.CodeAnalysis.Elfie.Diagnostics;
using SSA_Final.Models;

namespace SSA_Final.Interfaces
{
    public interface ISearchService
    {
        IEnumerable<(DomainScan Item, int Score)> Search(
            IEnumerable<DomainScan> source,
            string? query);
    }
}
