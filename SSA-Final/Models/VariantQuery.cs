// File: VariantQuery.cs
// Purpose: Defines project behavior and data flow for phishing-domain analysis and reporting.

namespace SSA_Final.Models
{
    public class VariantQuery
    {
        public string? Query { get; set; }
        public int Page { get; set; } = 1;
        public int PageSize { get; set; } = 25;
    }
}
