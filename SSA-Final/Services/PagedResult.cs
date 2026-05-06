// File: PagedResult.cs
// Purpose: Defines project behavior and data flow for phishing-domain analysis and reporting.

using SSA_Final.Interfaces;

namespace SSA_Final.Services
{
    public class PagedResult<T> : IPagedResult<T>
    {
        public IReadOnlyList<T> Items { get; init; } = [];
        public int TotalCount { get; init; }
        public int Page { get; init; }
        public int PageSize { get; init; }
        public int TotalPages => (int)Math.Ceiling((double)TotalCount / PageSize);
    }
}
