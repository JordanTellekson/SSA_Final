namespace SSA_Final.Interfaces
{
    public interface IPagedResult<T> : IPagedResult
    {
        IReadOnlyList<T> Items { get; }
    }

    public interface IPagedResult
    {
        int Page { get; }
        int PageSize { get; }
        int TotalPages { get; }
        int TotalCount { get; }
    }
}
