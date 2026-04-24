using SSA_Final.Interfaces;

namespace SSA_Final.ViewModels
{
    public class PagedResultViewModel<T>
    {
        public IPagedResult<T> Result { get; set; } = default!;
        public string? Query { get; set; }
        public string Mode { get; set; } = "table";
    }
}
