using SSA_Final.Interfaces;
using SSA_Final.Models;

namespace SSA_Final.ViewModels
{
    public class PagedResultViewModel<T>
    {
        public IPagedResult<T> Result { get; set; } = default!;
        public string? Query { get; set; }
        public string ViewType { get; set; } = "table";
    }
}
