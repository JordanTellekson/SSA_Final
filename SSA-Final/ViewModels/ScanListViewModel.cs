using SSA_Final.Models;

namespace SSA_Final.ViewModels
{
    public class ScanListViewModel
    {
        public IEnumerable<DomainScan> Scans { get; set; } = [];
        // "table" or "history"
        public string Mode { get; set; } = "table";
        public string? Query { get; set; }
    }
}
