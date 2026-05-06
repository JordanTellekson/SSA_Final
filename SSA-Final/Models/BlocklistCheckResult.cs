// Result model for phishing blocklist lookup responses.

namespace SSA_Final.Models
{
    public class BlocklistCheckResult
    {
        public bool IsMatch { get; set; }
        public string Source { get; set; }
        public DateTime LastUpdated { get; set; }
        public bool IsStale { get; set; }
    }
}


