namespace SSA_Final.Models
{
    /// <summary>
    /// View model used by the shared error page.
    /// </summary>
    public class ErrorViewModel
    {
        /// <summary>
        /// Request trace identifier shown to aid troubleshooting.
        /// </summary>
        public string? RequestId { get; set; }

        /// <summary>
        /// Indicates whether the request id should be displayed.
        /// </summary>
        public bool ShowRequestId => !string.IsNullOrEmpty(RequestId);
    }
}
