using System.ComponentModel.DataAnnotations;

namespace SSA_Final.ViewModels
{
    /// <summary>
    /// Form model for collecting a base domain to scan.
    /// </summary>
    public class DomainScanViewModel
    {
        /// <summary>
        /// User-entered base domain in host format (for example, <c>example.com</c>).
        /// </summary>
        [Required(ErrorMessage = "Domain is required.")]
        [RegularExpression(
            @"^(?!:\/\/)([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$",
            ErrorMessage = "Enter a valid domain (e.g. example.com)"
        )]
        public string Domain { get; set; } = string.Empty;
    }
}
