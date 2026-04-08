using System.ComponentModel.DataAnnotations;

namespace SSA_Final.ViewModels
{
    public class DomainScanViewModel
    {
        [Required(ErrorMessage = "Domain is required.")]
        [RegularExpression(
            @"^(?!:\/\/)([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$",
            ErrorMessage = "Enter a valid domain (e.g. example.com)"
        )]
        public string Domain { get; set; }
    }
}
