// File: DomainScanViewModel.cs
// Purpose: Defines project behavior and data flow for phishing-domain analysis and reporting.

using System.ComponentModel.DataAnnotations;
using SSA_Final.Models;

namespace SSA_Final.ViewModels
{
    public class DomainScanViewModel
    {
        [Required(ErrorMessage = "Domain is required.")]
        [RegularExpression(
            @"^(?!:\/\/)([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$",
            ErrorMessage = "Enter a valid domain (e.g. example.com)"
        )]
        public string Domain { get; set; } = string.Empty;

        /// <summary>
        /// Aggregated scan statistics populated by the GET action.
        /// Null-safe — the view renders the stats strip only when this is populated.
        /// </summary>
        public ScanStats? Stats { get; set; }
    }
}
