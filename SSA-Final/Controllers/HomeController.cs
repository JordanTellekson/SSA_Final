using Microsoft.AspNetCore.Mvc;
using SSA_Final.Models;
using System.Diagnostics;

namespace SSA_Final.Controllers
{
    /// <summary>
    /// Basic home/error controller for the public landing area.
    /// </summary>
    public class HomeController : Controller
    {
        /// <summary>
        /// Displays the landing page.
        /// </summary>
        /// <returns>Home index view.</returns>
        public IActionResult Index()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        /// <summary>
        /// Displays the shared error page with request id context.
        /// </summary>
        /// <returns>Error view model for diagnostics.</returns>
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
