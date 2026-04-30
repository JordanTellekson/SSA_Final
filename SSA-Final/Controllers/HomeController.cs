// MVC controller for public landing and global error pages.
// Keeps non-authenticated entry points separate from scan workflows.

using Microsoft.AspNetCore.Mvc;
using SSA_Final.Models;
using System.Diagnostics;

namespace SSA_Final.Controllers
{
    public class HomeController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}


