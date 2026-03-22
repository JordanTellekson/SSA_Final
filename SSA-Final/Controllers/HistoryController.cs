using Microsoft.AspNetCore.Mvc;

namespace SSA_Final.Controllers
{
    public class HistoryController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
    }
}
