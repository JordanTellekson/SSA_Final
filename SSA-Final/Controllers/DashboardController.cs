using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace SSA_Final.Controllers
{
    public class DashboardController : Controller
    {
        public ActionResult Index()
        {
            return View();
        }
    }
}
