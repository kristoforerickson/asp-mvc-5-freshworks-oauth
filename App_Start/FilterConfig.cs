using System.Web;
using System.Web.Mvc;

namespace asp_mvc_5_freshworks_oauth
{
    public class FilterConfig
    {
        public static void RegisterGlobalFilters(GlobalFilterCollection filters)
        {
            filters.Add(new HandleErrorAttribute());
        }
    }
}
