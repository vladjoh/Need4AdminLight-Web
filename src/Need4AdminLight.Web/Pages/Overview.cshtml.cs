using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Need4AdminLight.Web.Pages;

[Authorize]
public class OverviewModel : PageModel
{
    public void OnGet()
    {
    }
}
