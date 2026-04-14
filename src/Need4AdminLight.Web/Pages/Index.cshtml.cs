using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;

namespace Need4AdminLight.Web.Pages;

public class IndexModel(IOptions<Need4AdminOptions> need4AdminOptions) : PageModel
{
    public string ProductName => need4AdminOptions.Value.ProductName;

    public void OnGet()
    {
        ViewData["Title"] = ProductName;
    }
}
