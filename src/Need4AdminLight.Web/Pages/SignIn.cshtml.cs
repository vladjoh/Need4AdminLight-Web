using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Need4AdminLight.Web.Pages;

[AllowAnonymous]
public class SignInModel(IConfiguration configuration) : PageModel
{
    public string ClientId { get; private set; } = "";
    public string Authority { get; private set; } = "";
    public string RedirectUri { get; private set; } = "";
    public string ScopesJson { get; private set; } = "[]";

    public void OnGet()
    {
        var azure = configuration.GetSection("AzureAd");
        ClientId = azure["ClientId"] ?? "";
        var tenant = AuthConstants.TenantSegment(azure);
        Authority = $"https://login.microsoftonline.com/{tenant}";
        var callbackPath = azure["CallbackPath"] ?? "/signin-callback";
        RedirectUri = $"{Request.Scheme}://{Request.Host}{callbackPath}";
        var scopes = AuthConstants.GraphDelegatedScopes.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        ScopesJson = JsonSerializer.Serialize(scopes);
    }
}
