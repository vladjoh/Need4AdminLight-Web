using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Need4AdminLight.Web.Models;
using Need4AdminLight.Web.Services;
using System.Security.Claims;

namespace Need4AdminLight.Web.Pages;

[Authorize]
public class PrivilegedUsersModel(
    GraphAuditService graphAuditService,
    IMemoryCache cache) : PageModel
{
    public List<PrivilegedUserRecord> Users { get; private set; } = [];
    public string? ErrorMessage { get; private set; }

    public async Task OnGetAsync([FromQuery] string? reuse = null, CancellationToken cancellationToken = default)
    {
        var userKey = User.FindFirstValue(ClaimTypes.Name) ?? User.Identity?.Name ?? "anon";
        var cacheKey = $"n4al:privileged:{userKey}";
        if (IsReuseReportQuery(reuse) && cache.TryGetValue(cacheKey, out CachedPrivilegedReport? cached) && cached is not null)
        {
            Users = cached.Users;
            return;
        }

        var graphToken = await HttpContext.GetTokenAsync("access_token");
        if (string.IsNullOrWhiteSpace(graphToken))
        {
            ErrorMessage = "No Graph access token found in this session. Sign out and sign in again.";
            return;
        }

        try
        {
            var users = await graphAuditService.GetPrivilegedUsersAsync(graphToken, armAccessToken: null, cancellationToken);
            Users = users
                .OrderByDescending(ReportRisk.IsHighRiskUser)
                .ThenBy(u => u.UserPrincipalName, StringComparer.OrdinalIgnoreCase)
                .ToList();
            cache.Set(cacheKey, new CachedPrivilegedReport(Users), TimeSpan.FromMinutes(60));
        }
        catch (Exception ex)
        {
            ErrorMessage = ex.Message;
        }
    }

    private sealed record CachedPrivilegedReport(List<PrivilegedUserRecord> Users);

    /// <summary>Query <c>reuse=1</c> does not bind to <see cref="bool"/> (TryParse rejects "1"); parse explicitly.</summary>
    private static bool IsReuseReportQuery(string? reuse) =>
        string.Equals(reuse, "1", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(reuse, "true", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(reuse, "yes", StringComparison.OrdinalIgnoreCase);
}
