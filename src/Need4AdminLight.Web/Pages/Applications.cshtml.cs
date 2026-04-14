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
public class ApplicationsModel(
    GraphAuditService graphAuditService,
    IMemoryCache cache) : PageModel
{
    public List<ApplicationPermissionRecord> Applications { get; private set; } = [];
    public string? ErrorMessage { get; private set; }

    public async Task OnGetAsync([FromQuery] string? reuse = null, CancellationToken cancellationToken = default)
    {
        var userKey = User.FindFirstValue(ClaimTypes.Name) ?? User.Identity?.Name ?? "anon";
        var cacheKey = $"n4al:applications:{userKey}";
        if (IsReuseReportQuery(reuse) && cache.TryGetValue(cacheKey, out CachedApplicationsReport? cached) && cached is not null)
        {
            Applications = cached.Applications;
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
            var apps = await graphAuditService.GetApplicationsAsync(graphToken, cancellationToken);
            Applications = apps
                .OrderByDescending(ReportRisk.IsHighRiskApp)
                .ThenBy(a => a.DisplayName, StringComparer.OrdinalIgnoreCase)
                .ToList();
            cache.Set(cacheKey, new CachedApplicationsReport(Applications), TimeSpan.FromMinutes(60));
        }
        catch (Exception ex)
        {
            ErrorMessage = ex.Message;
        }
    }

    private sealed record CachedApplicationsReport(List<ApplicationPermissionRecord> Applications);

    private static bool IsReuseReportQuery(string? reuse) =>
        string.Equals(reuse, "1", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(reuse, "true", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(reuse, "yes", StringComparison.OrdinalIgnoreCase);
}
