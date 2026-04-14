namespace Need4AdminLight.Web;

/// <summary>OAuth / MSAL settings shared by Program.cs and sign-in pages.</summary>
public static class AuthConstants
{
    /// <summary>Delegated scopes requested in the browser (MSAL) — same set as former server-side OAuth.</summary>
    public const string GraphDelegatedScopes =
        "openid User.Read User.Read.All Directory.Read.All RoleManagement.Read.Directory RoleAssignmentSchedule.Read.Directory Application.Read.All";

    public static string TenantSegment(IConfigurationSection azureAd)
    {
        var t = (azureAd["TenantId"] ?? "organizations").Trim();
        if (t.Equals("common", StringComparison.OrdinalIgnoreCase) ||
            t.Equals("organizations", StringComparison.OrdinalIgnoreCase))
        {
            return "organizations";
        }

        return t;
    }
}
