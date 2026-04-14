using Need4AdminLight.Web.Models;

namespace Need4AdminLight.Web.Services;

public static class ReportRisk
{
    public static bool IsHighRiskUser(PrivilegedUserRecord u)
    {
        bool RoleHit(IEnumerable<string> roles) => roles.Any(r =>
            r.Contains("Global Administrator", StringComparison.OrdinalIgnoreCase) ||
            r.Contains("Privileged Role Administrator", StringComparison.OrdinalIgnoreCase) ||
            r.Contains("Application Administrator", StringComparison.OrdinalIgnoreCase) ||
            r.Contains("Cloud Application Administrator", StringComparison.OrdinalIgnoreCase));

        if (RoleHit(u.EntraActiveRoles) || RoleHit(u.EntraEligibleRoles.Select(e => e.Line)))
        {
            return true;
        }

        return false;
    }

    public static bool IsHighRiskApp(ApplicationPermissionRecord a)
    {
        foreach (var d in a.DelegatedScopes)
        {
            if (IsHighRiskGraphPermissionToken(d))
            {
                return true;
            }
        }

        foreach (var line in a.AppRolePermissions)
        {
            var perm = PermissionPartFromAppRoleLine(line);
            if (IsHighRiskGraphPermissionToken(perm) || IsHighRiskGraphPermissionToken(line))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsHighRiskGraphPermissionToken(string raw) => SensitiveApiPermissions.IsHighlightMatch(raw);

    private static string PermissionPartFromAppRoleLine(string line)
    {
        var idx = line.IndexOf(':');
        if (idx < 0)
        {
            return line.Trim();
        }

        return line[(idx + 1)..].Trim();
    }

    public static List<string> AnalyzePrivilegedUsers(IReadOnlyList<PrivilegedUserRecord> users)
    {
        var recs = new List<string>();
        recs.Add("Stale account means no interactive and non-interactive sign-ins in the last 90 days (or never).");

        if (users.Count == 0)
        {
            return recs;
        }

        var activeNoMfa = users.Count(u => u.AccountEnabled && !u.MfaEnabled);
        if (activeNoMfa > 0)
        {
            recs.Add($"Enroll MFA for {activeNoMfa} active privileged user(s) without MFA.");
        }

        var noPhish = users.Count(u => u.AccountEnabled && u.MfaEnabled && !u.HasPhishingResistantMethod);
        if (noPhish > 0)
        {
            recs.Add("Consider to require FIDO2 methods for your administrator accounts with Conditional Access.");
        }

        var globalAdmins = users.Count(u =>
            u.EntraActiveRoles.Concat(u.EntraEligibleRoles.Select(e => e.Line)).Any(r =>
                r.Contains("Global Administrator", StringComparison.OrdinalIgnoreCase)));
        if (globalAdmins > 5)
        {
            recs.Add($"Reduce Global Administrator assignments (currently {globalAdmins} privileged user rows).");
        }
        else if (globalAdmins > 0)
        {
            recs.Add("Review Global Administrator assignments and use Privileged Identity Management where possible.");
        }

        return recs;
    }

    /// <summary>Short guidance for Need4Admin Light (no eligible/PIM-eligibility columns).</summary>
    public static List<string> AnalyzePrivilegedUsersLight(IReadOnlyList<PrivilegedUserRecord> users)
    {
        var recs = new List<string>
        {
            "Eligible directory roles, Azure RBAC, roles assigned via PIM groups, PIM group expiration, and other advanced fields are not shown here — use the Need4Admin PowerShell script on GitHub.",
            "MFA Yes/No is derived from registered authentication methods (not Conditional Access policy state alone)."
        };

        if (users.Count == 0)
        {
            return recs;
        }

        var activeNoMfa = users.Count(u => u.AccountEnabled && !u.MfaEnabled);
        if (activeNoMfa > 0)
        {
            recs.Add($"Enroll MFA for {activeNoMfa} active privileged user(s) with MFA = No.");
        }

        var globalAdmins = users.Count(u =>
            u.EntraActiveRoles.Any(r => r.Contains("Global Administrator", StringComparison.OrdinalIgnoreCase)));
        if (globalAdmins > 5)
        {
            recs.Add($"Reduce Global Administrator assignments (currently {globalAdmins} user rows in this report).");
        }
        else if (globalAdmins > 0)
        {
            recs.Add("Review Global Administrator assignments; prefer just-in-time access where your process allows.");
        }

        return recs;
    }

    public static List<string> AnalyzeApplications(IReadOnlyList<ApplicationPermissionRecord> apps)
    {
        var recs = new List<string>();
        var high = apps.Count(IsHighRiskApp);
        if (high > 0)
        {
            recs.Add($"{high} application(s) use one or more high-risk Microsoft Graph permissions — review admin consent and least privilege.");
        }

        var manyDelegated = apps.Count(a => a.DelegatedScopes.Count > 15);
        if (manyDelegated > 0)
        {
            recs.Add($"{manyDelegated} app(s) have broad delegated scope sets.");
        }

        var staleInSample = apps.Count(a => a.IsStaleApp);
        if (staleInSample > 0)
        {
            recs.Add($"{staleInSample} app(s) have no recorded sign-in or last sign-in older than 90 days — review or retire unused apps.");
        }

        var notInSample = apps.Count(a => !a.SignInSeenInAuditSample);
        if (notInSample > 0)
        {
            recs.Add($"{notInSample} app(s) have no sign-in timestamp in the activity report — confirm in Entra sign-in logs if needed.");
        }

        return recs;
    }

    /// <summary>Applications report copy for Need4Admin Light (no secrets/owners/consent columns).</summary>
    public static List<string> AnalyzeApplicationsLight(IReadOnlyList<ApplicationPermissionRecord> apps)
    {
        var recs = new List<string>
        {
            "Client secrets, certificates, owners, consent type, last modified, and similar registration details are not in this web view — use the Need4Admin PowerShell script for those columns."
        };

        var high = apps.Count(IsHighRiskApp);
        if (high > 0)
        {
            recs.Add($"{high} application(s) declare high-risk Microsoft Graph permissions — review admin consent and least privilege.");
        }

        var manyDelegated = apps.Count(a => a.DelegatedScopes.Count > 15);
        if (manyDelegated > 0)
        {
            recs.Add($"{manyDelegated} app(s) have large delegated scope sets — consider narrowing permissions.");
        }

        return recs;
    }

}
