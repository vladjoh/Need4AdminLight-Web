namespace Need4AdminLight.Web.Models;

/// <summary>One Azure RBAC assignment (active or PIM-eligible) with scope detail for drill-down.</summary>
public sealed class AzureRoleLine
{
    public string RoleName { get; init; } = string.Empty;
    public string ScopeDetail { get; init; } = string.Empty;
    public bool ViaGroup { get; init; }
    /// <summary>Microsoft Entra group display name when <see cref="ViaGroup"/> is true.</summary>
    public string? GroupDisplayName { get; init; }
    /// <summary>Raw ARM scope path for parsing subscription / RG / resource in the UI.</summary>
    public string? ArmScopePath { get; init; }
    /// <summary>True when this line comes only from permanent ARM roleAssignments (not PIM schedule instances).</summary>
    public bool FromPermanentArmRbac { get; init; }
    /// <summary>For Azure <em>eligible</em> rows: value after &quot;Expires: &quot; in the report (&quot;Never&quot;, UTC timestamp, or &quot;Unknown&quot;). Null/empty for active-only rows.</summary>
    public string? EligibleExpiresDisplay { get; init; }
}

/// <summary>Entra directory role PIM eligibility with optional expiration line for the report.</summary>
public sealed class EntraEligibleRoleLine
{
    /// <summary>Full display line: role name or <c>Role (via group: Name)</c>.</summary>
    public string Line { get; init; } = string.Empty;
    /// <summary>Shown as <c>Expires: …</c> (&quot;Never&quot;, UTC timestamp, or &quot;Unknown&quot;).</summary>
    public string ExpiresDisplay { get; init; } = "Never";
    /// <summary>Merge key (<c>roleDefinitionId</c> + directory scope + via-group); avoids collapsing distinct PIM rows that share the same display name.</summary>
    public string DedupeKey { get; init; } = string.Empty;
}

public sealed class PrivilegedUserRecord
{
    public string UserId { get; init; } = string.Empty;
    public string UserPrincipalName { get; init; } = string.Empty;
    public string DisplayName { get; init; } = string.Empty;
    public bool AccountEnabled { get; init; }
    public string UserType { get; init; } = "Unknown";
    public List<string> EntraActiveRoles { get; init; } = [];
    public List<EntraEligibleRoleLine> EntraEligibleRoles { get; init; } = [];
    public List<AzureRoleLine> AzureActiveRoles { get; init; } = [];
    public List<AzureRoleLine> AzureEligibleRoles { get; init; } = [];
    /// <summary>Distinct Entra group display names implicated in directory-role or PIM eligibility via group.</summary>
    public List<string> EntraPimGroupNames { get; init; } = [];
    /// <summary>Distinct Azure RBAC group principal display names for group-based assignments.</summary>
    public List<string> AzurePimGroupNames { get; init; } = [];
    public string LastInteractiveSignIn { get; init; } = "Never";
    public string LastNonInteractiveSignIn { get; init; } = "Never";
    public bool IsStaleAccount { get; init; }
    public List<string> AuthMethods { get; init; } = [];
    public bool MfaEnabled { get; init; }
    public bool HasPhishingResistantMethod { get; init; }
}

public sealed class ApplicationPermissionRecord
{
    public string ServicePrincipalId { get; init; } = string.Empty;
    public string DisplayName { get; init; } = string.Empty;
    public string AppId { get; init; } = string.Empty;
    /// <summary>Enterprise app (service principal) <c>accountEnabled</c>; when unknown, treated as enabled.</summary>
    public bool AccountEnabled { get; init; } = true;
    /// <summary>True when this app appeared in the batched audit sign-in query (not proof of absence if false).</summary>
    public bool SignInSeenInAuditSample { get; init; }
    /// <summary>Most recent service principal sign-in from the audit sample (UTC).</summary>
    public DateTime? MostRecentSignInUtc { get; init; }
    /// <summary>Same as most recent sign-in; surfaced as &quot;Last used&quot; for Entra-style reporting.</summary>
    public DateTime? LastUsedUtc { get; init; }
    /// <summary>Latest <c>lastModifiedDateTime</c> from the app registration or the enterprise app (service principal), or enterprise <c>createdDateTime</c> when Graph does not return modified.</summary>
    public DateTime? ApplicationLastModifiedUtc { get; init; }
    /// <summary>True when <see cref="ApplicationLastModifiedUtc"/> falls back to enterprise app <c>createdDateTime</c> (no modified timestamps from Graph).</summary>
    public bool ApplicationLastModifiedIsCreatedFallback { get; init; }
    /// <summary>Enterprise app (service principal) <c>createdDateTime</c> in this tenant (UTC).</summary>
    public DateTime? EnterpriseAppCreatedUtc { get; init; }
    public string LastInteractiveSignIn { get; init; } = "Never";
    public string LastNonInteractiveSignIn { get; init; } = "Never";
    public DateTime? LastInteractiveSignInUtc { get; init; }
    public DateTime? LastNonInteractiveSignInUtc { get; init; }
    /// <summary>
    /// Short label from the newest sign-in audit log row sampled for this app (clientCredentialType / signInEventTypes / isInteractive).
    /// Tenant-wide audit is page-limited — use Entra sign-in logs for authoritative history.
    /// </summary>
    public string LatestAuditSignInMethodSummary { get; init; } = "—";
    /// <summary>Stale when seen in audit sample and latest sign-in is 90+ days ago or never in sample window.</summary>
    public bool IsStaleApp { get; init; }
    public bool HasKeyCredential { get; init; }
    public bool HasPasswordCredential { get; init; }
    /// <summary>Display lines for app registration or service principal owners.</summary>
    public List<string> OwnerDisplayLines { get; init; } = [];
    /// <summary>Admin, User, Mixed, or — (no consent data).</summary>
    public string ConsentTypeSummary { get; init; } = "—";
    public bool HasFederatedCredentials { get; init; }
    public bool ClientSecretExpired { get; init; }
    public bool CertificateExpired { get; init; }
    /// <summary>Earliest secret <c>endDateTime</c> from app registration (UTC).</summary>
    public DateTime? ClientSecretExpiresUtc { get; init; }
    /// <summary>Earliest key credential <c>endDateTime</c> from app registration (UTC).</summary>
    public DateTime? CertificateExpiresUtc { get; init; }
    /// <summary>Application (app-only) or tenant-wide delegated consent (AllPrincipals).</summary>
    public bool HasAdminConsentPath { get; init; }
    /// <summary>User-delegated consent (Principal) with delegated scopes.</summary>
    public bool HasUserConsentPath { get; init; }
    public List<string> AppRolePermissions { get; init; } = [];
    public List<string> DelegatedScopes { get; init; } = [];
}
