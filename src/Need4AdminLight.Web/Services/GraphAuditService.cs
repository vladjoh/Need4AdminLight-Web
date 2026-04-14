using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading;
using Need4AdminLight.Web.Models;

namespace Need4AdminLight.Web.Services;

public sealed class GraphAuditService(HttpClient httpClient)
{
    /// <summary>This assembly is the Light SKU only: Microsoft Graph only (Entra directory roles; no Azure RBAC / ARM).</summary>
    private static bool IsLightweight() => true;

    /// <summary>Built-in Entra directory role templateId → display name when Graph omits displayName on PIM schedule/instance payloads.</summary>
    private static readonly Dictionary<string, string> EntraBuiltInRoleDisplayByTemplateId = new(StringComparer.OrdinalIgnoreCase)
    {
        // https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference
        ["f2ef992c-3afb-46b9-b7cf-a126ee74c451"] = "Global Reader",
        ["5d6b6bb7-de71-4623-b4af-96380a352509"] = "Security Reader",
    };

    /// <summary>resource SP id -> (appRole id string -> display label).</summary>
    private readonly ConcurrentDictionary<string, Lazy<Task<Dictionary<string, string>>>> _resourceAppRoleLookup = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, string> _azureRoleNameCache = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, string?> _graphGroupDisplayCache = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, string> _entraDirectoryRoleDisplayByDefinitionId = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Per <see cref="GetPrivilegedUsersAsync"/> request: all directory roleDefinitions (id/templateId → displayName) so PIM rows never drop on empty expanded displayName.</summary>
    private EntraDirectoryRoleCatalog? _entraRoleCatalogScope;

    /// <summary>Per privileged-user report: one transitiveMemberOf result per user (Azure + Entra paths reused the same API up to four times per user).</summary>
    private ConcurrentDictionary<string, Lazy<Task<List<string>>>>? _privilegedReportTransitiveGroupsByUserId;

    /// <summary>Per privileged-user report: one PIM-for-Groups group-id list per principal (called from many code paths per user).</summary>
    private ConcurrentDictionary<string, Lazy<Task<List<string>>>>? _privilegedReportPrivilegedAccessGroupIdsByPrincipal;

    private ConcurrentDictionary<string, Lazy<Task<List<JsonElement>>>>? _privilegedReportArmJsonCache;

    private Dictionary<string, JsonDocument>? _privilegedReportUserJsonById;

    private Dictionary<string, List<JsonElement>>? _entraIdentityGovGroupEligInstByGroupId;
    private Dictionary<string, List<JsonElement>>? _entraIdentityGovGroupEligSchedByGroupId;
    private Dictionary<string, List<JsonElement>>? _entraIdentityGovGroupAssignInstByGroupId;
    private Dictionary<string, List<JsonElement>>? _entraIdentityGovGroupAssignSchedByGroupId;

    private sealed class EntraDirectoryRoleCatalog
    {
        public Dictionary<string, string> ByDefinitionId { get; } = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, string> ByTemplateId { get; } = new(StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>Pre-indexed tenant PIM rows (principalId → rows). Built once per report to avoid brittle per-user OData and to match Microsoft Entra admin center.</summary>
    private sealed record EntraDirectoryPimIndexes(
        Dictionary<string, List<JsonElement>> EligibilitySchedulesByPrincipal,
        Dictionary<string, List<JsonElement>> EligibilityInstancesByPrincipal,
        Dictionary<string, List<JsonElement>> EligibilityRequestsByPrincipal,
        Dictionary<string, List<JsonElement>> AssignmentSchedulesByPrincipal,
        Dictionary<string, List<JsonElement>> AssignmentInstancesByPrincipal);

    private static Dictionary<string, List<JsonElement>> IndexGraphRowsByPrincipalId(IEnumerable<JsonElement> items)
    {
        var d = new Dictionary<string, List<JsonElement>>(StringComparer.OrdinalIgnoreCase);
        foreach (var item in items)
        {
            var pid = GetString(item, "principalId");
            if (string.IsNullOrWhiteSpace(pid))
            {
                continue;
            }

            if (!d.TryGetValue(pid, out var list))
            {
                list = [];
                d[pid] = list;
            }

            list.Add(item);
        }

        return d;
    }

    private static Dictionary<string, List<JsonElement>> IndexGraphRowsByGroupId(IEnumerable<JsonElement> items)
    {
        var d = new Dictionary<string, List<JsonElement>>(StringComparer.OrdinalIgnoreCase);
        foreach (var item in items)
        {
            var gid = GetString(item, "groupId");
            if (string.IsNullOrWhiteSpace(gid))
            {
                continue;
            }

            if (!d.TryGetValue(gid, out var list))
            {
                list = [];
                d[gid] = list;
            }

            list.Add(item);
        }

        return d;
    }

    private const string GraphDirectoryRoleEligibilityExpand = "?$expand=roleDefinition($select=id,displayName,templateId)";

    private sealed record AuthRegistrationInfo(List<string> Methods, bool HasMfa, bool HasPhishingResistant);

    /// <summary>v1+beta Microsoft Entra directory PIM eligibility rows merged by id (beta sometimes returns rows v1 omits).</summary>
    private sealed record MergedDirectoryPimEligibility(List<JsonElement> Schedules, List<JsonElement> Instances, List<JsonElement> Requests);

    private static List<JsonElement> MergeJsonRowsById(IEnumerable<JsonElement> a, IEnumerable<JsonElement> b)
    {
        var d = new Dictionary<string, JsonElement>(StringComparer.OrdinalIgnoreCase);
        foreach (var x in a.Concat(b))
        {
            var id = GetString(x, "id");
            if (string.IsNullOrWhiteSpace(id))
            {
                continue;
            }

            d[id] = x;
        }

        return d.Values.ToList();
    }

    private async Task<List<JsonElement>> MergeV1BetaDirectoryEligibilityAsync(string v1Url, string betaUrl, string graphToken, CancellationToken cancellationToken)
    {
        var v1 = await GetJsonCollectionAsync(v1Url, graphToken, cancellationToken).ConfigureAwait(false);
        List<JsonElement> beta = [];
        try
        {
            beta = await GetJsonCollectionAsync(betaUrl, graphToken, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
        }

        return MergeJsonRowsById(v1, beta);
    }

    private async Task<MergedDirectoryPimEligibility> LoadMergedDirectoryPimEligibilityAsync(string graphToken, CancellationToken cancellationToken)
    {
        var sTask = MergeV1BetaDirectoryEligibilityAsync(
            "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules" + GraphDirectoryRoleEligibilityExpand,
            "https://graph.microsoft.com/beta/roleManagement/directory/roleEligibilitySchedules" + GraphDirectoryRoleEligibilityExpand,
            graphToken,
            cancellationToken);
        var iTask = MergeV1BetaDirectoryEligibilityAsync(
            "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances" + GraphDirectoryRoleEligibilityExpand,
            "https://graph.microsoft.com/beta/roleManagement/directory/roleEligibilityScheduleInstances" + GraphDirectoryRoleEligibilityExpand,
            graphToken,
            cancellationToken);
        var rTask = MergeV1BetaDirectoryEligibilityAsync(
            "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleRequests" + GraphDirectoryRoleEligibilityExpand,
            "https://graph.microsoft.com/beta/roleManagement/directory/roleEligibilityScheduleRequests" + GraphDirectoryRoleEligibilityExpand,
            graphToken,
            cancellationToken);
        await Task.WhenAll(sTask, iTask, rTask).ConfigureAwait(false);
        return new MergedDirectoryPimEligibility(await sTask.ConfigureAwait(false), await iTask.ConfigureAwait(false), await rTask.ConfigureAwait(false));
    }

    private static DateTime? MaxUtc(DateTime? a, DateTime? b)
    {
        if (!a.HasValue)
        {
            return b;
        }

        if (!b.HasValue)
        {
            return a;
        }

        return a.Value >= b.Value ? a : b;
    }

    /// <summary>
    /// Merged sign-in telemetry for an app (client) ID. AggregateLatestUtc is the maximum of every *DateTime on report rows and SP signInActivity so app-only and resource-side usage still move &quot;Latest&quot; forward.
    /// </summary>
    private sealed record AppSignInSnapshot(DateTime? InteractiveUtc, DateTime? NonInteractiveUtc, DateTime? AggregateLatestUtc)
    {
        public DateTime? LatestUtc => MaxUtc(MaxUtc(InteractiveUtc, NonInteractiveUtc), AggregateLatestUtc);

        public static AppSignInSnapshot MergeSnapshots(AppSignInSnapshot? a, AppSignInSnapshot? b)
        {
            if (a is null)
            {
                return b ?? new AppSignInSnapshot(null, null, null);
            }

            if (b is null)
            {
                return a;
            }

            var mi = MaxUtc(a.InteractiveUtc, b.InteractiveUtc);
            var mn = MaxUtc(a.NonInteractiveUtc, b.NonInteractiveUtc);
            var ma = MaxUtc(MaxUtc(a.AggregateLatestUtc, b.AggregateLatestUtc), MaxUtc(mi, mn));
            return new AppSignInSnapshot(mi, mn, ma);
        }
    }

    /// <summary>Does not copy the same timestamp into both buckets (mislabels client-credential sign-ins as interactive). Only when neither bucket is set but aggregate exists, treat as non-interactive (typical for app-only / SP flows).</summary>
    private static AppSignInSnapshot NormalizeAppSignInSnapshotForDisplay(AppSignInSnapshot? s)
    {
        if (s is null)
        {
            return new AppSignInSnapshot(null, null, null);
        }

        var li = s.InteractiveUtc;
        var ln = s.NonInteractiveUtc;
        var agg = s.AggregateLatestUtc ?? MaxUtc(li, ln);
        if (!li.HasValue && !ln.HasValue && agg.HasValue)
        {
            ln = agg;
        }

        var ma = MaxUtc(MaxUtc(agg, li), ln);
        return new AppSignInSnapshot(li, ln, ma);
    }

    /// <summary>Bulk app sign-in snapshots plus audit-derived &quot;latest row&quot; method labels per app (see <see cref="MergeSignInRow"/>).</summary>
    private sealed record AppSignInBulkLoad(
        Dictionary<string, AppSignInSnapshot> Snapshots,
        Dictionary<string, string> LatestAuditSignInMethodByAppId);

    // Directory-role membership seed: all built-in directory roles except Directory Readers (that role would expand nearly every user).

    public async Task<List<PrivilegedUserRecord>> GetPrivilegedUsersAsync(string graphAccessToken, string? armAccessToken, CancellationToken cancellationToken = default)
    {
        _entraRoleCatalogScope = await TryLoadEntraDirectoryRoleCatalogAsync(graphAccessToken, cancellationToken).ConfigureAwait(false);
        _entraIdentityGovGroupEligInstByGroupId = null;
        _entraIdentityGovGroupEligSchedByGroupId = null;
        _entraIdentityGovGroupAssignInstByGroupId = null;
        _entraIdentityGovGroupAssignSchedByGroupId = null;
        if (!IsLightweight())
        {
            await LoadIdentityGovernancePrivilegedAccessGroupIndexesAsync(graphAccessToken, cancellationToken).ConfigureAwait(false);
        }

        try
        {
            var lw = IsLightweight();
            _privilegedReportTransitiveGroupsByUserId = new ConcurrentDictionary<string, Lazy<Task<List<string>>>>(StringComparer.OrdinalIgnoreCase);
            _privilegedReportPrivilegedAccessGroupIdsByPrincipal = new ConcurrentDictionary<string, Lazy<Task<List<string>>>>(StringComparer.OrdinalIgnoreCase);
            _privilegedReportArmJsonCache = new ConcurrentDictionary<string, Lazy<Task<List<JsonElement>>>>(StringComparer.OrdinalIgnoreCase);

            var roles = await GetJsonCollectionAsync("https://graph.microsoft.com/v1.0/directoryRoles?$select=id,displayName", graphAccessToken, cancellationToken);
        var relevantRoles = roles
            .Where(r => IncludeEntraDirectoryRoleInMembershipEnumeration(GetString(r, "displayName")))
            .Select(r => (Id: GetString(r, "id"), Name: GetString(r, "displayName")))
            .Where(r => !string.IsNullOrWhiteSpace(r.Id))
            .ToList();

        var userRolesMap = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        var userRolesMapLock = new object();
        var dirRoleSem = new SemaphoreSlim(8, 8);
        var dirRoleTasks = relevantRoles.Select(async role =>
        {
            await dirRoleSem.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var members = await GetJsonCollectionAsync(
                        $"https://graph.microsoft.com/v1.0/directoryRoles/{role.Id}/members?$select=id,userPrincipalName,displayName,accountEnabled",
                        graphAccessToken,
                        cancellationToken)
                    .ConfigureAwait(false);
                foreach (var member in members)
                {
                    var type = GetString(member, "@odata.type");
                    var memberId = GetString(member, "id");
                    if (string.IsNullOrWhiteSpace(memberId))
                    {
                        continue;
                    }

                    if (type.Equals("#microsoft.graph.user", StringComparison.OrdinalIgnoreCase))
                    {
                        lock (userRolesMapLock)
                        {
                            AddRole(userRolesMap, memberId, role.Name);
                        }
                    }
                    else if (type.Equals("#microsoft.graph.group", StringComparison.OrdinalIgnoreCase))
                    {
                        var gMeta = await GetJsonAsync($"https://graph.microsoft.com/v1.0/groups/{memberId}?$select=displayName", graphAccessToken, cancellationToken).ConfigureAwait(false);
                        var gName = gMeta.HasValue && !string.IsNullOrWhiteSpace(GetString(gMeta.Value, "displayName"))
                            ? GetString(gMeta.Value, "displayName")
                            : "Group";
                        var groupMembers = await GetJsonCollectionAsync(
                                $"https://graph.microsoft.com/v1.0/groups/{memberId}/transitiveMembers?$select=id",
                                graphAccessToken,
                                cancellationToken)
                            .ConfigureAwait(false);
                        foreach (var gm in groupMembers.Where(x => GetString(x, "@odata.type").Equals("#microsoft.graph.user", StringComparison.OrdinalIgnoreCase)))
                        {
                            var uid = GetString(gm, "id");
                            if (!string.IsNullOrWhiteSpace(uid))
                            {
                                lock (userRolesMapLock)
                                {
                                    // Light: plain role name (same effective access as Entra "Assigned roles"); full SKU keeps group provenance.
                                    var label = lw ? role.Name : $"{role.Name} (via group: {gName})";
                                    AddRole(userRolesMap, uid, label);
                                }
                            }
                        }
                    }
                }
            }
            finally
            {
                dirRoleSem.Release();
            }
        });
        await Task.WhenAll(dirRoleTasks).ConfigureAwait(false);

        if (lw)
        {
            await TryMergeLightUnifiedRoleAssignmentsIntoUserMapAsync(userRolesMap, userRolesMapLock, graphAccessToken, cancellationToken).ConfigureAwait(false);
        }

        MergedDirectoryPimEligibility mergedDirElig;
        if (lw)
        {
            mergedDirElig = new MergedDirectoryPimEligibility([], [], []);
        }
        else
        {
            try
            {
                mergedDirElig = await LoadMergedDirectoryPimEligibilityAsync(graphAccessToken, cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                mergedDirElig = new MergedDirectoryPimEligibility([], [], []);
            }

            await ExpandPrivilegedUsersFromDirectoryPimSchedulesAsync(userRolesMap, graphAccessToken, cancellationToken, mergedDirElig);
        }
        if (!string.IsNullOrWhiteSpace(armAccessToken))
        {
            await MergeAzureOnlyPrivilegedUserIdsAsync(userRolesMap, graphAccessToken, armAccessToken, cancellationToken);
        }

        EntraDirectoryPimIndexes? entraTenantPim = null;
        if (!lw)
        {
            try
            {
                var assignSchedTask = MergeV1BetaDirectoryEligibilityAsync(
                    "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentSchedules" + GraphDirectoryRoleEligibilityExpand,
                    "https://graph.microsoft.com/beta/roleManagement/directory/roleAssignmentSchedules" + GraphDirectoryRoleEligibilityExpand,
                    graphAccessToken,
                    cancellationToken);
                var assignInstTask = MergeV1BetaDirectoryEligibilityAsync(
                    "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances" + GraphDirectoryRoleEligibilityExpand,
                    "https://graph.microsoft.com/beta/roleManagement/directory/roleAssignmentScheduleInstances" + GraphDirectoryRoleEligibilityExpand,
                    graphAccessToken,
                    cancellationToken);
                await Task.WhenAll(assignSchedTask, assignInstTask).ConfigureAwait(false);

                entraTenantPim = new EntraDirectoryPimIndexes(
                    IndexGraphRowsByPrincipalId(mergedDirElig.Schedules),
                    IndexGraphRowsByPrincipalId(mergedDirElig.Instances),
                    IndexGraphRowsByPrincipalId(mergedDirElig.Requests),
                    IndexGraphRowsByPrincipalId(await assignSchedTask.ConfigureAwait(false)),
                    IndexGraphRowsByPrincipalId(await assignInstTask.ConfigureAwait(false)));
            }
            catch
            {
                entraTenantPim = null;
            }
        }

        IReadOnlyList<string>? armScopePrefixesPrefetched = null;
        if (!string.IsNullOrWhiteSpace(armAccessToken))
        {
            try
            {
                armScopePrefixesPrefetched = await ListAzureArmScopePrefixesAsync(armAccessToken, cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                armScopePrefixesPrefetched = null;
            }
        }

        Dictionary<string, AuthRegistrationInfo>? authRegByUserId = null;
        if (!lw)
        {
            try
            {
                var bulkAuth = await LoadAuthRegistrationDetailsMapByUserIdAsync(graphAccessToken, cancellationToken).ConfigureAwait(false);
                if (bulkAuth.Count > 0)
                {
                    authRegByUserId = bulkAuth;
                }
            }
            catch
            {
                authRegByUserId = null;
            }
        }

        var userIds = userRolesMap.Keys.ToList();
        try
        {
            _privilegedReportUserJsonById = await PrefetchPrivilegedUserJsonDocumentsAsync(userIds, graphAccessToken, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            _privilegedReportUserJsonById = null;
        }

        var records = new List<PrivilegedUserRecord>();
        var semaphore = new SemaphoreSlim(lw ? 20 : 12, lw ? 20 : 12);
        var tasks = userIds.Select(async userId =>
        {
            await semaphore.WaitAsync(cancellationToken);
            try
            {
                JsonElement? userDocEl = null;
                if (_privilegedReportUserJsonById is not null &&
                    _privilegedReportUserJsonById.TryGetValue(userId, out var prefetchedDoc))
                {
                    userDocEl = prefetchedDoc.RootElement;
                }

                if (userDocEl is null)
                {
                    userDocEl = await GetJsonAsync($"https://graph.microsoft.com/v1.0/users/{userId}?$select=id,userPrincipalName,displayName,accountEnabled,onPremisesSyncEnabled,onPremisesImmutableId,onPremisesDistinguishedName,onPremisesSecurityIdentifier,onPremisesSamAccountName,onPremisesUserPrincipalName", graphAccessToken, cancellationToken);
                }

                if (userDocEl is null)
                {
                    return;
                }

                var userDoc = userDocEl.Value;

                var userType = GetBool(userDoc, "onPremisesSyncEnabled")
                               || !string.IsNullOrWhiteSpace(GetString(userDoc, "onPremisesImmutableId"))
                               || !string.IsNullOrWhiteSpace(GetString(userDoc, "onPremisesDistinguishedName"))
                               || !string.IsNullOrWhiteSpace(GetString(userDoc, "onPremisesSecurityIdentifier"))
                               || !string.IsNullOrWhiteSpace(GetString(userDoc, "onPremisesSamAccountName"))
                               || !string.IsNullOrWhiteSpace(GetString(userDoc, "onPremisesUserPrincipalName"))
                    ? "Hybrid"
                    : "Cloud";

                List<EntraEligibleRoleLine> eligibleRoles = [];
                List<string> activeRolesFromSchedules = [];
                List<string> authMethods = ["Unable to check"];
                var mfa = false;
                var phishingResistant = false;
                List<AzureRoleLine> azureActive = [];
                List<AzureRoleLine> azureEligible = [];

                var eligibleTask = lw
                    ? Task.FromResult(new List<EntraEligibleRoleLine>())
                    : GetEligibleRolesAsync(userId, graphAccessToken, entraTenantPim, cancellationToken);
                var activeRolesTask = GetActiveRolesViaSchedulesAsync(userId, graphAccessToken, entraTenantPim, cancellationToken);
                Task<(List<string> Methods, bool HasMfa, bool HasPhishingResistant)> authTask =
                    lw
                        ? Task.FromResult((new List<string>(), false, false))
                        : authRegByUserId != null && authRegByUserId.TryGetValue(userId, out var preAuth)
                            ? Task.FromResult((preAuth.Methods, preAuth.HasMfa, preAuth.HasPhishingResistant))
                            : GetAuthInfoAsync(userId, graphAccessToken, cancellationToken);
                Task<(List<AzureRoleLine> ActiveRoles, List<AzureRoleLine> EligibleRoles)> azureTask =
                    string.IsNullOrWhiteSpace(armAccessToken)
                        ? Task.FromResult((new List<AzureRoleLine>(), new List<AzureRoleLine>()))
                        : GetAzureRolesAsync(userId, graphAccessToken, armAccessToken, cancellationToken, armScopePrefixesPrefetched, lw);

                try { eligibleRoles = await eligibleTask; } catch { }
                try { activeRolesFromSchedules = await activeRolesTask; } catch { }
                try
                {
                    var auth = await authTask;
                    authMethods = auth.Methods;
                    mfa = auth.HasMfa;
                    phishingResistant = auth.HasPhishingResistant;
                }
                catch { }
                try
                {
                    var azure = await azureTask;
                    azureActive = azure.ActiveRoles;
                    azureEligible = azure.EligibleRoles;
                }
                catch { }

                var mergedActiveRoles = DedupeEntraRoleLines(
                    userRolesMap[userId].Concat(activeRolesFromSchedules));
                if (lw)
                {
                    mergedActiveRoles = mergedActiveRoles
                        .Where(r => r.IndexOf("(via group:", StringComparison.OrdinalIgnoreCase) < 0)
                        .ToList();
                }

                var entraPimNames = ExtractEntraPimGroupNames(mergedActiveRoles.Concat(eligibleRoles.Select(e => e.Line)));
                var azurePimNames = azureActive.Concat(azureEligible)
                    .Where(x => x.ViaGroup && !string.IsNullOrWhiteSpace(x.GroupDisplayName))
                    .Select(x => x.GroupDisplayName!)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
                    .ToList();

                lock (records)
                {
                    records.Add(new PrivilegedUserRecord
                    {
                        UserId = userId,
                        UserPrincipalName = GetString(userDoc, "userPrincipalName"),
                        DisplayName = GetString(userDoc, "displayName"),
                        AccountEnabled = GetBool(userDoc, "accountEnabled"),
                        UserType = userType,
                        EntraActiveRoles = mergedActiveRoles,
                        EntraEligibleRoles = DedupeEntraEligibleRoleLines(eligibleRoles),
                        AzureActiveRoles = azureActive,
                        AzureEligibleRoles = azureEligible,
                        EntraPimGroupNames = entraPimNames,
                        AzurePimGroupNames = azurePimNames,
                        LastInteractiveSignIn = "—",
                        LastNonInteractiveSignIn = "—",
                        IsStaleAccount = false,
                        AuthMethods = authMethods,
                        MfaEnabled = mfa,
                        HasPhishingResistantMethod = phishingResistant
                    });
                }
            }
            finally
            {
                semaphore.Release();
            }
        });
        await Task.WhenAll(tasks);
        return records.OrderBy(x => x.UserPrincipalName, StringComparer.OrdinalIgnoreCase).ToList();
        }
        finally
        {
            _entraRoleCatalogScope = null;
            _privilegedReportTransitiveGroupsByUserId = null;
            _privilegedReportPrivilegedAccessGroupIdsByPrincipal = null;
            _privilegedReportArmJsonCache = null;
            if (_privilegedReportUserJsonById is not null)
            {
                foreach (var d in _privilegedReportUserJsonById.Values)
                {
                    d.Dispose();
                }

                _privilegedReportUserJsonById = null;
            }

            _entraIdentityGovGroupEligInstByGroupId = null;
            _entraIdentityGovGroupEligSchedByGroupId = null;
            _entraIdentityGovGroupAssignInstByGroupId = null;
            _entraIdentityGovGroupAssignSchedByGroupId = null;
        }
    }

    public async Task<List<ApplicationPermissionRecord>> GetApplicationsAsync(string graphAccessToken, CancellationToken cancellationToken = default)
    {
        var grants = await GetJsonCollectionAsync("https://graph.microsoft.com/v1.0/oauth2PermissionGrants", graphAccessToken, cancellationToken);
        var delegatedByClient = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        var delegatedConsentByClientSpId = new Dictionary<string, (bool Admin, bool User)>(StringComparer.OrdinalIgnoreCase);
        foreach (var grant in grants)
        {
            var clientId = GetString(grant, "clientId");
            var scope = GetString(grant, "scope");
            var consentType = GetString(grant, "consentType");
            if (string.IsNullOrWhiteSpace(clientId))
            {
                continue;
            }

            if (!delegatedByClient.TryGetValue(clientId, out var scopeSet))
            {
                scopeSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                delegatedByClient[clientId] = scopeSet;
            }

            foreach (var part in scope.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                scopeSet.Add(part);
            }

            if (!delegatedConsentByClientSpId.TryGetValue(clientId, out var flags))
            {
                flags = (false, false);
            }

            if (consentType.Equals("AllPrincipals", StringComparison.OrdinalIgnoreCase))
            {
                flags.Admin = true;
            }

            if (consentType.Equals("Principal", StringComparison.OrdinalIgnoreCase))
            {
                flags.User = true;
            }

            delegatedConsentByClientSpId[clientId] = flags;
        }

        var lwApps = IsLightweight();
        AppSignInBulkLoad signInBulk;
        if (lwApps)
        {
            signInBulk = new AppSignInBulkLoad(
                new Dictionary<string, AppSignInSnapshot>(StringComparer.OrdinalIgnoreCase),
                new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase));
        }
        else
        {
            signInBulk = await LoadAppSignInSnapshotsByAppIdAsync(graphAccessToken, cancellationToken);
        }

        var signInByAppId = signInBulk.Snapshots;
        var auditSignInMethodByAppId = signInBulk.LatestAuditSignInMethodByAppId;

        // Beta often returns lastModifiedDateTime on servicePrincipal; v1 frequently omits it, which left the report column empty.
        // If beta is denied or fails every page, GetJsonCollectionWithRetryAsync returns an empty list (no throw)—fall back to v1.
        List<JsonElement> allServicePrincipals;
        try
        {
            var betaRows = await GetJsonCollectionWithRetryAsync(
                "https://graph.microsoft.com/beta/servicePrincipals?$select=id,displayName,appId,createdDateTime,lastModifiedDateTime,appOwnerOrganizationId,accountEnabled",
                graphAccessToken,
                cancellationToken);
            allServicePrincipals = betaRows.Count > 0
                ? betaRows
                : await GetJsonCollectionAsync(
                    "https://graph.microsoft.com/v1.0/servicePrincipals?$select=id,displayName,appId,createdDateTime,lastModifiedDateTime,appOwnerOrganizationId,accountEnabled",
                    graphAccessToken,
                    cancellationToken);
        }
        catch
        {
            allServicePrincipals = await GetJsonCollectionAsync(
                "https://graph.microsoft.com/v1.0/servicePrincipals?$select=id,displayName,appId,createdDateTime,lastModifiedDateTime,appOwnerOrganizationId,accountEnabled",
                graphAccessToken,
                cancellationToken);
        }

        var appMetaByAppId = lwApps
            ? new Dictionary<string, AppRegistrationMeta>(StringComparer.OrdinalIgnoreCase)
            : await GetApplicationMetadataByAppIdAsync(graphAccessToken, cancellationToken);
        var bag = new ConcurrentBag<ApplicationPermissionRecord>();
        var semaphore = new SemaphoreSlim(8);
        var signInFallbackSem = new SemaphoreSlim(6);
        var tasks = allServicePrincipals.Select(async sp =>
        {
            var spId = GetString(sp, "id");
            if (string.IsNullOrWhiteSpace(spId))
            {
                return;
            }

            delegatedByClient.TryGetValue(spId, out var delSet);
            var delegatedList = delSet is null ? [] : delSet.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToList();

            await semaphore.WaitAsync(cancellationToken);
            try
            {
                var appRoles = await GetAppRoleAssignmentStringsAsync(spId, graphAccessToken, cancellationToken);
                if (appRoles.Count == 0 && delegatedList.Count == 0)
                {
                    return;
                }

                var appId = GetString(sp, "appId");
                var hasKey = false;
                var hasSecret = false;
                DateTime? appModifiedUtc = null;
                AppRegistrationMeta? meta = null;
                if (!lwApps && !string.IsNullOrWhiteSpace(appId) && appMetaByAppId.TryGetValue(appId, out var m))
                {
                    meta = m;
                    hasKey = meta.HasKey;
                    hasSecret = meta.HasSecret;
                    appModifiedUtc = meta.AppModifiedUtc;
                }

                if (!lwApps && !hasKey && !hasSecret)
                {
                    var spCred = await LoadServicePrincipalCredentialFlagsAsync(spId, graphAccessToken, cancellationToken);
                    hasKey = spCred.HasKey;
                    hasSecret = spCred.HasSecret;
                }

                delegatedConsentByClientSpId.TryGetValue(spId, out var consentFlags);
                var hasAdminConsent = appRoles.Count > 0 || consentFlags.Admin;
                var hasUserConsent = consentFlags.User && delegatedList.Count > 0;
                var consentSummary = lwApps
                    ? "—"
                    : !hasAdminConsent && !hasUserConsent
                        ? "—"
                        : hasAdminConsent && hasUserConsent
                            ? "Mixed"
                            : hasAdminConsent
                                ? "Admin"
                                : "User";

                List<string> ownerLines;
                if (lwApps)
                {
                    ownerLines = [];
                }
                else if (meta is { OwnerLines.Count: > 0 })
                {
                    ownerLines = meta.OwnerLines.ToList();
                }
                else
                {
                    ownerLines = await GetServicePrincipalOwnerLinesAsync(spId, graphAccessToken, cancellationToken);
                }

                var certExpired = !lwApps && hasKey && (meta?.CertificateExpired ?? false);
                var secretExpired = !lwApps && hasSecret && (meta?.ClientSecretExpired ?? false);

                AppSignInSnapshot? snap = null;
                DateTime? latest;
                var hasAnySignInDate = false;
                var seen = false;
                string liStr;
                string lnStr;
                var isStale = false;

                if (lwApps)
                {
                    latest = null;
                    liStr = "—";
                    lnStr = "—";
                }
                else
                {
                    if (!string.IsNullOrWhiteSpace(appId) && signInByAppId.TryGetValue(appId, out var bulkSnap))
                    {
                        snap = bulkSnap;
                    }

                    await signInFallbackSem.WaitAsync(cancellationToken);
                    try
                    {
                        var spSnap = await LoadServicePrincipalSignInSnapshotAsync(spId, graphAccessToken, cancellationToken);
                        snap = NormalizeAppSignInSnapshotForDisplay(AppSignInSnapshot.MergeSnapshots(snap, spSnap));
                    }
                    finally
                    {
                        signInFallbackSem.Release();
                    }

                    latest = snap?.LatestUtc;
                    hasAnySignInDate = latest.HasValue;
                    seen = hasAnySignInDate;
                    liStr = hasAnySignInDate ? FormatAppSignInLine(snap?.InteractiveUtc) : "No sign-in data";
                    lnStr = hasAnySignInDate ? FormatAppSignInLine(snap?.NonInteractiveUtc) : "No sign-in data";
                    isStale = !latest.HasValue || latest.Value < DateTime.UtcNow.AddDays(-90);
                }
                var spCreatedUtc = ParseODataDateTime(sp, "createdDateTime");
                var spModifiedUtc = ParseODataDateTime(sp, "lastModifiedDateTime");
                var lastChangedUtc = MaxUtc(appModifiedUtc, spModifiedUtc);
                var lastModIsCreatedFallback = false;
                if (!lastChangedUtc.HasValue && spCreatedUtc.HasValue)
                {
                    lastChangedUtc = spCreatedUtc;
                    lastModIsCreatedFallback = true;
                }

                var methodHint = !string.IsNullOrWhiteSpace(appId) && auditSignInMethodByAppId.TryGetValue(appId, out var mh)
                    ? mh
                    : "—";

                var accountEnabled = true;
                if (sp.TryGetProperty("accountEnabled", out var accEn) && accEn.ValueKind is JsonValueKind.True or JsonValueKind.False)
                {
                    accountEnabled = accEn.ValueKind == JsonValueKind.True;
                }

                bag.Add(new ApplicationPermissionRecord
                {
                    ServicePrincipalId = spId,
                    DisplayName = GetString(sp, "displayName"),
                    AppId = appId,
                    AccountEnabled = accountEnabled,
                    SignInSeenInAuditSample = seen,
                    MostRecentSignInUtc = hasAnySignInDate ? latest : null,
                    LastUsedUtc = hasAnySignInDate ? latest : null,
                    ApplicationLastModifiedUtc = lastChangedUtc,
                    ApplicationLastModifiedIsCreatedFallback = lastModIsCreatedFallback,
                    EnterpriseAppCreatedUtc = spCreatedUtc,
                    LastInteractiveSignIn = lwApps ? "—" : (hasAnySignInDate ? liStr : "No sign-in data returned"),
                    LastNonInteractiveSignIn = lwApps ? "—" : (hasAnySignInDate ? lnStr : "No sign-in data returned"),
                    LastInteractiveSignInUtc = lwApps ? null : snap?.InteractiveUtc,
                    LastNonInteractiveSignInUtc = lwApps ? null : snap?.NonInteractiveUtc,
                    LatestAuditSignInMethodSummary = lwApps ? "—" : methodHint,
                    IsStaleApp = lwApps ? false : isStale,
                    HasKeyCredential = lwApps ? false : hasKey,
                    HasPasswordCredential = lwApps ? false : hasSecret,
                    OwnerDisplayLines = ownerLines,
                    ConsentTypeSummary = consentSummary,
                    HasFederatedCredentials = lwApps ? false : (meta?.HasFederatedCredentials ?? false),
                    ClientSecretExpired = secretExpired,
                    CertificateExpired = certExpired,
                    ClientSecretExpiresUtc = lwApps ? null : meta?.ClientSecretExpiresUtc,
                    CertificateExpiresUtc = lwApps ? null : meta?.CertificateExpiresUtc,
                    HasAdminConsentPath = !lwApps && hasAdminConsent,
                    HasUserConsentPath = !lwApps && hasUserConsent,
                    AppRolePermissions = appRoles,
                    DelegatedScopes = delegatedList
                });
            }
            catch
            {
                // skip noisy SPs
            }
            finally
            {
                semaphore.Release();
            }
        });

        await Task.WhenAll(tasks);
        return bag.OrderBy(x => x.DisplayName, StringComparer.OrdinalIgnoreCase).ToList();
    }

    /// <summary>
    /// Bulk sign-in snapshot from beta <c>reports/servicePrincipalSignInActivities</c>; merges audit sampling (all relevant sign-in event types) when reports are empty or thin.
    /// </summary>
    private async Task<AppSignInBulkLoad> LoadAppSignInSnapshotsByAppIdAsync(string graphToken, CancellationToken cancellationToken)
    {
        var map = new Dictionary<string, AppSignInSnapshot>(StringComparer.OrdinalIgnoreCase);
        var latestAuditMethodByAppId = new Dictionary<string, (DateTime Utc, string Label)>(StringComparer.OrdinalIgnoreCase);
        try
        {
            var rows = await GetJsonCollectionWithRetryAsync(
                "https://graph.microsoft.com/beta/reports/servicePrincipalSignInActivities",
                graphToken,
                cancellationToken);
            foreach (var row in rows)
            {
                var appId = GetString(row, "appId");
                if (string.IsNullOrWhiteSpace(appId))
                {
                    continue;
                }

                var rowSnap = SignInSnapshotFromServicePrincipalReportRow(row);
                if (rowSnap.LatestUtc is null)
                {
                    continue;
                }

                map.TryGetValue(appId, out var exist);
                map[appId] = AppSignInSnapshot.MergeSnapshots(exist, rowSnap);
            }
        }
        catch
        {
            // Reports may require Reports Reader / AuditLog.Read.All; continue with audit merge.
        }

        try
        {
            // Windowed pass: recent sign-ins are often missing from the global "newest N events" tail when a few principals dominate volume.
            var auditWindow = await GetRecentServicePrincipalSignInsByAppClientIdAsync(
                graphToken,
                cancellationToken,
                maxPages: 65,
                minCreatedUtc: DateTime.UtcNow.AddDays(-548),
                latestAuditMethodByAppId: latestAuditMethodByAppId);
            MergeAuditSignInMapIntoSnapshotMap(map, auditWindow);
            var auditTail = await GetRecentServicePrincipalSignInsByAppClientIdAsync(
                graphToken,
                cancellationToken,
                maxPages: 38,
                minCreatedUtc: null,
                latestAuditMethodByAppId: latestAuditMethodByAppId);
            MergeAuditSignInMapIntoSnapshotMap(map, auditTail);
            var spSourceWindow = await GetRecentServicePrincipalSignInsByAppClientIdAsync(
                graphToken,
                cancellationToken,
                maxPages: 48,
                minCreatedUtc: DateTime.UtcNow.AddDays(-548),
                betaServicePrincipalSource: true,
                latestAuditMethodByAppId: latestAuditMethodByAppId);
            MergeAuditSignInMapIntoSnapshotMap(map, spSourceWindow);
            var spSourceTail = await GetRecentServicePrincipalSignInsByAppClientIdAsync(
                graphToken,
                cancellationToken,
                maxPages: 32,
                minCreatedUtc: null,
                betaServicePrincipalSource: true,
                latestAuditMethodByAppId: latestAuditMethodByAppId);
            MergeAuditSignInMapIntoSnapshotMap(map, spSourceTail);
        }
        catch
        {
            // Audit logs unavailable.
        }

        var flatHints = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var kv in latestAuditMethodByAppId)
        {
            flatHints[kv.Key] = kv.Value.Label;
        }

        return new AppSignInBulkLoad(map, flatHints);
    }

    private static AppSignInSnapshot SignInSnapshotFromServicePrincipalReportRow(JsonElement row)
    {
        DateTime? i = null;
        DateTime? n = null;
        DateTime? agg = null;

        void BumpAgg(DateTime du)
        {
            agg = !agg.HasValue || du > agg.Value ? du : agg;
        }

        void IngestDelegatedLikeActivity(JsonElement act)
        {
            foreach (var prop in act.EnumerateObject())
            {
                if (prop.Value.ValueKind != JsonValueKind.String
                    || !prop.Name.EndsWith("DateTime", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                var raw = prop.Value.GetString();
                if (string.IsNullOrWhiteSpace(raw)
                    || !DateTime.TryParse(raw, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal, out var parsed))
                {
                    continue;
                }

                var du = parsed.ToUniversalTime();
                BumpAgg(du);
            }

            var ni = ParseDateUtc(act, "lastNonInteractiveSignInDateTime");
            if (ni.HasValue)
            {
                n = MaxUtc(n, ni);
            }

            foreach (var p in new[] { "lastSignInDateTime", "lastSuccessfulSignInDateTime" })
            {
                var d = ParseDateUtc(act, p);
                if (d.HasValue)
                {
                    i = MaxUtc(i, d);
                }
            }
        }

        void IngestApplicationAuthActivity(JsonElement act)
        {
            foreach (var prop in act.EnumerateObject())
            {
                if (prop.Value.ValueKind != JsonValueKind.String
                    || !prop.Name.EndsWith("DateTime", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                var raw = prop.Value.GetString();
                if (string.IsNullOrWhiteSpace(raw)
                    || !DateTime.TryParse(raw, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal, out var parsed))
                {
                    continue;
                }

                var du = parsed.ToUniversalTime();
                BumpAgg(du);
                n = MaxUtc(n, du);
            }
        }

        if (row.TryGetProperty("delegatedClientSignInActivity", out var delClient) && delClient.ValueKind == JsonValueKind.Object)
        {
            IngestDelegatedLikeActivity(delClient);
        }

        if (row.TryGetProperty("delegatedResourceSignInActivity", out var delRes) && delRes.ValueKind == JsonValueKind.Object)
        {
            IngestDelegatedLikeActivity(delRes);
        }

        if (row.TryGetProperty("applicationAuthenticationClientSignInActivity", out var appClient) && appClient.ValueKind == JsonValueKind.Object)
        {
            IngestApplicationAuthActivity(appClient);
        }

        if (row.TryGetProperty("applicationAuthenticationResourceSignInActivity", out var appRes) && appRes.ValueKind == JsonValueKind.Object)
        {
            IngestApplicationAuthActivity(appRes);
        }

        if (row.TryGetProperty("lastSignInActivity", out var legacy) && legacy.ValueKind == JsonValueKind.Object)
        {
            IngestDelegatedLikeActivity(legacy);
        }

        agg = MaxUtc(MaxUtc(agg, i), n);
        return NormalizeAppSignInSnapshotForDisplay(new AppSignInSnapshot(i, n, agg));
    }

    private static void MergeAuditSignInMapIntoSnapshotMap(
        Dictionary<string, AppSignInSnapshot> map,
        Dictionary<string, (DateTime? Interactive, DateTime? NonInteractive)> auditMap)
    {
        foreach (var kv in auditMap)
        {
            var i = kv.Value.Interactive;
            var ni = kv.Value.NonInteractive;
            var patch = new AppSignInSnapshot(i, ni, MaxUtc(i, ni));
            map.TryGetValue(kv.Key, out var exist);
            map[kv.Key] = AppSignInSnapshot.MergeSnapshots(exist, patch);
        }
    }

    /// <summary>
    /// Batched audit sign-ins keyed by application (client) ID. All sign-in event types are read from the log (no OData type filter); rows are bucketed in <see cref="MergeSignInRow"/>.
    /// Limited pages for speed; not exhaustive for the whole tenant.
    /// </summary>
    private async Task<Dictionary<string, (DateTime? Interactive, DateTime? NonInteractive)>> GetRecentServicePrincipalSignInsByAppClientIdAsync(
        string graphToken,
        CancellationToken cancellationToken,
        int maxPages,
        DateTime? minCreatedUtc = null,
        bool betaServicePrincipalSource = false,
        Dictionary<string, (DateTime Utc, string Label)>? latestAuditMethodByAppId = null)
    {
        var map = new Dictionary<string, (DateTime? Interactive, DateTime? NonInteractive)>(StringComparer.OrdinalIgnoreCase);
        // Beta <c>source=sp</c> surfaces service-principal / client-credential sign-ins that the tenant-wide v1 tail often omits (parity with common Entra reporting scripts).
        var selectFields = "appId,createdDateTime,isInteractive,signInEventTypes,clientCredentialType";
        var endpointPrefix = betaServicePrincipalSource
            ? "https://graph.microsoft.com/beta/auditLogs/signIns?source=sp&"
            : "https://graph.microsoft.com/v1.0/auditLogs/signIns?";
        // Do not filter by signInEventTypes in OData: some tenants/events omit or vary types; we classify each row in MergeSignInRow.
        string firstUrl;
        if (minCreatedUtc.HasValue)
        {
            var iso = minCreatedUtc.Value.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture);
            var filter = "createdDateTime ge " + iso;
            firstUrl =
                endpointPrefix
                + "$filter="
                + Uri.EscapeDataString(filter)
                + "&$orderby=createdDateTime desc&$top=999&$select="
                + selectFields;
        }
        else
        {
            firstUrl =
                endpointPrefix
                + "$orderby=createdDateTime desc&$top=999&$select="
                + selectFields;
        }
        var next = firstUrl;
        var pages = 0;
        while (!string.IsNullOrWhiteSpace(next) && pages < maxPages)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, next);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", graphToken);
            request.Headers.TryAddWithoutValidation("ConsistencyLevel", "eventual");
            using var response = await httpClient.SendAsync(request, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                break;
            }

            using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken));
            var root = document.RootElement;
            if (root.TryGetProperty("value", out var value) && value.ValueKind == JsonValueKind.Array)
            {
                foreach (var row in value.EnumerateArray())
                {
                    MergeSignInRow(map, row, latestAuditMethodByAppId);
                }
            }

            next = root.TryGetProperty("@odata.nextLink", out var nextLink) ? nextLink.GetString() : null;
            pages++;
        }

        return map;
    }

    /// <summary>
    /// Buckets each audit row into interactive vs non-interactive timestamps (see <c>signInEventTypes</c>, <c>clientCredentialType</c>, <c>isInteractive</c>).
    /// When <paramref name="latestAuditMethodByAppId"/> is provided, stores a human-readable label from the chronologically newest row per <c>appId</c> in this crawl
    /// (sampled pages only — not a full tenant history). Labels explain service principal vs managed identity style flows where Graph exposes them.
    /// </summary>
    private static void MergeSignInRow(
        Dictionary<string, (DateTime? Interactive, DateTime? NonInteractive)> map,
        JsonElement row,
        Dictionary<string, (DateTime Utc, string Label)>? latestAuditMethodByAppId = null)
    {
        var appId = GetString(row, "appId");
        if (string.IsNullOrWhiteSpace(appId))
        {
            appId = GetString(row, "clientId");
        }

        if (string.IsNullOrWhiteSpace(appId))
        {
            return;
        }

        var dt = ParseAuditSignInCreatedUtc(row);
        if (!dt.HasValue)
        {
            return;
        }

        var hasInteractive = false;
        var hasNonInteractive = row.TryGetProperty("clientCredentialType", out var ccType)
                                && ccType.ValueKind == JsonValueKind.String
                                && !string.IsNullOrWhiteSpace(ccType.GetString());
        void ClassifyEventType(string? s)
        {
            if (string.IsNullOrWhiteSpace(s))
            {
                return;
            }

            if (s.Equals("interactiveUser", StringComparison.OrdinalIgnoreCase)
                || s.Equals("integratedWindowsAuthentication", StringComparison.OrdinalIgnoreCase)
                || s.Equals("resourceOwnerPassword", StringComparison.OrdinalIgnoreCase)
                || s.Equals("windowsHelloForBusiness", StringComparison.OrdinalIgnoreCase)
                || s.Equals("federatedCredentialAuthentication", StringComparison.OrdinalIgnoreCase))
            {
                hasInteractive = true;
            }
            else if (s.Equals("nonInteractiveUser", StringComparison.OrdinalIgnoreCase)
                     || s.Equals("servicePrincipal", StringComparison.OrdinalIgnoreCase)
                     || s.Equals("managedIdentity", StringComparison.OrdinalIgnoreCase)
                     || s.Equals("workloadIdentity", StringComparison.OrdinalIgnoreCase)
                     || s.Equals("workloadIdentityUser", StringComparison.OrdinalIgnoreCase)
                     || s.Equals("application", StringComparison.OrdinalIgnoreCase)
                     || s.Equals("clientCredentialRequest", StringComparison.OrdinalIgnoreCase)
                     || s.Equals("refreshToken", StringComparison.OrdinalIgnoreCase)
                     || s.Equals("deviceCode", StringComparison.OrdinalIgnoreCase)
                     || s.Equals("passthrough", StringComparison.OrdinalIgnoreCase)
                     || s.Equals("token", StringComparison.OrdinalIgnoreCase)
                     || s.Equals("unknownFutureValue", StringComparison.OrdinalIgnoreCase))
            {
                hasNonInteractive = true;
            }
        }

        if (row.TryGetProperty("signInEventTypes", out var typesNode))
        {
            if (typesNode.ValueKind == JsonValueKind.Array)
            {
                foreach (var t in typesNode.EnumerateArray())
                {
                    ClassifyEventType(t.ValueKind == JsonValueKind.String ? t.GetString() : null);
                }
            }
            else if (typesNode.ValueKind == JsonValueKind.String)
            {
                ClassifyEventType(typesNode.GetString());
            }
        }

        if (row.TryGetProperty("signInEventType", out var singleType) && singleType.ValueKind == JsonValueKind.String)
        {
            ClassifyEventType(singleType.GetString());
        }

        if (!hasInteractive && !hasNonInteractive)
        {
            if (row.TryGetProperty("isInteractive", out var interactiveNode) && interactiveNode.ValueKind == JsonValueKind.True)
            {
                hasInteractive = true;
            }
            else if (row.TryGetProperty("isInteractive", out var interactiveNode2) && interactiveNode2.ValueKind == JsonValueKind.False)
            {
                hasNonInteractive = true;
            }
            else
            {
                hasNonInteractive = true;
            }
        }

        map.TryGetValue(appId, out var current);
        if (hasInteractive)
        {
            if (!current.Interactive.HasValue || dt.Value > current.Interactive.Value)
            {
                current.Interactive = dt.Value;
            }
        }

        if (hasNonInteractive)
        {
            if (!current.NonInteractive.HasValue || dt.Value > current.NonInteractive.Value)
            {
                current.NonInteractive = dt.Value;
            }
        }

        map[appId] = current;

        if (latestAuditMethodByAppId is not null)
        {
            var label = BuildAuditSignInMethodLabel(row, hasInteractive, hasNonInteractive);
            if (!latestAuditMethodByAppId.TryGetValue(appId, out var curHint) || dt.Value > curHint.Utc)
            {
                latestAuditMethodByAppId[appId] = (dt.Value, label);
            }
        }
    }

    private static string BuildAuditSignInMethodLabel(JsonElement row, bool hasInteractive, bool hasNonInteractive)
    {
        var cc = row.TryGetProperty("clientCredentialType", out var ccNode) && ccNode.ValueKind == JsonValueKind.String
            ? ccNode.GetString()?.Trim()
            : null;
        if (!string.IsNullOrWhiteSpace(cc))
        {
            return "Non-interactive app credential (" + cc + ")";
        }

        var types = new List<string>();
        void AddType(string? s)
        {
            if (!string.IsNullOrWhiteSpace(s))
            {
                types.Add(s.Trim());
            }
        }

        if (row.TryGetProperty("signInEventTypes", out var typesNode))
        {
            if (typesNode.ValueKind == JsonValueKind.Array)
            {
                foreach (var t in typesNode.EnumerateArray())
                {
                    AddType(t.ValueKind == JsonValueKind.String ? t.GetString() : null);
                }
            }
            else if (typesNode.ValueKind == JsonValueKind.String)
            {
                AddType(typesNode.GetString());
            }
        }

        if (row.TryGetProperty("signInEventType", out var singleType) && singleType.ValueKind == JsonValueKind.String)
        {
            AddType(singleType.GetString());
        }

        if (types.Count > 0)
        {
            var distinct = types.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            var joined = string.Join(", ", distinct);
            if (distinct.Exists(s => s.Equals("managedIdentity", StringComparison.OrdinalIgnoreCase)))
            {
                return "Non-interactive (managed identity — " + joined + ")";
            }

            if (distinct.Exists(s => s.Equals("servicePrincipal", StringComparison.OrdinalIgnoreCase)))
            {
                return "Non-interactive (service principal — " + joined + ")";
            }

            if (distinct.Exists(s => s.Equals("application", StringComparison.OrdinalIgnoreCase)
                                     || s.Equals("clientCredentialRequest", StringComparison.OrdinalIgnoreCase)))
            {
                return "Non-interactive (application / client credential — " + joined + ")";
            }

            if (hasInteractive && !hasNonInteractive)
            {
                return "Interactive (" + joined + ")";
            }

            if (hasNonInteractive && !hasInteractive)
            {
                return "Non-interactive (" + joined + ")";
            }

            return "Mixed (" + joined + ")";
        }

        if (row.TryGetProperty("isInteractive", out var i1) && i1.ValueKind == JsonValueKind.True)
        {
            return "Interactive (Entra isInteractive flag)";
        }

        if (row.TryGetProperty("isInteractive", out var i0) && i0.ValueKind == JsonValueKind.False)
        {
            return "Non-interactive (Entra isInteractive flag)";
        }

        if (hasInteractive)
        {
            return "Interactive (inferred)";
        }

        if (hasNonInteractive)
        {
            return "Non-interactive (inferred; refresh, device code, or workload identity where types were omitted)";
        }

        return "Sign-in (classification unclear in sample row)";
    }

    private static DateTime? ParseAuditSignInCreatedUtc(JsonElement row)
    {
        var raw = GetString(row, "createdDateTime");
        if (string.IsNullOrWhiteSpace(raw))
        {
            return null;
        }

        return DateTime.TryParse(raw, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal, out var dt)
            ? dt.ToUniversalTime()
            : null;
    }

    private static bool JsonCredentialArrayNonEmpty(JsonElement sp, string propertyName) =>
        sp.TryGetProperty(propertyName, out var arr) && arr.ValueKind == JsonValueKind.Array && arr.GetArrayLength() > 0;

    private sealed record AppRegistrationMeta(
        bool HasKey,
        bool HasSecret,
        DateTime? AppModifiedUtc,
        IReadOnlyList<string> OwnerLines,
        bool HasFederatedCredentials,
        DateTime? ClientSecretExpiresUtc,
        DateTime? CertificateExpiresUtc,
        bool ClientSecretExpired,
        bool CertificateExpired);

    private async Task<Dictionary<string, AppRegistrationMeta>> GetApplicationMetadataByAppIdAsync(
        string graphToken,
        CancellationToken cancellationToken)
    {
        var map = new Dictionary<string, AppRegistrationMeta>(StringComparer.OrdinalIgnoreCase);
        const string v1Url =
            "https://graph.microsoft.com/v1.0/applications?$select=appId,keyCredentials,passwordCredentials,lastModifiedDateTime" +
            "&$expand=owners($select=displayName,mail,userPrincipalName)";
        var apps = await GetJsonCollectionAsync(v1Url, graphToken, cancellationToken);

        var federatedByAppId = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        try
        {
            var fedApps = await GetJsonCollectionAsync(
                "https://graph.microsoft.com/beta/applications?$select=appId&$expand=federatedIdentityCredentials($select=id)",
                graphToken,
                cancellationToken);
            foreach (var a in fedApps)
            {
                var aid = GetString(a, "appId");
                if (string.IsNullOrWhiteSpace(aid))
                {
                    continue;
                }

                federatedByAppId[aid] = ParseHasFederatedIdentityCredentials(a);
            }
        }
        catch
        {
            // Beta optional; federated column stays false.
        }

        foreach (var app in apps)
        {
            var appId = GetString(app, "appId");
            if (string.IsNullOrWhiteSpace(appId))
            {
                continue;
            }

            var modified = ParseODataDateTime(app, "lastModifiedDateTime");
            var ownerLines = ParseApplicationOwnerLines(app);
            var hasFed = federatedByAppId.TryGetValue(appId, out var hf) && hf;
            var (secretEnd, secretExpired) = ParseCredentialArrayEarliestAndExpired(app, "passwordCredentials");
            var (certEnd, certExpired) = ParseCredentialArrayEarliestAndExpired(app, "keyCredentials");
            map[appId] = new AppRegistrationMeta(
                JsonCredentialArrayNonEmpty(app, "keyCredentials"),
                JsonCredentialArrayNonEmpty(app, "passwordCredentials"),
                modified,
                ownerLines,
                hasFed,
                secretEnd,
                certEnd,
                secretExpired,
                certExpired);
        }

        return map;
    }

    private static List<string> ParseApplicationOwnerLines(JsonElement app)
    {
        var lines = new List<string>();
        if (!app.TryGetProperty("owners", out var owners) || owners.ValueKind != JsonValueKind.Array)
        {
            return lines;
        }

        foreach (var o in owners.EnumerateArray())
        {
            var dn = GetString(o, "displayName");
            var mail = GetString(o, "mail");
            var upn = GetString(o, "userPrincipalName");
            var label = !string.IsNullOrWhiteSpace(dn) ? dn : (!string.IsNullOrWhiteSpace(upn) ? upn : mail);
            if (string.IsNullOrWhiteSpace(label))
            {
                continue;
            }

            if (!string.IsNullOrWhiteSpace(mail) && !label.Contains(mail, StringComparison.OrdinalIgnoreCase))
            {
                lines.Add($"{label} ({mail})");
            }
            else
            {
                lines.Add(label);
            }
        }

        return lines;
    }

    private static bool ParseHasFederatedIdentityCredentials(JsonElement app)
    {
        return app.TryGetProperty("federatedIdentityCredentials", out var fed)
               && fed.ValueKind == JsonValueKind.Array
               && fed.GetArrayLength() > 0;
    }

    private static (DateTime? EarliestEndUtc, bool AnyExpired) ParseCredentialArrayEarliestAndExpired(JsonElement app, string arrayName)
    {
        DateTime? earliest = null;
        var anyExpired = false;
        var now = DateTime.UtcNow;
        if (!app.TryGetProperty(arrayName, out var arr) || arr.ValueKind != JsonValueKind.Array)
        {
            return (null, false);
        }

        foreach (var item in arr.EnumerateArray())
        {
            var end = ParseODataDateTime(item, "endDateTime");
            if (!end.HasValue)
            {
                continue;
            }

            if (!earliest.HasValue || end.Value < earliest.Value)
            {
                earliest = end.Value;
            }

            if (end.Value < now)
            {
                anyExpired = true;
            }
        }

        return (earliest, anyExpired);
    }

    private async Task<List<string>> GetServicePrincipalOwnerLinesAsync(string servicePrincipalId, string graphToken, CancellationToken cancellationToken)
    {
        var lines = new List<string>();
        if (string.IsNullOrWhiteSpace(servicePrincipalId))
        {
            return lines;
        }

        try
        {
            var enc = Uri.EscapeDataString(servicePrincipalId);
            var rows = await GetJsonCollectionAsync(
                $"https://graph.microsoft.com/v1.0/servicePrincipals/{enc}/owners?$select=displayName,mail,userPrincipalName",
                graphToken,
                cancellationToken);
            foreach (var o in rows)
            {
                var dn = GetString(o, "displayName");
                var mail = GetString(o, "mail");
                var upn = GetString(o, "userPrincipalName");
                var label = !string.IsNullOrWhiteSpace(dn) ? dn : (!string.IsNullOrWhiteSpace(upn) ? upn : mail);
                if (string.IsNullOrWhiteSpace(label))
                {
                    continue;
                }

                if (!string.IsNullOrWhiteSpace(mail) && !label.Contains(mail, StringComparison.OrdinalIgnoreCase))
                {
                    lines.Add($"{label} ({mail})");
                }
                else
                {
                    lines.Add(label);
                }
            }
        }
        catch
        {
            // ignore
        }

        return lines;
    }

    private static DateTime? ParseODataDateTime(JsonElement obj, string propertyName)
    {
        if (!obj.TryGetProperty(propertyName, out var node) || node.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        var raw = node.ValueKind == JsonValueKind.String ? node.GetString() : null;
        if (string.IsNullOrWhiteSpace(raw))
        {
            return null;
        }

        return DateTime.TryParse(raw, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal, out var dt)
            ? dt.ToUniversalTime()
            : null;
    }

    /// <summary>
    /// Per-SP sign-in from <c>signInActivity</c> (beta then v1). Aggregates every *DateTime field on the object so app-only and delegated usage match
    /// <see href="https://learn.microsoft.com/en-us/graph/api/resources/serviceprincipalsigninactivity">servicePrincipalSignInActivity</see>-style reporting.
    /// </summary>
    private async Task<AppSignInSnapshot> LoadServicePrincipalSignInSnapshotAsync(
        string servicePrincipalId,
        string graphToken,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(servicePrincipalId))
        {
            return new AppSignInSnapshot(null, null, null);
        }

        var encoded = Uri.EscapeDataString(servicePrincipalId);
        const string select = "id,signInActivity";
        var doc = await GetJsonWithRetryAsync($"https://graph.microsoft.com/beta/servicePrincipals/{encoded}?$select={select}", graphToken, cancellationToken)
                  ?? await GetJsonWithRetryAsync($"https://graph.microsoft.com/v1.0/servicePrincipals/{encoded}?$select={select}", graphToken, cancellationToken);

        if (doc is null)
        {
            return new AppSignInSnapshot(null, null, null);
        }

        var root = doc.Value;
        DateTime? li = null;
        DateTime? ln = null;
        DateTime? agg = null;
        if (root.TryGetProperty("signInActivity", out var signIn) && signIn.ValueKind == JsonValueKind.Object)
        {
            foreach (var prop in signIn.EnumerateObject())
            {
                if (prop.Value.ValueKind != JsonValueKind.String)
                {
                    continue;
                }

                if (!prop.Name.EndsWith("DateTime", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                var raw = prop.Value.GetString();
                if (string.IsNullOrWhiteSpace(raw)
                    || !DateTime.TryParse(raw, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal, out var parsed))
                {
                    continue;
                }

                var du = parsed.ToUniversalTime();
                agg = !agg.HasValue || du > agg.Value ? du : agg;
            }

            li = ParseDateUtc(signIn, "lastSignInDateTime");
            ln = ParseDateUtc(signIn, "lastNonInteractiveSignInDateTime");
            var ls = ParseDateUtc(signIn, "lastSuccessfulSignInDateTime");
            // Do not push lastSuccessfulSignInDateTime into the non-interactive bucket when lastSignIn is empty — that mislabels many delegated flows.
            // When Graph only returns lastSuccessfulSignInDateTime, treat it as interactive so the "Interactive" line matches Entra portal behavior for user sign-in.
            if (ls.HasValue && !li.HasValue && !ln.HasValue)
            {
                li = ls;
            }

            agg = MaxUtc(MaxUtc(MaxUtc(agg, li), ln), ls);
        }

        return NormalizeAppSignInSnapshotForDisplay(new AppSignInSnapshot(li, ln, agg));
    }

    private async Task<(bool HasKey, bool HasSecret)> LoadServicePrincipalCredentialFlagsAsync(
        string servicePrincipalId,
        string graphToken,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(servicePrincipalId))
        {
            return (false, false);
        }

        var encoded = Uri.EscapeDataString(servicePrincipalId);
        const string select = "keyCredentials,passwordCredentials";
        var doc = await GetJsonAsync($"https://graph.microsoft.com/beta/servicePrincipals/{encoded}?$select={select}", graphToken, cancellationToken)
                  ?? await GetJsonAsync($"https://graph.microsoft.com/v1.0/servicePrincipals/{encoded}?$select={select}", graphToken, cancellationToken);
        if (doc is null)
        {
            return (false, false);
        }

        var root = doc.Value;
        return (JsonCredentialArrayNonEmpty(root, "keyCredentials"), JsonCredentialArrayNonEmpty(root, "passwordCredentials"));
    }

    private static string FormatAppSignInLine(DateTime? utc) =>
        utc.HasValue ? utc.Value.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture) + " UTC" : "Never";

    private static List<string> ExtractEntraPimGroupNames(IEnumerable<string> roleStrings)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var r in roleStrings)
        {
            const string marker = "(via group:";
            var i = r.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
            if (i < 0)
            {
                continue;
            }

            var start = i + marker.Length;
            var end = r.LastIndexOf(')');
            if (end <= start)
            {
                continue;
            }

            var name = r[start..end].Trim();
            if (!string.IsNullOrWhiteSpace(name))
            {
                set.Add(name);
            }
        }

        return set.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToList();
    }

    private async Task ExpandPrivilegedUsersFromDirectoryPimSchedulesAsync(
        Dictionary<string, HashSet<string>> userRolesMap,
        string graphToken,
        CancellationToken cancellationToken,
        MergedDirectoryPimEligibility mergedEligibility)
    {
        var principalIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var item in mergedEligibility.Schedules)
        {
            if (!IsEntraEligibilityRowStillEffective(item, DateTime.UtcNow))
            {
                continue;
            }

            // Always record principals for effective eligibility rows. Do not gate on resolved displayName:
            // if expand/catalog failed earlier, skipping here left eligible-only users out of userRolesMap entirely.
            var principalId = GetString(item, "principalId");
            if (!string.IsNullOrWhiteSpace(principalId))
            {
                principalIds.Add(principalId);
            }
        }

        foreach (var item in mergedEligibility.Instances)
        {
            if (!IsEntraEligibilityRowStillEffective(item, DateTime.UtcNow))
            {
                continue;
            }

            var principalId = GetString(item, "principalId");
            if (!string.IsNullOrWhiteSpace(principalId))
            {
                principalIds.Add(principalId);
            }
        }

        var assignAll = await GetJsonCollectionAsync(
            "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentSchedules" + GraphDirectoryRoleEligibilityExpand,
            graphToken,
            cancellationToken);
        foreach (var item in assignAll)
        {
            var principalId = GetString(item, "principalId");
            if (!string.IsNullOrWhiteSpace(principalId))
            {
                principalIds.Add(principalId);
            }
        }

        var assignInstAll = await GetJsonCollectionAsync(
            "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances" + GraphDirectoryRoleEligibilityExpand,
            graphToken,
            cancellationToken);
        foreach (var item in assignInstAll)
        {
            var principalId = GetString(item, "principalId");
            if (!string.IsNullOrWhiteSpace(principalId))
            {
                principalIds.Add(principalId);
            }
        }

        foreach (var item in mergedEligibility.Requests)
        {
            if (!ShouldIncludeEntraEligibilityScheduleRequest(item))
            {
                continue;
            }

            var principalId = GetString(item, "principalId");
            if (!string.IsNullOrWhiteSpace(principalId))
            {
                principalIds.Add(principalId);
            }
        }

        foreach (var pid in principalIds)
        {
            if (userRolesMap.ContainsKey(pid))
            {
                continue;
            }

            var obj = await GetJsonAsync(
                $"https://graph.microsoft.com/v1.0/directoryObjects/{Uri.EscapeDataString(pid)}?$select=id,@odata.type",
                graphToken,
                cancellationToken);
            if (obj is null)
            {
                continue;
            }

            var otype = GetString(obj.Value, "@odata.type");
            if (otype.Equals("#microsoft.graph.user", StringComparison.OrdinalIgnoreCase))
            {
                userRolesMap[pid] = [];
                continue;
            }

            if (!otype.Equals("#microsoft.graph.group", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var groupMembers = await GetJsonCollectionAsync(
                $"https://graph.microsoft.com/v1.0/groups/{Uri.EscapeDataString(pid)}/transitiveMembers?$select=id,@odata.type",
                graphToken,
                cancellationToken);
            foreach (var gm in groupMembers)
            {
                if (!GetString(gm, "@odata.type").Equals("#microsoft.graph.user", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                var uid = GetString(gm, "id");
                if (string.IsNullOrWhiteSpace(uid) || userRolesMap.ContainsKey(uid))
                {
                    continue;
                }

                userRolesMap[uid] = [];
            }
        }
    }

    private async Task MergeAzureOnlyPrivilegedUserIdsAsync(
        Dictionary<string, HashSet<string>> userRolesMap,
        string graphToken,
        string armToken,
        CancellationToken cancellationToken)
    {
        var discovered = new ConcurrentDictionary<string, byte>(StringComparer.OrdinalIgnoreCase);
        var principalIsUserCache = new ConcurrentDictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        try
        {
            var subs = await GetJsonCollectionAsync("https://management.azure.com/subscriptions?api-version=2022-12-01", armToken, cancellationToken);
            var sem = new SemaphoreSlim(10, 10);
            var tasks = subs.Select(async sub =>
            {
                await sem.WaitAsync(cancellationToken).ConfigureAwait(false);
                try
                {
                    var subId = GetString(sub, "subscriptionId");
                    if (string.IsNullOrWhiteSpace(subId))
                    {
                        return;
                    }

                    var baseUrl =
                        $"https://management.azure.com/subscriptions/{Uri.EscapeDataString(subId)}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01";
                    var rows = await GetArmJsonCollectionAsync(baseUrl, armToken, cancellationToken).ConfigureAwait(false);
                    foreach (var ra in rows)
                    {
                        if (!ra.TryGetProperty("properties", out var props) || props.ValueKind != JsonValueKind.Object)
                        {
                            continue;
                        }

                        var principalId = GetString(props, "principalId");
                        if (string.IsNullOrWhiteSpace(principalId))
                        {
                            continue;
                        }

                        var roleDefId = GetString(props, "roleDefinitionId");
                        var roleName = await ResolveAzureRoleNameAsync(roleDefId, GetString(props, "scope"), armToken, cancellationToken).ConfigureAwait(false);
                        if (!IsPrivilegedAzureRole(roleName))
                        {
                            continue;
                        }

                        if (!principalIsUserCache.TryGetValue(principalId, out var isUser))
                        {
                            isUser = await IsGraphUserPrincipalAsync(principalId, graphToken, cancellationToken).ConfigureAwait(false);
                            principalIsUserCache[principalId] = isUser;
                        }

                        if (isUser)
                        {
                            discovered[principalId] = 0;
                        }
                    }
                }
                finally
                {
                    sem.Release();
                }
            });
            await Task.WhenAll(tasks).ConfigureAwait(false);
        }
        catch
        {
            // Subscription enumeration may be denied.
        }

        foreach (var id in discovered.Keys)
        {
            if (!userRolesMap.ContainsKey(id))
            {
                userRolesMap[id] = [];
            }
        }
    }

    private async Task<bool> IsGraphUserPrincipalAsync(string objectId, string graphToken, CancellationToken cancellationToken)
    {
        var doc = await GetJsonAsync(
            $"https://graph.microsoft.com/v1.0/users/{Uri.EscapeDataString(objectId)}?$select=id",
            graphToken,
            cancellationToken).ConfigureAwait(false);
        return doc.HasValue;
    }

    /// <summary>
    /// Azure PIM and RBAC list APIs require a <see href="https://learn.microsoft.com/en-us/rest/api/authorization/role-eligibility-schedule-instances/list-for-scope">scope</see>
    /// Returns <c>subscriptions/{{id}}</c> prefixes for each readable subscription (ARM list-for-scope pattern). Unscoped <c>/providers/Microsoft.Authorization/…</c> calls omit assignments.
    /// </summary>
    private async Task<List<string>> ListAzureArmScopePrefixesAsync(string armToken, CancellationToken cancellationToken)
    {
        var list = new List<string>();
        try
        {
            var subs = await GetArmJsonCollectionAsync(
                    "https://management.azure.com/subscriptions?api-version=2022-12-01",
                    armToken,
                    cancellationToken)
                .ConfigureAwait(false);
            foreach (var sub in subs)
            {
                var id = GetString(sub, "subscriptionId");
                if (!string.IsNullOrWhiteSpace(id))
                {
                    list.Add($"subscriptions/{id}");
                    list.Add($"providers/Microsoft.Subscription/subscriptions/{id}");
                }
            }
        }
        catch
        {
            // Subscription enumeration may be denied.
        }

        return list.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static List<string> DedupeEntraRoleLines(IEnumerable<string> lines)
    {
        var best = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var r in lines)
        {
            var key = EntraRoleDisplayKey(r);
            if (!best.TryGetValue(key, out var cur))
            {
                best[key] = r;
                continue;
            }

            best[key] = PreferEntraRoleLine(cur, r);
        }

        return best.Values.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static string EntraRoleDisplayKey(string r)
    {
        var i = r.IndexOf(" (via group:", StringComparison.OrdinalIgnoreCase);
        return i > 0 ? r[..i].Trim() : r.Trim();
    }

    private static string PreferEntraRoleLine(string a, string b)
    {
        var aVia = a.Contains("(via group:", StringComparison.OrdinalIgnoreCase);
        var bVia = b.Contains("(via group:", StringComparison.OrdinalIgnoreCase);
        // Same role key can appear as plain text (directory role member, JIT principal=user) and as "(via group: …)" from PIM schedules.
        // Keep the group-qualified line so PIM group assignments and EntraPimGroupNames stay accurate.
        if (aVia && !bVia)
        {
            return a;
        }

        if (!aVia && bVia)
        {
            return b;
        }

        return string.Compare(a, b, StringComparison.OrdinalIgnoreCase) <= 0 ? a : b;
    }

    private static List<EntraEligibleRoleLine> DedupeEntraEligibleRoleLines(IEnumerable<EntraEligibleRoleLine> rows)
    {
        var best = new Dictionary<string, EntraEligibleRoleLine>(StringComparer.OrdinalIgnoreCase);
        foreach (var row in rows)
        {
            var key = string.IsNullOrWhiteSpace(row.DedupeKey) ? EntraRoleDisplayKey(row.Line) : row.DedupeKey;
            if (!best.TryGetValue(key, out var cur))
            {
                best[key] = row;
                continue;
            }

            var mergedLine = PreferEntraRoleLine(cur.Line, row.Line);
            var mergedExp = PreferEntraEligibleExpiration(cur.ExpiresDisplay, row.ExpiresDisplay);
            best[key] = new EntraEligibleRoleLine { Line = mergedLine, ExpiresDisplay = mergedExp, DedupeKey = key };
        }

        return best.Values.OrderBy(x => x.Line, StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static string EntraViaGroupKeyPart(string line)
    {
        const string marker = " (via group:";
        var i = line.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
        if (i < 0)
        {
            return string.Empty;
        }

        var start = i + marker.Length;
        var end = line.IndexOf(')', start);
        if (end < start)
        {
            return string.Empty;
        }

        return line[start..end].Trim();
    }

    private static string AppendEntraDirectoryScopeEligibleSuffix(string line, JsonElement item)
    {
        var scope = GetString(item, "directoryScopeId").Trim();
        if (string.IsNullOrWhiteSpace(scope) || scope.Equals("/", StringComparison.Ordinal))
        {
            return line;
        }

        return $"{line} (Entra scope: {scope})";
    }

    private static string BuildEntraEligibleDedupeKey(string lineBeforeScopeSuffix, JsonElement item)
    {
        var rd = GetString(item, "roleDefinitionId").Trim();
        var scope = GetString(item, "directoryScopeId").Trim();
        var via = EntraViaGroupKeyPart(lineBeforeScopeSuffix);
        if (string.IsNullOrWhiteSpace(rd))
        {
            return $"{lineBeforeScopeSuffix.Trim()}\u0001{scope}\u0001{via}";
        }

        return $"{rd}\u0001{scope}\u0001{via}";
    }

    private static EntraEligibleRoleLine ToEntraEligibleLine(string lineBeforeScope, string expiresDisplay, JsonElement item)
    {
        var dk = BuildEntraEligibleDedupeKey(lineBeforeScope, item);
        var line = AppendEntraDirectoryScopeEligibleSuffix(lineBeforeScope, item);
        return new EntraEligibleRoleLine { Line = line, ExpiresDisplay = expiresDisplay, DedupeKey = dk };
    }

    private static string PreferEntraEligibleExpiration(string a, string b)
    {
        if (string.Equals(a, b, StringComparison.OrdinalIgnoreCase))
        {
            return a;
        }

        if (a.Equals("Unknown", StringComparison.OrdinalIgnoreCase))
        {
            return b;
        }

        if (b.Equals("Unknown", StringComparison.OrdinalIgnoreCase))
        {
            return a;
        }

        if (a.Equals("Never", StringComparison.OrdinalIgnoreCase) && !b.Equals("Never", StringComparison.OrdinalIgnoreCase))
        {
            return b;
        }

        if (b.Equals("Never", StringComparison.OrdinalIgnoreCase) && !a.Equals("Never", StringComparison.OrdinalIgnoreCase))
        {
            return a;
        }

        return a;
    }

    /// <summary>Directory PIM / roleEligibilitySchedules: end for report &quot;Expires: …&quot; line.</summary>
    private static string FormatEntraGraphEligibilityEndDisplay(JsonElement item)
    {
        if (item.TryGetProperty("scheduleInfo", out var si0) && si0.ValueKind == JsonValueKind.Object
            && si0.TryGetProperty("expiration", out var exp0) && exp0.ValueKind == JsonValueKind.Object
            && exp0.TryGetProperty("type", out var tp0) && tp0.ValueKind == JsonValueKind.String
            && (tp0.GetString() ?? string.Empty).Equals("noEnd", StringComparison.OrdinalIgnoreCase))
        {
            return "Never";
        }

        if (item.TryGetProperty("endDateTime", out var endTop) && endTop.ValueKind == JsonValueKind.String)
        {
            if (TryParseGraphODataDateTime(endTop.GetString(), out var utc))
            {
                if (utc.Year < 1970 || utc.Year >= 9999)
                {
                    return "Never";
                }

                return utc.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) + " UTC";
            }

            return "Unknown";
        }

        if (item.TryGetProperty("scheduleInfo", out var si) && si.ValueKind == JsonValueKind.Object
            && si.TryGetProperty("expiration", out var exp) && exp.ValueKind == JsonValueKind.Object
            && exp.TryGetProperty("endDateTime", out var endExp) && endExp.ValueKind == JsonValueKind.String)
        {
            if (TryParseGraphODataDateTime(endExp.GetString(), out var utc))
            {
                if (utc.Year < 1970 || utc.Year >= 9999)
                {
                    return "Never";
                }

                return utc.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) + " UTC";
            }

            return "Unknown";
        }

        return "Never";
    }

    /// <summary>Identity Governance PIM-for-groups schedule rows (root <c>endDateTime</c>).</summary>
    private static string FormatPrivilegedAccessGroupEligibilityEndDisplay(JsonElement item)
    {
        if (!item.TryGetProperty("endDateTime", out var en) || en.ValueKind != JsonValueKind.String)
        {
            return "Never";
        }

        if (!TryParseGraphODataDateTime(en.GetString(), out var utc))
        {
            return "Unknown";
        }

        if (utc.Year < 1970 || utc.Year >= 9999)
        {
            return "Never";
        }

        return utc.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) + " UTC";
    }

    /// <summary>ARM role eligibility instance/schedule <c>properties</c> blob.</summary>
    private static string FormatArmPimEligibilityEndDisplay(JsonElement props)
    {
        static bool TryFromStringProperty(JsonElement obj, string name, out string formatted)
        {
            formatted = "Never";
            if (!obj.TryGetProperty(name, out var p) || p.ValueKind != JsonValueKind.String)
            {
                return false;
            }

            if (!TryParseGraphODataDateTime(p.GetString(), out var utc))
            {
                formatted = "Unknown";
                return true;
            }

            if (utc.Year < 1970 || utc.Year >= 9999)
            {
                formatted = "Never";
                return true;
            }

            formatted = utc.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) + " UTC";
            return true;
        }

        if (TryFromStringProperty(props, "endDateTime", out var fromTop))
        {
            return fromTop;
        }

        if (props.TryGetProperty("expandedProperties", out var exp) && exp.ValueKind == JsonValueKind.Object
            && TryFromStringProperty(exp, "endDateTime", out var fromExp))
        {
            return fromExp;
        }

        return "Never";
    }

    private static string? PreferAzureEligibleExpiration(string? a, string? b)
    {
        if (string.IsNullOrWhiteSpace(a) || a.Equals("Unknown", StringComparison.OrdinalIgnoreCase))
        {
            return string.IsNullOrWhiteSpace(b) ? a : b;
        }

        if (string.IsNullOrWhiteSpace(b) || b.Equals("Unknown", StringComparison.OrdinalIgnoreCase))
        {
            return a;
        }

        if (a.Equals("Never", StringComparison.OrdinalIgnoreCase) && !b.Equals("Never", StringComparison.OrdinalIgnoreCase))
        {
            return b;
        }

        if (b.Equals("Never", StringComparison.OrdinalIgnoreCase) && !a.Equals("Never", StringComparison.OrdinalIgnoreCase))
        {
            return a;
        }

        return a;
    }

    private static List<AzureRoleLine> MergeAndDedupeAzureRoleLines(List<AzureRoleLine> lines)
    {
        var dict = new Dictionary<string, AzureRoleLine>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in lines)
        {
            var key = AzureRoleLineDedupKey(line);
            if (!dict.TryGetValue(key, out var existing))
            {
                dict[key] = line;
                continue;
            }

            dict[key] = MergeAzureRoleLine(existing, line);
        }

        return dict.Values.ToList();
    }

    private static string AzureRoleLineDedupKey(AzureRoleLine x)
    {
        var scopePath = NormalizeArmScopePath(x.ArmScopePath);
        var scope = !string.IsNullOrWhiteSpace(scopePath) ? scopePath : NormalizeScopeDetailForDedup(x.ScopeDetail);
        return $"{x.RoleName}\u001f{scope}";
    }

    private static string NormalizeArmScopePath(string? p)
    {
        if (string.IsNullOrWhiteSpace(p))
        {
            return string.Empty;
        }

        var t = p.Trim();
        if (t.Equals("/", StringComparison.Ordinal))
        {
            return "/";
        }

        return t.TrimEnd('/');
    }

    private static string NormalizeScopeDetailForDedup(string? d)
    {
        if (string.IsNullOrWhiteSpace(d))
        {
            return string.Empty;
        }

        if (d.Contains("tenant root", StringComparison.OrdinalIgnoreCase))
        {
            return "/";
        }

        return d.Trim();
    }

    private static AzureRoleLine MergeAzureRoleLine(AzureRoleLine a, AzureRoleLine b)
    {
        var via = a.ViaGroup || b.ViaGroup;
        var gName = PreferAzureGroupDisplayName(a.GroupDisplayName, b.GroupDisplayName);
        var armPath = !string.IsNullOrWhiteSpace(a.ArmScopePath) ? a.ArmScopePath : b.ArmScopePath;
        var scopeDetail = !string.IsNullOrWhiteSpace(a.ScopeDetail) ? a.ScopeDetail : b.ScopeDetail;
        if (string.IsNullOrWhiteSpace(scopeDetail) && !string.IsNullOrWhiteSpace(b.ScopeDetail))
        {
            scopeDetail = b.ScopeDetail;
        }

        return new AzureRoleLine
        {
            RoleName = a.RoleName,
            ScopeDetail = scopeDetail ?? string.Empty,
            ViaGroup = via,
            GroupDisplayName = gName,
            ArmScopePath = armPath,
            FromPermanentArmRbac = a.FromPermanentArmRbac && b.FromPermanentArmRbac,
            EligibleExpiresDisplay = PreferAzureEligibleExpiration(a.EligibleExpiresDisplay, b.EligibleExpiresDisplay)
        };
    }

    private static string? PreferAzureGroupDisplayName(string? a, string? b)
    {
        if (string.IsNullOrWhiteSpace(a))
        {
            return b;
        }

        if (string.IsNullOrWhiteSpace(b))
        {
            return a;
        }

        var aGuid = Guid.TryParse(a, out _);
        var bGuid = Guid.TryParse(b, out _);
        if (aGuid && !bGuid)
        {
            return b;
        }

        if (bGuid && !aGuid)
        {
            return a;
        }

        return a;
    }

    private static List<AzureRoleLine> OrderAzureRoleLines(List<AzureRoleLine> lines) =>
        lines.OrderBy(x => x.RoleName, StringComparer.OrdinalIgnoreCase).ThenBy(x => x.ScopeDetail, StringComparer.OrdinalIgnoreCase).ToList();

    private const string UnknownGroupLabel = "Unknown group";

    private async Task<List<AzureRoleLine>> ResolveGuidsInAzureRoleLinesAsync(
        List<AzureRoleLine> lines,
        string graphToken,
        CancellationToken cancellationToken)
    {
        var outList = new List<AzureRoleLine>(lines.Count);
        foreach (var line in lines)
        {
            var gName = line.GroupDisplayName;
            if (line.ViaGroup && !string.IsNullOrWhiteSpace(gName) && Guid.TryParse(gName, out _))
            {
                var resolved = await TryResolveGraphGroupDisplayNameAsync(gName, graphToken, cancellationToken).ConfigureAwait(false);
                if (!string.IsNullOrWhiteSpace(resolved))
                {
                    gName = resolved;
                }
                else if (Guid.TryParse(gName, out _))
                {
                    gName = UnknownGroupLabel;
                }
            }

            outList.Add(new AzureRoleLine
            {
                RoleName = line.RoleName,
                ScopeDetail = line.ScopeDetail,
                ViaGroup = line.ViaGroup,
                GroupDisplayName = gName,
                ArmScopePath = line.ArmScopePath,
                FromPermanentArmRbac = line.FromPermanentArmRbac,
                EligibleExpiresDisplay = line.EligibleExpiresDisplay
            });
        }

        return outList;
    }

    private async Task<string?> TryResolveGraphGroupDisplayNameAsync(string groupId, string graphToken, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(groupId))
        {
            return null;
        }

        if (_graphGroupDisplayCache.TryGetValue(groupId, out var cached))
        {
            return cached;
        }

        var enc = Uri.EscapeDataString(groupId);
        string? name = null;

        var g = await GetJsonAsync(
            $"https://graph.microsoft.com/v1.0/groups/{enc}?$select=displayName",
            graphToken,
            cancellationToken).ConfigureAwait(false);
        if (g.HasValue)
        {
            var dn = GetString(g.Value, "displayName");
            if (!string.IsNullOrWhiteSpace(dn))
            {
                name = dn;
            }
        }

        if (string.IsNullOrWhiteSpace(name))
        {
            var obj = await GetJsonAsyncWithConsistencyAsync(
                $"https://graph.microsoft.com/v1.0/directoryObjects/{enc}?$select=displayName,@odata.type",
                graphToken,
                cancellationToken,
                "eventual").ConfigureAwait(false);
            if (obj.HasValue)
            {
                var otype = GetString(obj.Value, "@odata.type");
                if (otype.Contains("group", StringComparison.OrdinalIgnoreCase))
                {
                    var dn = GetString(obj.Value, "displayName");
                    if (!string.IsNullOrWhiteSpace(dn))
                    {
                        name = dn;
                    }
                }
            }
        }

        if (string.IsNullOrWhiteSpace(name))
        {
            var bg = await GetJsonAsync(
                $"https://graph.microsoft.com/beta/groups/{enc}?$select=displayName",
                graphToken,
                cancellationToken).ConfigureAwait(false);
            if (bg.HasValue)
            {
                var dn = GetString(bg.Value, "displayName");
                if (!string.IsNullOrWhiteSpace(dn))
                {
                    name = dn;
                }
            }
        }

        if (string.IsNullOrWhiteSpace(name))
        {
            var bobj = await GetJsonAsyncWithConsistencyAsync(
                $"https://graph.microsoft.com/beta/directoryObjects/{enc}?$select=displayName,@odata.type",
                graphToken,
                cancellationToken,
                "eventual").ConfigureAwait(false);
            if (bobj.HasValue)
            {
                var otype = GetString(bobj.Value, "@odata.type");
                if (otype.Contains("group", StringComparison.OrdinalIgnoreCase))
                {
                    var dn = GetString(bobj.Value, "displayName");
                    if (!string.IsNullOrWhiteSpace(dn))
                    {
                        name = dn;
                    }
                }
            }
        }

        if (string.IsNullOrWhiteSpace(name))
        {
            name = await DirectoryObjectsGetByIdsLookupGroupDisplayNameAsync(groupId, graphToken, cancellationToken).ConfigureAwait(false);
        }

        _graphGroupDisplayCache[groupId] = name;
        return name;
    }

    private async Task PopulateGroupDisplayNamesForAzureRbacAsync(
        List<string> groupIds,
        Dictionary<string, string> groupDisplayById,
        string graphToken,
        CancellationToken cancellationToken)
    {
        var distinct = groupIds
            .Where(g => !string.IsNullOrWhiteSpace(g))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (distinct.Count == 0)
        {
            return;
        }

        var sem = new SemaphoreSlim(24, 24);
        await Task.WhenAll(distinct.Select(async gid =>
        {
            await sem.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var name = await TryResolveGraphGroupDisplayNameAsync(gid, graphToken, cancellationToken).ConfigureAwait(false);
                var label = string.IsNullOrWhiteSpace(name)
                    ? (Guid.TryParse(gid, out _) ? UnknownGroupLabel : gid)
                    : name!;
                lock (groupDisplayById)
                {
                    groupDisplayById[gid] = label;
                }
            }
            finally
            {
                sem.Release();
            }
        })).ConfigureAwait(false);
    }

    private async Task<(List<AzureRoleLine> ActiveRoles, List<AzureRoleLine> EligibleRoles)> GetAzureRolesAsync(
        string userId,
        string graphToken,
        string? armToken,
        CancellationToken cancellationToken,
        IReadOnlyList<string>? armScopePrefixesPrefetched = null,
        bool activeAssignmentsOnly = false)
    {
        if (string.IsNullOrWhiteSpace(armToken))
        {
            return ([], []);
        }

        var includeArmEligible = !activeAssignmentsOnly;
        var active = new List<AzureRoleLine>();
        var eligible = new List<AzureRoleLine>();
        var armScopeMergeLock = new object();
        var scopeCache = new ArmScopeDisplayCache();
        var userGroupIds = new List<string>();
        var userGroupIdSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var groupDisplayById = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            userGroupIds = await GetUserTransitiveGroupIdsAsync(userId, graphToken, cancellationToken).ConfigureAwait(false);
            userGroupIdSet = new HashSet<string>(userGroupIds, StringComparer.OrdinalIgnoreCase);
        }
        catch
        {
            // User-scoped and assignedTo() ARM calls still run; group-based expansion is best-effort.
        }

        try
        {
            // PIM for Groups (identityGovernance/privilegedAccess/group/*): merge even when transitiveMemberOf failed above.
            userGroupIdSet = new HashSet<string>(userGroupIds, StringComparer.OrdinalIgnoreCase);

            foreach (var gid in await GetIdentityGovernancePrivilegedAccessGroupIdsForPrincipalAsync(userId, graphToken, cancellationToken).ConfigureAwait(false))
            {
                if (!userGroupIdSet.Add(gid))
                {
                    continue;
                }

                userGroupIds.Add(gid);
            }
        }
        catch
        {
        }

        await PopulateGroupDisplayNamesForAzureRbacAsync(userGroupIds, groupDisplayById, graphToken, cancellationToken).ConfigureAwait(false);

        async Task AddFromArmScheduleInstancesAsync(List<AzureRoleLine> target, string listUrl)
        {
            var rows = await PrivilegedReportArmFetchAsync(listUrl, armToken, cancellationToken).ConfigureAwait(false);
            foreach (var row in rows)
            {
                if (!row.TryGetProperty("properties", out var props) || props.ValueKind != JsonValueKind.Object)
                {
                    continue;
                }

                var scopePath = GetString(props, "scope");
                var roleName = await ResolveAzureRoleNameAsync(GetString(props, "roleDefinitionId"), scopePath, armToken, cancellationToken);
                if (string.Equals(roleName, "Unknown", StringComparison.OrdinalIgnoreCase))
                {
                    roleName = TryGetRoleNameFromProperties(props, roleName);
                }
                if (!IsPrivilegedAzureRole(roleName))
                {
                    continue;
                }

                var scopeLabel = await ScopeToDisplayAsync(scopePath, armToken, scopeCache, cancellationToken).ConfigureAwait(false);
                var memberType = GetString(props, "memberType");
                var principalInRow = GetString(props, "principalId");
                var viaGroup = false;
                string? groupName = null;
                if (!string.IsNullOrWhiteSpace(principalInRow) && userGroupIdSet.Contains(principalInRow))
                {
                    viaGroup = true;
                    if (groupDisplayById.TryGetValue(principalInRow, out var gFromMembership))
                    {
                        groupName = gFromMembership;
                    }
                }
                else if (memberType.Equals("Group", StringComparison.OrdinalIgnoreCase)
                         && !string.IsNullOrWhiteSpace(principalInRow)
                         && !principalInRow.Equals(userId, StringComparison.OrdinalIgnoreCase))
                {
                    viaGroup = true;
                }

                ApplyArmExpandedGroupPrincipal(props, ref viaGroup, ref groupName);
                FinalizeAzureViaGroupForPrincipal(userId, principalInRow, ref viaGroup, ref groupName);

                if (viaGroup && string.IsNullOrWhiteSpace(groupName) && groupDisplayById.TryGetValue(principalInRow, out var gdn))
                {
                    groupName = gdn;
                }
                if (viaGroup && string.IsNullOrWhiteSpace(groupName) && !string.IsNullOrWhiteSpace(principalInRow))
                {
                    groupName = principalInRow;
                }

                target.Add(new AzureRoleLine
                {
                    RoleName = roleName,
                    ScopeDetail = scopeLabel,
                    ViaGroup = viaGroup,
                    GroupDisplayName = string.IsNullOrWhiteSpace(groupName) ? null : groupName,
                    ArmScopePath = string.IsNullOrWhiteSpace(scopePath) ? null : scopePath,
                    FromPermanentArmRbac = false
                });
            }
        }

        async Task AddActiveFromUrlAsync(List<AzureRoleLine> bucket, string url, string? groupId = null)
        {
            var rows = await PrivilegedReportArmFetchAsync(url, armToken, cancellationToken).ConfigureAwait(false);
            foreach (var ra in rows)
            {
                if (!ra.TryGetProperty("properties", out var raProps) || raProps.ValueKind != JsonValueKind.Object)
                {
                    continue;
                }

                var scopePathRa = GetString(raProps, "scope");
                var roleName = await ResolveAzureRoleNameAsync(GetString(raProps, "roleDefinitionId"), scopePathRa, armToken, cancellationToken);
                if (string.Equals(roleName, "Unknown", StringComparison.OrdinalIgnoreCase))
                {
                    roleName = TryGetRoleNameFromProperties(raProps, roleName);
                }
                if (!IsPrivilegedAzureRole(roleName))
                {
                    continue;
                }

                var scopePath = scopePathRa;
                var scopeLabel = await ScopeToDisplayAsync(scopePath, armToken, scopeCache, cancellationToken).ConfigureAwait(false);
                var principalInRow = GetString(raProps, "principalId");
                var viaGroup = !string.IsNullOrWhiteSpace(groupId);
                string? groupName = !string.IsNullOrWhiteSpace(groupId) && groupDisplayById.TryGetValue(groupId, out var gdn) ? gdn : null;
                if (!viaGroup && !string.IsNullOrWhiteSpace(principalInRow) && userGroupIdSet.Contains(principalInRow))
                {
                    viaGroup = true;
                    if (string.IsNullOrWhiteSpace(groupName) && groupDisplayById.TryGetValue(principalInRow, out var gFromMembership))
                    {
                        groupName = gFromMembership;
                    }
                }
                if (viaGroup && string.IsNullOrWhiteSpace(groupName) && !string.IsNullOrWhiteSpace(principalInRow))
                {
                    groupName = principalInRow;
                }

                FinalizeAzureViaGroupForPrincipal(userId, principalInRow, ref viaGroup, ref groupName);
                bucket.Add(new AzureRoleLine
                {
                    RoleName = roleName,
                    ScopeDetail = scopeLabel,
                    ViaGroup = viaGroup,
                    GroupDisplayName = groupName,
                    ArmScopePath = string.IsNullOrWhiteSpace(scopePath) ? null : scopePath,
                    FromPermanentArmRbac = true
                });
            }
        }

        async Task AddEligibleFromUrlAsync(List<AzureRoleLine> bucket, string url, string? groupId = null)
        {
            var rows = await PrivilegedReportArmFetchAsync(url, armToken, cancellationToken).ConfigureAwait(false);
            foreach (var e in rows)
            {
                if (!e.TryGetProperty("properties", out var eProps) || eProps.ValueKind != JsonValueKind.Object)
                {
                    continue;
                }

                var scopePathEl = GetString(eProps, "scope");
                var roleName = await ResolveAzureRoleNameAsync(GetString(eProps, "roleDefinitionId"), scopePathEl, armToken, cancellationToken);
                if (string.Equals(roleName, "Unknown", StringComparison.OrdinalIgnoreCase))
                {
                    roleName = TryGetRoleNameFromProperties(eProps, roleName);
                }
                if (!IsPrivilegedAzureRole(roleName))
                {
                    continue;
                }

                var scopePath = scopePathEl;
                var scopeLabel = await ScopeToDisplayAsync(scopePath, armToken, scopeCache, cancellationToken).ConfigureAwait(false);
                var principalInRow = GetString(eProps, "principalId");
                var viaGroup = !string.IsNullOrWhiteSpace(groupId);
                string? groupName = !string.IsNullOrWhiteSpace(groupId) && groupDisplayById.TryGetValue(groupId, out var gdn) ? gdn : null;
                if (!viaGroup && !string.IsNullOrWhiteSpace(principalInRow) && userGroupIdSet.Contains(principalInRow))
                {
                    viaGroup = true;
                    if (string.IsNullOrWhiteSpace(groupName) && groupDisplayById.TryGetValue(principalInRow, out var gFromMembership))
                    {
                        groupName = gFromMembership;
                    }
                }
                if (viaGroup && string.IsNullOrWhiteSpace(groupName) && !string.IsNullOrWhiteSpace(principalInRow))
                {
                    groupName = principalInRow;
                }

                ApplyArmExpandedGroupPrincipal(eProps, ref viaGroup, ref groupName);
                FinalizeAzureViaGroupForPrincipal(userId, principalInRow, ref viaGroup, ref groupName);
                bucket.Add(new AzureRoleLine
                {
                    RoleName = roleName,
                    ScopeDetail = scopeLabel,
                    ViaGroup = viaGroup,
                    GroupDisplayName = groupName,
                    ArmScopePath = string.IsNullOrWhiteSpace(scopePath) ? null : scopePath,
                    FromPermanentArmRbac = false,
                    EligibleExpiresDisplay = FormatArmPimEligibilityEndDisplay(eProps)
                });
            }
        }

        async Task AddEligibleFromScheduleUrlAsync(List<AzureRoleLine> bucket, string url, string? groupId = null)
        {
            var rows = await PrivilegedReportArmFetchAsync(url, armToken, cancellationToken).ConfigureAwait(false);
            foreach (var e in rows)
            {
                if (!e.TryGetProperty("properties", out var props) || props.ValueKind != JsonValueKind.Object)
                {
                    continue;
                }

                var scopePathSch = GetString(props, "scope");
                var roleName = await ResolveAzureRoleNameAsync(GetString(props, "roleDefinitionId"), scopePathSch, armToken, cancellationToken);
                if (string.Equals(roleName, "Unknown", StringComparison.OrdinalIgnoreCase))
                {
                    roleName = TryGetRoleNameFromProperties(props, roleName);
                }
                if (!IsPrivilegedAzureRole(roleName))
                {
                    continue;
                }

                var scopePath = scopePathSch;
                var scopeLabel = await ScopeToDisplayAsync(scopePath, armToken, scopeCache, cancellationToken).ConfigureAwait(false);
                var memberType = GetString(props, "memberType");
                var principalInRow = GetString(props, "principalId");
                var viaGroup = !string.IsNullOrWhiteSpace(groupId);
                string? groupName = !string.IsNullOrWhiteSpace(groupId) && groupDisplayById.TryGetValue(groupId, out var gnById) ? gnById : null;
                if (!string.IsNullOrWhiteSpace(principalInRow) && userGroupIdSet.Contains(principalInRow))
                {
                    viaGroup = true;
                    if (string.IsNullOrWhiteSpace(groupName) && groupDisplayById.TryGetValue(principalInRow, out var gFromMembership))
                    {
                        groupName = gFromMembership;
                    }
                }
                else if (!viaGroup
                         && memberType.Equals("Group", StringComparison.OrdinalIgnoreCase)
                         && !string.IsNullOrWhiteSpace(principalInRow)
                         && !principalInRow.Equals(userId, StringComparison.OrdinalIgnoreCase))
                {
                    viaGroup = true;
                }

                ApplyArmExpandedGroupPrincipal(props, ref viaGroup, ref groupName);
                FinalizeAzureViaGroupForPrincipal(userId, principalInRow, ref viaGroup, ref groupName);

                if (viaGroup && string.IsNullOrWhiteSpace(groupName) && groupDisplayById.TryGetValue(principalInRow, out var gdn))
                {
                    groupName = gdn;
                }
                if (viaGroup && string.IsNullOrWhiteSpace(groupName) && !string.IsNullOrWhiteSpace(principalInRow))
                {
                    groupName = principalInRow;
                }

                bucket.Add(new AzureRoleLine
                {
                    RoleName = roleName,
                    ScopeDetail = scopeLabel,
                    ViaGroup = viaGroup,
                    GroupDisplayName = string.IsNullOrWhiteSpace(groupName) ? null : groupName,
                    ArmScopePath = string.IsNullOrWhiteSpace(scopePath) ? null : scopePath,
                    FromPermanentArmRbac = false,
                    EligibleExpiresDisplay = FormatArmPimEligibilityEndDisplay(props)
                });
            }
        }

        // ARM docs: list PIM/RBAC at each scope with $filter=assignedTo('userId') (includes group-inherited eligible/active).
        // See https://learn.microsoft.com/en-us/rest/api/authorization/role-eligibility-schedule-instances/list-for-scope
        var assignedToEnc = Uri.EscapeDataString($"assignedTo('{userId}')");
        const string armPimVer = "2020-10-01";
        const string armRbacVer = "2022-04-01";
        var scopePrefixes = armScopePrefixesPrefetched != null
            ? armScopePrefixesPrefetched.ToList()
            : await ListAzureArmScopePrefixesAsync(armToken, cancellationToken).ConfigureAwait(false);
        if (scopePrefixes.Count > 0)
        {
            var sem = new SemaphoreSlim(20, 20);
            var scopeTasks = scopePrefixes.Select(async scopePrefix =>
            {
                await sem.WaitAsync(cancellationToken).ConfigureAwait(false);
                try
                {
                    try
                    {
                        var ePart = new List<AzureRoleLine>();
                        var aPart = new List<AzureRoleLine>();
                        var authz = $"https://management.azure.com/{scopePrefix}/providers/Microsoft.Authorization";
                        if (includeArmEligible)
                        {
                            await AddEligibleFromUrlAsync(
                                    ePart,
                                    $"{authz}/roleEligibilityScheduleInstances?$filter={assignedToEnc}&$expand=expandedProperties&api-version={armPimVer}")
                                .ConfigureAwait(false);
                            await AddFromArmScheduleInstancesAsync(
                                    aPart,
                                    $"{authz}/roleAssignmentScheduleInstances?$filter={assignedToEnc}&$expand=expandedProperties&api-version={armPimVer}")
                                .ConfigureAwait(false);
                            await AddEligibleFromScheduleUrlAsync(
                                    ePart,
                                    $"{authz}/roleEligibilitySchedules?$filter={assignedToEnc}&$expand=expandedProperties&api-version={armPimVer}")
                                .ConfigureAwait(false);
                        }

                        await AddActiveFromUrlAsync(aPart, $"{authz}/roleAssignments?api-version={armRbacVer}&$filter={assignedToEnc}")
                            .ConfigureAwait(false);
                        foreach (var groupIdArm in userGroupIds)
                        {
                            if (string.IsNullOrWhiteSpace(groupIdArm))
                            {
                                continue;
                            }

                            var assignedToGroupEnc = Uri.EscapeDataString($"assignedTo('{groupIdArm}')");
                            var pidGroupEnc = Uri.EscapeDataString($"principalId eq '{groupIdArm}'");
                            if (includeArmEligible)
                            {
                                await AddEligibleFromUrlAsync(
                                        ePart,
                                        $"{authz}/roleEligibilityScheduleInstances?$filter={assignedToGroupEnc}&$expand=expandedProperties&api-version={armPimVer}",
                                        groupIdArm)
                                    .ConfigureAwait(false);
                                await AddFromArmScheduleInstancesAsync(
                                        aPart,
                                        $"{authz}/roleAssignmentScheduleInstances?$filter={assignedToGroupEnc}&$expand=expandedProperties&api-version={armPimVer}")
                                    .ConfigureAwait(false);
                                await AddEligibleFromScheduleUrlAsync(
                                        ePart,
                                        $"{authz}/roleEligibilitySchedules?$filter={assignedToGroupEnc}&$expand=expandedProperties&api-version={armPimVer}",
                                        groupIdArm)
                                    .ConfigureAwait(false);
                            }

                            await AddActiveFromUrlAsync(
                                    aPart,
                                    $"{authz}/roleAssignments?api-version={armRbacVer}&$filter={assignedToGroupEnc}",
                                    groupIdArm)
                                .ConfigureAwait(false);
                            if (includeArmEligible)
                            {
                                await AddEligibleFromUrlAsync(
                                        ePart,
                                        $"{authz}/roleEligibilityScheduleInstances?$filter={pidGroupEnc}&$expand=expandedProperties&api-version={armPimVer}",
                                        groupIdArm)
                                    .ConfigureAwait(false);
                                await AddEligibleFromScheduleUrlAsync(
                                        ePart,
                                        $"{authz}/roleEligibilitySchedules?$filter={pidGroupEnc}&$expand=expandedProperties&api-version={armPimVer}",
                                        groupIdArm)
                                    .ConfigureAwait(false);
                                await AddFromArmScheduleInstancesAsync(
                                        aPart,
                                        $"{authz}/roleAssignmentScheduleInstances?$filter={pidGroupEnc}&$expand=expandedProperties&api-version={armPimVer}")
                                    .ConfigureAwait(false);
                            }
                        }

                        if (includeArmEligible)
                        {
                            var pidUserEnc = Uri.EscapeDataString($"principalId eq '{userId}'");
                            await AddEligibleFromUrlAsync(
                                    ePart,
                                    $"{authz}/roleEligibilityScheduleInstances?$filter={pidUserEnc}&$expand=expandedProperties&api-version={armPimVer}")
                                .ConfigureAwait(false);
                            await AddEligibleFromScheduleUrlAsync(
                                    ePart,
                                    $"{authz}/roleEligibilitySchedules?$filter={pidUserEnc}&$expand=expandedProperties&api-version={armPimVer}")
                                .ConfigureAwait(false);
                        }

                        lock (armScopeMergeLock)
                        {
                            if (includeArmEligible)
                            {
                                eligible.AddRange(ePart);
                            }

                            active.AddRange(aPart);
                        }
                    }
                    catch
                    {
                        // Per-subscription ARM errors must not wipe other scopes or legacy fallbacks.
                    }
                }
                finally
                {
                    sem.Release();
                }
            });
            await Task.WhenAll(scopeTasks).ConfigureAwait(false);
        }

        // Always union legacy tenant/provider + principalId paths. Some data appears only at subscription scope, only unscoped, or only via principalId — MergeAndDedupe dedupes.
        if (includeArmEligible)
        {
            await AddEligibleFromUrlAsync(
                eligible,
                $"https://management.azure.com/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?$filter={assignedToEnc}&$expand=expandedProperties&api-version={armPimVer}");
            await AddFromArmScheduleInstancesAsync(
                active,
                $"https://management.azure.com/providers/Microsoft.Authorization/roleAssignmentScheduleInstances?$filter={assignedToEnc}&$expand=expandedProperties&api-version={armPimVer}");
            await AddEligibleFromScheduleUrlAsync(
                eligible,
                $"https://management.azure.com/providers/Microsoft.Authorization/roleEligibilitySchedules?$filter={assignedToEnc}&$expand=expandedProperties&api-version={armPimVer}");
            await AddEligibleFromUrlAsync(
                eligible,
                $"https://management.azure.com/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?api-version={armPimVer}&$expand=expandedProperties&$filter=principalId eq '{userId}'");
            await AddEligibleFromScheduleUrlAsync(
                eligible,
                $"https://management.azure.com/providers/Microsoft.Authorization/roleEligibilitySchedules?api-version={armPimVer}&$expand=expandedProperties&$filter=principalId eq '{userId}'");
            foreach (var groupId in userGroupIds)
            {
                if (string.IsNullOrWhiteSpace(groupId))
                {
                    continue;
                }

                await AddEligibleFromUrlAsync(
                    eligible,
                    $"https://management.azure.com/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?api-version={armPimVer}&$expand=expandedProperties&$filter=principalId eq '{groupId}'",
                    groupId);
                await AddEligibleFromScheduleUrlAsync(
                    eligible,
                    $"https://management.azure.com/providers/Microsoft.Authorization/roleEligibilitySchedules?api-version={armPimVer}&$expand=expandedProperties&$filter=principalId eq '{groupId}'",
                    groupId);
            }
        }

        await AddActiveFromUrlAsync(active, $"https://management.azure.com/providers/Microsoft.Authorization/roleAssignments?api-version={armRbacVer}&$filter=principalId eq '{userId}'");
        foreach (var groupId in userGroupIds)
        {
            if (string.IsNullOrWhiteSpace(groupId))
            {
                continue;
            }

            await AddActiveFromUrlAsync(
                active,
                $"https://management.azure.com/providers/Microsoft.Authorization/roleAssignments?api-version={armRbacVer}&$filter=principalId eq '{groupId}'",
                groupId);
        }

        var mergedActive = MergeAndDedupeAzureRoleLines(active);
        var mergedEligible = includeArmEligible ? MergeAndDedupeAzureRoleLines(eligible) : [];
        mergedActive = await ResolveGuidsInAzureRoleLinesAsync(mergedActive, graphToken, cancellationToken).ConfigureAwait(false);
        if (includeArmEligible)
        {
            mergedEligible = await ResolveGuidsInAzureRoleLinesAsync(mergedEligible, graphToken, cancellationToken).ConfigureAwait(false);
        }

        return (OrderAzureRoleLines(mergedActive), OrderAzureRoleLines(mergedEligible));
    }

    private async Task<string> ResolveEntraDirectoryRoleDisplayNameAsync(string? roleDefinitionId, string graphToken, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(roleDefinitionId))
        {
            return string.Empty;
        }

        if (_entraDirectoryRoleDisplayByDefinitionId.TryGetValue(roleDefinitionId, out var cached))
        {
            return cached;
        }

        var enc = Uri.EscapeDataString(roleDefinitionId);
        var doc = await GetJsonAsync(
                $"https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions/{enc}?$select=displayName",
                graphToken,
                cancellationToken)
            .ConfigureAwait(false);
        var dn = doc.HasValue ? GetString(doc.Value, "displayName") : string.Empty;
        // Do not cache failures — avoids poisoning all rows after throttling/404.
        if (!string.IsNullOrWhiteSpace(dn))
        {
            _entraDirectoryRoleDisplayByDefinitionId[roleDefinitionId] = dn;
        }

        return dn;
    }

    private static string? TryEntraBuiltInRoleDisplayNameFromTemplateId(string? templateId)
    {
        if (string.IsNullOrWhiteSpace(templateId))
        {
            return null;
        }

        return EntraBuiltInRoleDisplayByTemplateId.TryGetValue(templateId.Trim(), out var dn) ? dn : null;
    }

    private async Task<string> GetUnifiedDirectoryRoleDisplayNameAsync(JsonElement item, string graphToken, CancellationToken cancellationToken)
    {
        var catalog = _entraRoleCatalogScope;
        if (item.TryGetProperty("roleDefinition", out var rd) && rd.ValueKind == JsonValueKind.Object)
        {
            var fromExpand = GetString(rd, "displayName").Trim();
            if (!string.IsNullOrWhiteSpace(fromExpand))
            {
                return fromExpand;
            }

            var rdTemplate = GetString(rd, "templateId").Trim();
            if (catalog != null && !string.IsNullOrWhiteSpace(rdTemplate)
                                 && catalog.ByTemplateId.TryGetValue(rdTemplate, out var catByT)
                                 && !string.IsNullOrWhiteSpace(catByT))
            {
                return catByT;
            }

            var fromTemplate = TryEntraBuiltInRoleDisplayNameFromTemplateId(rdTemplate);
            if (!string.IsNullOrWhiteSpace(fromTemplate))
            {
                return fromTemplate;
            }

            var defIdFromExpand = GetString(rd, "id");
            if (catalog != null && !string.IsNullOrWhiteSpace(defIdFromExpand)
                                 && catalog.ByDefinitionId.TryGetValue(defIdFromExpand, out var catByD)
                                 && !string.IsNullOrWhiteSpace(catByD))
            {
                return catByD;
            }

            if (!string.IsNullOrWhiteSpace(defIdFromExpand))
            {
                var resolvedExpand = await ResolveEntraDirectoryRoleDisplayNameAsync(defIdFromExpand, graphToken, cancellationToken).ConfigureAwait(false);
                if (!string.IsNullOrWhiteSpace(resolvedExpand))
                {
                    return resolvedExpand.Trim();
                }
            }
        }

        var rowDefId = GetString(item, "roleDefinitionId");
        if (catalog != null && !string.IsNullOrWhiteSpace(rowDefId)
                             && catalog.ByDefinitionId.TryGetValue(rowDefId.Trim(), out var catRow)
                             && !string.IsNullOrWhiteSpace(catRow))
        {
            return catRow;
        }

        var rowTemplateId = GetString(item, "roleTemplateId").Trim();
        if (catalog != null && !string.IsNullOrWhiteSpace(rowTemplateId)
                             && catalog.ByTemplateId.TryGetValue(rowTemplateId, out var catRt)
                             && !string.IsNullOrWhiteSpace(catRt))
        {
            return catRt;
        }

        var fromRowTemplate = TryEntraBuiltInRoleDisplayNameFromTemplateId(GetString(item, "roleTemplateId"));
        if (!string.IsNullOrWhiteSpace(fromRowTemplate))
        {
            return fromRowTemplate;
        }

        var fromRoleDefId = await ResolveEntraDirectoryRoleDisplayNameAsync(rowDefId, graphToken, cancellationToken).ConfigureAwait(false);
        if (!string.IsNullOrWhiteSpace(fromRoleDefId))
        {
            return fromRoleDefId.Trim();
        }

        if (!string.IsNullOrWhiteSpace(rowDefId))
        {
            return $"Directory role ({rowDefId})";
        }

        return string.Empty;
    }

    /// <summary>Never drop a PIM eligibility row for an empty display string; align with inventory scripts that always emit a role label.</summary>
    private async Task<string> GetEntraEligibleRoleDisplayLineAsync(JsonElement item, string graphToken, CancellationToken cancellationToken)
    {
        var roleName = await GetUnifiedDirectoryRoleDisplayNameAsync(item, graphToken, cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(roleName))
        {
            var rdf = GetString(item, "roleDefinitionId");
            roleName = string.IsNullOrWhiteSpace(rdf)
                ? "PIM directory eligibility (unresolved)"
                : $"Directory role ({rdf})";
        }

        return roleName;
    }

    private async Task<EntraDirectoryRoleCatalog?> TryLoadEntraDirectoryRoleCatalogAsync(string graphToken, CancellationToken cancellationToken)
    {
        try
        {
            var rows = await GetJsonCollectionAsync(
                    "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?$select=id,displayName,templateId",
                    graphToken,
                    cancellationToken)
                .ConfigureAwait(false);
            var cat = new EntraDirectoryRoleCatalog();
            foreach (var row in rows)
            {
                var id = GetString(row, "id").Trim();
                var dn = GetString(row, "displayName").Trim();
                var tid = GetString(row, "templateId").Trim();
                if (string.IsNullOrWhiteSpace(dn))
                {
                    continue;
                }

                if (!string.IsNullOrWhiteSpace(id))
                {
                    cat.ByDefinitionId[id] = dn;
                }

                if (!string.IsNullOrWhiteSpace(tid))
                {
                    cat.ByTemplateId[tid] = dn;
                }
            }

            return cat.ByDefinitionId.Count > 0 ? cat : null;
        }
        catch
        {
            return null;
        }
    }

    private async Task LoadIdentityGovernancePrivilegedAccessGroupIndexesAsync(string graphToken, CancellationToken cancellationToken)
    {
        _entraIdentityGovGroupEligInstByGroupId = null;
        _entraIdentityGovGroupEligSchedByGroupId = null;
        _entraIdentityGovGroupAssignInstByGroupId = null;
        _entraIdentityGovGroupAssignSchedByGroupId = null;
        try
        {
            const string expand = "$expand=roleDefinition($select=id,displayName,templateId)";
            var eligInstTask = GetJsonCollectionAsync(
                $"https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/eligibilityScheduleInstances?{expand}",
                graphToken,
                cancellationToken);
            var eligSchedTask = GetJsonCollectionAsync(
                $"https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/eligibilitySchedules?{expand}",
                graphToken,
                cancellationToken);
            var assignInstTask = GetJsonCollectionAsync(
                $"https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/assignmentScheduleInstances?{expand}",
                graphToken,
                cancellationToken);
            var assignSchedTask = GetJsonCollectionAsync(
                $"https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/assignmentSchedules?{expand}",
                graphToken,
                cancellationToken);
            await Task.WhenAll(eligInstTask, eligSchedTask, assignInstTask, assignSchedTask).ConfigureAwait(false);
            _entraIdentityGovGroupEligInstByGroupId = IndexGraphRowsByGroupId(await eligInstTask.ConfigureAwait(false));
            _entraIdentityGovGroupEligSchedByGroupId = IndexGraphRowsByGroupId(await eligSchedTask.ConfigureAwait(false));
            _entraIdentityGovGroupAssignInstByGroupId = IndexGraphRowsByGroupId(await assignInstTask.ConfigureAwait(false));
            _entraIdentityGovGroupAssignSchedByGroupId = IndexGraphRowsByGroupId(await assignSchedTask.ConfigureAwait(false));
        }
        catch
        {
            _entraIdentityGovGroupEligInstByGroupId = null;
            _entraIdentityGovGroupEligSchedByGroupId = null;
            _entraIdentityGovGroupAssignInstByGroupId = null;
            _entraIdentityGovGroupAssignSchedByGroupId = null;
        }
    }

    private async Task AppendEntraIdentityGovGroupEligibleToListAsync(
        List<EntraEligibleRoleLine> eligibleLines,
        IReadOnlyCollection<string> groupIds,
        Dictionary<string, string> groupLabelCache,
        Func<string, Task<string>> getGroupLabelAsync,
        string graphToken,
        CancellationToken cancellationToken)
    {
        if (_entraIdentityGovGroupEligInstByGroupId is null && _entraIdentityGovGroupEligSchedByGroupId is null)
        {
            return;
        }

        foreach (var gid in groupIds)
        {
            if (string.IsNullOrWhiteSpace(gid))
            {
                continue;
            }

            var label = await getGroupLabelAsync(gid).ConfigureAwait(false);
            if (_entraIdentityGovGroupEligInstByGroupId is { } byInst && byInst.TryGetValue(gid, out var instRows))
            {
                foreach (var item in instRows)
                {
                    if (!IsPrivilegedAccessGroupRowStillEffective(item, DateTime.UtcNow))
                    {
                        continue;
                    }

                    var roleName = await GetEntraEligibleRoleDisplayLineAsync(item, graphToken, cancellationToken).ConfigureAwait(false);
                    if (!IncludeEntraDirectoryRoleInPrivilegedReport(roleName))
                    {
                        continue;
                    }

                    eligibleLines.Add(ToEntraEligibleLine(
                        $"{roleName} (via group: {label})",
                        FormatPrivilegedAccessGroupEligibilityEndDisplay(item),
                        item));
                }
            }

            if (_entraIdentityGovGroupEligSchedByGroupId is { } bySched && bySched.TryGetValue(gid, out var schedRows))
            {
                foreach (var item in schedRows)
                {
                    if (!IsPrivilegedAccessGroupRowStillEffective(item, DateTime.UtcNow))
                    {
                        continue;
                    }

                    var roleName = await GetEntraEligibleRoleDisplayLineAsync(item, graphToken, cancellationToken).ConfigureAwait(false);
                    if (!IncludeEntraDirectoryRoleInPrivilegedReport(roleName))
                    {
                        continue;
                    }

                    eligibleLines.Add(ToEntraEligibleLine(
                        $"{roleName} (via group: {label})",
                        FormatPrivilegedAccessGroupEligibilityEndDisplay(item),
                        item));
                }
            }
        }
    }

    private async Task AppendEntraIdentityGovGroupActiveToSetAsync(
        HashSet<string> active,
        IReadOnlyCollection<string> groupIds,
        Dictionary<string, string> groupLabelCache,
        Func<string, Task<string>> getGroupLabelAsync,
        string graphToken,
        CancellationToken cancellationToken)
    {
        if (_entraIdentityGovGroupAssignInstByGroupId is null && _entraIdentityGovGroupAssignSchedByGroupId is null)
        {
            return;
        }

        foreach (var gid in groupIds)
        {
            if (string.IsNullOrWhiteSpace(gid))
            {
                continue;
            }

            var label = await getGroupLabelAsync(gid).ConfigureAwait(false);
            if (_entraIdentityGovGroupAssignInstByGroupId is { } byInst && byInst.TryGetValue(gid, out var instRows))
            {
                foreach (var item in instRows)
                {
                    if (!IsPrivilegedAccessGroupRowStillEffective(item, DateTime.UtcNow))
                    {
                        continue;
                    }

                    var roleName = await GetUnifiedDirectoryRoleDisplayNameAsync(item, graphToken, cancellationToken).ConfigureAwait(false);
                    if (!IncludeEntraDirectoryRoleInPrivilegedReport(roleName))
                    {
                        continue;
                    }

                    active.Add($"{roleName} (via group: {label})");
                }
            }

            if (_entraIdentityGovGroupAssignSchedByGroupId is { } bySched && bySched.TryGetValue(gid, out var schedRows))
            {
                foreach (var item in schedRows)
                {
                    if (!IsPrivilegedAccessGroupRowStillEffective(item, DateTime.UtcNow))
                    {
                        continue;
                    }

                    var roleName = await GetUnifiedDirectoryRoleDisplayNameAsync(item, graphToken, cancellationToken).ConfigureAwait(false);
                    if (!IncludeEntraDirectoryRoleInPrivilegedReport(roleName))
                    {
                        continue;
                    }

                    active.Add($"{roleName} (via group: {label})");
                }
            }
        }
    }

    private async Task<List<EntraEligibleRoleLine>> GetEligibleRolesAsync(
        string userId,
        string graphToken,
        EntraDirectoryPimIndexes? tenantPim,
        CancellationToken cancellationToken)
    {
        // Bulk tenant index can be non-null but incomplete (empty pages, partial Graph behavior, or indexing gaps).
        // Legacy filtered calls still surface per-user and group-based eligibility; merge and dedupe.
        if (tenantPim != null)
        {
            var idxTask = GetEligibleRolesFromTenantIndexAsync(userId, graphToken, tenantPim, cancellationToken);
            var legTask = GetEligibleRolesLegacyAsync(userId, graphToken, cancellationToken);
            await Task.WhenAll(idxTask, legTask).ConfigureAwait(false);
            var fromIndex = await idxTask.ConfigureAwait(false);
            var fromLegacy = await legTask.ConfigureAwait(false);
            return DedupeEntraEligibleRoleLines(fromIndex.Concat(fromLegacy));
        }

        return await GetEligibleRolesLegacyAsync(userId, graphToken, cancellationToken).ConfigureAwait(false);
    }

    private async Task<List<EntraEligibleRoleLine>> GetEligibleRolesFromTenantIndexAsync(
        string userId,
        string graphToken,
        EntraDirectoryPimIndexes pim,
        CancellationToken cancellationToken)
    {
        var eligibleLines = new List<EntraEligibleRoleLine>();
        List<string> groupIds = [];
        try
        {
            groupIds = await GetUserTransitiveGroupIdsAsync(userId, graphToken, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            // Still surface direct principalId rows from the tenant index; group-based eligibility is best-effort.
            groupIds = [];
        }

        var match = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { userId };
        foreach (var g in groupIds)
        {
            match.Add(g);
        }

        try
        {
            foreach (var g in await GetIdentityGovernancePrivilegedAccessGroupIdsForPrincipalAsync(userId, graphToken, cancellationToken).ConfigureAwait(false))
            {
                match.Add(g);
            }
        }
        catch
        {
        }

        var groupLabelCache = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        async Task<string> CacheGroupLabelAsync(string groupObjectId)
        {
            if (groupLabelCache.TryGetValue(groupObjectId, out var c))
            {
                return c;
            }

            var gd = await GetJsonAsync(
                    $"https://graph.microsoft.com/v1.0/groups/{Uri.EscapeDataString(groupObjectId)}?$select=displayName",
                    graphToken,
                    cancellationToken)
                .ConfigureAwait(false);
            var dn = gd.HasValue && !string.IsNullOrWhiteSpace(GetString(gd.Value, "displayName"))
                ? GetString(gd.Value, "displayName")
                : "Group";
            groupLabelCache[groupObjectId] = dn;
            return dn;
        }

        async Task ConsumeRowsAsync(
            IReadOnlyDictionary<string, List<JsonElement>> byPrincipal,
            HashSet<string> seenRowIds,
            string rowIdPrefix,
            Func<JsonElement, bool>? includeRow = null)
        {
            foreach (var p in match)
            {
                if (!byPrincipal.TryGetValue(p, out var rows))
                {
                    continue;
                }

                foreach (var item in rows)
                {
                    if (includeRow != null && !includeRow(item))
                    {
                        continue;
                    }

                    var rid = GetString(item, "id");
                    var compositeId = string.IsNullOrWhiteSpace(rid) ? null : $"{rowIdPrefix}:{rid}";
                    if (!string.IsNullOrWhiteSpace(compositeId) && !seenRowIds.Add(compositeId))
                    {
                        continue;
                    }

                    if (!IsEntraEligibilityRowStillEffective(item, DateTime.UtcNow))
                    {
                        continue;
                    }

                    var roleName = await GetUnifiedDirectoryRoleDisplayNameAsync(item, graphToken, cancellationToken).ConfigureAwait(false);
                    if (string.IsNullOrWhiteSpace(roleName))
                    {
                        var rdf = GetString(item, "roleDefinitionId");
                        roleName = string.IsNullOrWhiteSpace(rdf)
                            ? "PIM directory eligibility (unresolved)"
                            : $"Directory role ({rdf})";
                    }

                    if (!IncludeEntraDirectoryRoleInPrivilegedReport(roleName))
                    {
                        continue;
                    }

                    var pidRow = GetString(item, "principalId");
                    var exp = FormatEntraGraphEligibilityEndDisplay(item);
                    if (pidRow.Equals(userId, StringComparison.OrdinalIgnoreCase))
                    {
                        eligibleLines.Add(ToEntraEligibleLine(roleName, exp, item));
                    }
                    else
                    {
                        var gl = await CacheGroupLabelAsync(pidRow).ConfigureAwait(false);
                        eligibleLines.Add(ToEntraEligibleLine($"{roleName} (via group: {gl})", exp, item));
                    }
                }
            }
        }

        var seenElig = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        await ConsumeRowsAsync(pim.EligibilitySchedulesByPrincipal, seenElig, "es").ConfigureAwait(false);
        await ConsumeRowsAsync(pim.EligibilityInstancesByPrincipal, seenElig, "ei").ConfigureAwait(false);
        await ConsumeRowsAsync(pim.EligibilityRequestsByPrincipal, seenElig, "er", ShouldIncludeEntraEligibilityScheduleRequest).ConfigureAwait(false);
        List<string> groupsForIgAppend = [..groupIds];
        try
        {
            var seenG = new HashSet<string>(groupsForIgAppend, StringComparer.OrdinalIgnoreCase);
            foreach (var g in await GetIdentityGovernancePrivilegedAccessGroupIdsForPrincipalAsync(userId, graphToken, cancellationToken).ConfigureAwait(false))
            {
                if (seenG.Add(g))
                {
                    groupsForIgAppend.Add(g);
                }
            }
        }
        catch
        {
        }

        await AppendEntraIdentityGovGroupEligibleToListAsync(eligibleLines, groupsForIgAppend, groupLabelCache, CacheGroupLabelAsync, graphToken, cancellationToken).ConfigureAwait(false);
        return DedupeEntraEligibleRoleLines(eligibleLines);
    }

    private async Task<List<EntraEligibleRoleLine>> GetEligibleRolesLegacyAsync(string userId, string graphToken, CancellationToken cancellationToken)
    {
        var eligibleLines = new List<EntraEligibleRoleLine>();
        try
        {
            var pidQ = $"?$filter=principalId eq '{userId}'&$expand=roleDefinition($select=id,displayName,templateId)";
            var directSchedTask = MergeV1BetaDirectoryEligibilityAsync(
                "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules" + pidQ,
                "https://graph.microsoft.com/beta/roleManagement/directory/roleEligibilitySchedules" + pidQ,
                graphToken,
                cancellationToken);
            var directInstTask = MergeV1BetaDirectoryEligibilityAsync(
                "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances" + pidQ,
                "https://graph.microsoft.com/beta/roleManagement/directory/roleEligibilityScheduleInstances" + pidQ,
                graphToken,
                cancellationToken);
            await Task.WhenAll(directSchedTask, directInstTask).ConfigureAwait(false);
            foreach (var item in await directSchedTask.ConfigureAwait(false))
            {
                if (!IsEntraEligibilityRowStillEffective(item, DateTime.UtcNow))
                {
                    continue;
                }

                var roleName = await GetUnifiedDirectoryRoleDisplayNameAsync(item, graphToken, cancellationToken).ConfigureAwait(false);
                if (IncludeEntraDirectoryRoleInPrivilegedReport(roleName))
                {
                    eligibleLines.Add(ToEntraEligibleLine(roleName, FormatEntraGraphEligibilityEndDisplay(item), item));
                }
            }

            foreach (var item in await directInstTask.ConfigureAwait(false))
            {
                if (!IsEntraEligibilityRowStillEffective(item, DateTime.UtcNow))
                {
                    continue;
                }

                var roleName = await GetUnifiedDirectoryRoleDisplayNameAsync(item, graphToken, cancellationToken).ConfigureAwait(false);
                if (IncludeEntraDirectoryRoleInPrivilegedReport(roleName))
                {
                    eligibleLines.Add(ToEntraEligibleLine(roleName, FormatEntraGraphEligibilityEndDisplay(item), item));
                }
            }

            try
            {
                var directReqRows = await MergeV1BetaDirectoryEligibilityAsync(
                        "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleRequests" + pidQ,
                        "https://graph.microsoft.com/beta/roleManagement/directory/roleEligibilityScheduleRequests" + pidQ,
                        graphToken,
                        cancellationToken)
                    .ConfigureAwait(false);
                foreach (var item in directReqRows)
                {
                    if (!ShouldIncludeEntraEligibilityScheduleRequest(item))
                    {
                        continue;
                    }

                    if (!IsEntraEligibilityRowStillEffective(item, DateTime.UtcNow))
                    {
                        continue;
                    }

                    var roleName = await GetEntraEligibleRoleDisplayLineAsync(item, graphToken, cancellationToken).ConfigureAwait(false);
                    if (IncludeEntraDirectoryRoleInPrivilegedReport(roleName))
                    {
                        eligibleLines.Add(ToEntraEligibleLine(roleName, FormatEntraGraphEligibilityEndDisplay(item), item));
                    }
                }
            }
            catch
            {
                // $filter on requests or missing permission must not drop schedules/instances.
            }
        }
        catch
        {
            // One bad page/parse must not wipe group-based eligibility.
        }

        List<string> groupIds = [];
        try
        {
            groupIds = await GetUserTransitiveGroupIdsAsync(userId, graphToken, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            groupIds = [];
        }

        try
        {
            var seenG = new HashSet<string>(groupIds, StringComparer.OrdinalIgnoreCase);
            foreach (var g in await GetIdentityGovernancePrivilegedAccessGroupIdsForPrincipalAsync(userId, graphToken, cancellationToken).ConfigureAwait(false))
            {
                if (seenG.Add(g))
                {
                    groupIds.Add(g);
                }
            }
        }
        catch
        {
        }

        var sem = new SemaphoreSlim(12, 12);
        var groupTasks = groupIds.Select(async gid =>
        {
            await sem.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                try
                {
                    var lines = new List<EntraEligibleRoleLine>();
                    var gd = await GetJsonAsync(
                            $"https://graph.microsoft.com/v1.0/groups/{Uri.EscapeDataString(gid)}?$select=displayName",
                            graphToken,
                            cancellationToken)
                        .ConfigureAwait(false);
                    var gName = gd.HasValue && !string.IsNullOrWhiteSpace(GetString(gd.Value, "displayName"))
                        ? GetString(gd.Value, "displayName")
                        : "Group";
                    var gidQ = $"?$filter=principalId eq '{gid}'&$expand=roleDefinition($select=id,displayName,templateId)";
                    var groupSchedulesTask = MergeV1BetaDirectoryEligibilityAsync(
                        "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules" + gidQ,
                        "https://graph.microsoft.com/beta/roleManagement/directory/roleEligibilitySchedules" + gidQ,
                        graphToken,
                        cancellationToken);
                    var groupInstancesTask = MergeV1BetaDirectoryEligibilityAsync(
                        "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances" + gidQ,
                        "https://graph.microsoft.com/beta/roleManagement/directory/roleEligibilityScheduleInstances" + gidQ,
                        graphToken,
                        cancellationToken);
                    var groupReqTask = MergeV1BetaDirectoryEligibilityAsync(
                        "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleRequests" + gidQ,
                        "https://graph.microsoft.com/beta/roleManagement/directory/roleEligibilityScheduleRequests" + gidQ,
                        graphToken,
                        cancellationToken);
                    await Task.WhenAll(groupSchedulesTask, groupInstancesTask, groupReqTask).ConfigureAwait(false);
                    foreach (var item in await groupSchedulesTask.ConfigureAwait(false))
                    {
                        if (!IsEntraEligibilityRowStillEffective(item, DateTime.UtcNow))
                        {
                            continue;
                        }

                        var roleName = await GetEntraEligibleRoleDisplayLineAsync(item, graphToken, cancellationToken).ConfigureAwait(false);
                        if (IncludeEntraDirectoryRoleInPrivilegedReport(roleName))
                        {
                            lines.Add(ToEntraEligibleLine(
                                $"{roleName} (via group: {gName})",
                                FormatEntraGraphEligibilityEndDisplay(item),
                                item));
                        }
                    }

                    foreach (var item in await groupInstancesTask.ConfigureAwait(false))
                    {
                        if (!IsEntraEligibilityRowStillEffective(item, DateTime.UtcNow))
                        {
                            continue;
                        }

                        var roleName = await GetEntraEligibleRoleDisplayLineAsync(item, graphToken, cancellationToken).ConfigureAwait(false);
                        if (IncludeEntraDirectoryRoleInPrivilegedReport(roleName))
                        {
                            lines.Add(ToEntraEligibleLine(
                                $"{roleName} (via group: {gName})",
                                FormatEntraGraphEligibilityEndDisplay(item),
                                item));
                        }
                    }

                    foreach (var item in await groupReqTask.ConfigureAwait(false))
                    {
                        if (!ShouldIncludeEntraEligibilityScheduleRequest(item))
                        {
                            continue;
                        }

                        if (!IsEntraEligibilityRowStillEffective(item, DateTime.UtcNow))
                        {
                            continue;
                        }

                        var roleName = await GetEntraEligibleRoleDisplayLineAsync(item, graphToken, cancellationToken).ConfigureAwait(false);
                        if (IncludeEntraDirectoryRoleInPrivilegedReport(roleName))
                        {
                            lines.Add(ToEntraEligibleLine(
                                $"{roleName} (via group: {gName})",
                                FormatEntraGraphEligibilityEndDisplay(item),
                                item));
                        }
                    }

                    return lines;
                }
                catch
                {
                    return [];
                }
            }
            finally
            {
                sem.Release();
            }
        });
        foreach (var chunk in await Task.WhenAll(groupTasks).ConfigureAwait(false))
        {
            eligibleLines.AddRange(chunk);
        }

        var groupLabelCacheForIg = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        async Task<string> CacheGroupLabelForIgAsync(string groupObjectId)
        {
            if (groupLabelCacheForIg.TryGetValue(groupObjectId, out var c))
            {
                return c;
            }

            var gd = await GetJsonAsync(
                    $"https://graph.microsoft.com/v1.0/groups/{Uri.EscapeDataString(groupObjectId)}?$select=displayName",
                    graphToken,
                    cancellationToken)
                .ConfigureAwait(false);
            var dn = gd.HasValue && !string.IsNullOrWhiteSpace(GetString(gd.Value, "displayName"))
                ? GetString(gd.Value, "displayName")
                : "Group";
            groupLabelCacheForIg[groupObjectId] = dn;
            return dn;
        }

        await AppendEntraIdentityGovGroupEligibleToListAsync(eligibleLines, groupIds, groupLabelCacheForIg, CacheGroupLabelForIgAsync, graphToken, cancellationToken).ConfigureAwait(false);
        return DedupeEntraEligibleRoleLines(eligibleLines);
    }

    private async Task<List<string>> GetActiveRolesViaSchedulesAsync(
        string userId,
        string graphToken,
        EntraDirectoryPimIndexes? tenantPim,
        CancellationToken cancellationToken)
    {
        if (IsLightweight())
        {
            return await GetActiveRolesLightAsync(userId, graphToken, cancellationToken).ConfigureAwait(false);
        }

        if (tenantPim != null)
        {
            var fromIndex = await GetActivePimRolesFromTenantIndexAsync(userId, graphToken, tenantPim, cancellationToken).ConfigureAwait(false);
            var fromLegacy = await GetActiveRolesViaSchedulesLegacyAsync(userId, graphToken, cancellationToken).ConfigureAwait(false);
            return DedupeEntraRoleLines(fromIndex.Concat(fromLegacy));
        }

        return await GetActiveRolesViaSchedulesLegacyAsync(userId, graphToken, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Light SKU: merge PIM schedules, unified <c>roleAssignments</c>, and <c>transitiveRoleAssignments</c> (Entra docs) for the user.</summary>
    private async Task<List<string>> GetActiveRolesLightAsync(string userId, string graphToken, CancellationToken cancellationToken)
    {
        var acc = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var r in await GetActiveRolesLightDirectUserOnlyAsync(userId, graphToken, cancellationToken).ConfigureAwait(false))
        {
            acc.Add(r);
        }

        await AppendUnifiedRoleAssignmentsForPrincipalAsync(userId, graphToken, acc, cancellationToken).ConfigureAwait(false);
        await AppendTransitiveDirectoryRoleAssignmentsForUserAsync(userId, graphToken, acc, cancellationToken).ConfigureAwait(false);
        return DedupeEntraRoleLines(acc.Where(r => IncludeEntraDirectoryRoleInPrivilegedReport(r)));
    }

    private async Task AppendUnifiedRoleAssignmentsForPrincipalAsync(
        string userId,
        string graphToken,
        HashSet<string> acc,
        CancellationToken cancellationToken)
    {
        async Task PullAsync(string baseUrl)
        {
            var rows = await GetJsonCollectionAsync(
                    $"{baseUrl}?$filter=principalId eq '{userId}'&$expand=roleDefinition($select=id,displayName,templateId)",
                    graphToken,
                    cancellationToken)
                .ConfigureAwait(false);
            foreach (var item in rows)
            {
                var roleName = await GetUnifiedDirectoryRoleDisplayNameAsync(item, graphToken, cancellationToken).ConfigureAwait(false);
                if (IncludeEntraDirectoryRoleInPrivilegedReport(roleName))
                {
                    acc.Add(roleName);
                }
            }
        }

        try
        {
            await PullAsync("https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments").ConfigureAwait(false);
        }
        catch
        {
        }

        try
        {
            await PullAsync("https://graph.microsoft.com/beta/roleManagement/directory/roleAssignments").ConfigureAwait(false);
        }
        catch
        {
        }
    }

    private async Task AppendTransitiveDirectoryRoleAssignmentsForUserAsync(
        string userId,
        string graphToken,
        HashSet<string> acc,
        CancellationToken cancellationToken)
    {
        try
        {
            var rows = await GetJsonCollectionAsync(
                    $"https://graph.microsoft.com/beta/roleManagement/directory/transitiveRoleAssignments?$filter=principalId eq '{userId}'&$expand=roleDefinition($select=id,displayName,templateId)",
                    graphToken,
                    cancellationToken)
                .ConfigureAwait(false);
            foreach (var item in rows)
            {
                var roleName = await GetUnifiedDirectoryRoleDisplayNameAsync(item, graphToken, cancellationToken).ConfigureAwait(false);
                if (IncludeEntraDirectoryRoleInPrivilegedReport(roleName))
                {
                    acc.Add(roleName);
                }
            }
        }
        catch
        {
            // Missing consent (e.g. RoleManagement.Read.Directory) or API unavailable.
        }
    }

    /// <summary>Merge tenant-wide unified role assignments so group-based principals are expanded to users (Light).</summary>
    private async Task TryMergeLightUnifiedRoleAssignmentsIntoUserMapAsync(
        Dictionary<string, HashSet<string>> userRolesMap,
        object userRolesMapLock,
        string graphToken,
        CancellationToken cancellationToken)
    {
        List<JsonElement> rows;
        try
        {
            rows = await GetJsonCollectionAsync(
                    "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$expand=roleDefinition($select=id,displayName,templateId)",
                    graphToken,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch
        {
            return;
        }

        var principalKind = new ConcurrentDictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        async Task<string?> KindOfAsync(string pid)
        {
            if (principalKind.TryGetValue(pid, out var cached))
            {
                return cached;
            }

            try
            {
                var doc = await GetJsonAsync(
                        $"https://graph.microsoft.com/v1.0/directoryObjects/{Uri.EscapeDataString(pid)}?$select=id",
                        graphToken,
                        cancellationToken)
                    .ConfigureAwait(false);
                if (!doc.HasValue)
                {
                    principalKind[pid] = "";
                    return "";
                }

                var t = GetString(doc.Value, "@odata.type");
                principalKind[pid] = t;
                return t;
            }
            catch
            {
                principalKind[pid] = "";
                return "";
            }
        }

        foreach (var row in rows)
        {
            var roleName = await GetUnifiedDirectoryRoleDisplayNameAsync(row, graphToken, cancellationToken).ConfigureAwait(false);
            if (!IncludeEntraDirectoryRoleInPrivilegedReport(roleName))
            {
                continue;
            }

            var pid = GetString(row, "principalId");
            if (string.IsNullOrWhiteSpace(pid))
            {
                continue;
            }

            var kind = await KindOfAsync(pid).ConfigureAwait(false) ?? "";
            if (kind.Equals("#microsoft.graph.user", StringComparison.OrdinalIgnoreCase))
            {
                lock (userRolesMapLock)
                {
                    AddRole(userRolesMap, pid, roleName);
                }
            }
            else if (kind.Equals("#microsoft.graph.group", StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    var groupMembers = await GetJsonCollectionAsync(
                            $"https://graph.microsoft.com/v1.0/groups/{Uri.EscapeDataString(pid)}/transitiveMembers?$select=id",
                            graphToken,
                            cancellationToken)
                        .ConfigureAwait(false);
                    foreach (var gm in groupMembers.Where(x =>
                                 GetString(x, "@odata.type").Equals("#microsoft.graph.user", StringComparison.OrdinalIgnoreCase)))
                    {
                        var uid = GetString(gm, "id");
                        if (!string.IsNullOrWhiteSpace(uid))
                        {
                            lock (userRolesMapLock)
                            {
                                AddRole(userRolesMap, uid, roleName);
                            }
                        }
                    }
                }
                catch
                {
                }
            }
        }
    }

    /// <summary>Light SKU: directory roles activated via PIM for this user only (no transitive group principals).</summary>
    private async Task<List<string>> GetActiveRolesLightDirectUserOnlyAsync(
        string userId,
        string graphToken,
        CancellationToken cancellationToken)
    {
        var active = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        async Task PullPairAsync(string schedulesBase, string instancesBase)
        {
            var st = GetJsonCollectionAsync(
                $"{schedulesBase}?$filter=principalId eq '{userId}'&$expand=roleDefinition($select=id,displayName,templateId)",
                graphToken,
                cancellationToken);
            var inst = GetJsonCollectionAsync(
                $"{instancesBase}?$filter=principalId eq '{userId}'&$expand=roleDefinition($select=id,displayName,templateId)",
                graphToken,
                cancellationToken);
            await Task.WhenAll(st, inst).ConfigureAwait(false);
            foreach (var item in await st.ConfigureAwait(false))
            {
                var roleName = await GetUnifiedDirectoryRoleDisplayNameAsync(item, graphToken, cancellationToken).ConfigureAwait(false);
                if (IncludeEntraDirectoryRoleInPrivilegedReport(roleName))
                {
                    active.Add(roleName);
                }
            }

            foreach (var item in await inst.ConfigureAwait(false))
            {
                var roleName = await GetUnifiedDirectoryRoleDisplayNameAsync(item, graphToken, cancellationToken).ConfigureAwait(false);
                if (IncludeEntraDirectoryRoleInPrivilegedReport(roleName))
                {
                    active.Add(roleName);
                }
            }
        }

        try
        {
            await PullPairAsync(
                "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentSchedules",
                "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances").ConfigureAwait(false);
        }
        catch
        {
        }

        try
        {
            await PullPairAsync(
                "https://graph.microsoft.com/beta/roleManagement/directory/roleAssignmentSchedules",
                "https://graph.microsoft.com/beta/roleManagement/directory/roleAssignmentScheduleInstances").ConfigureAwait(false);
        }
        catch
        {
        }

        return DedupeEntraRoleLines(active);
    }

    private async Task<List<string>> GetActivePimRolesFromTenantIndexAsync(
        string userId,
        string graphToken,
        EntraDirectoryPimIndexes pim,
        CancellationToken cancellationToken)
    {
        var active = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        List<string> groupIds = [];
        try
        {
            groupIds = await GetUserTransitiveGroupIdsAsync(userId, graphToken, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            groupIds = [];
        }

        var match = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { userId };
        foreach (var g in groupIds)
        {
            match.Add(g);
        }

        try
        {
            foreach (var g in await GetIdentityGovernancePrivilegedAccessGroupIdsForPrincipalAsync(userId, graphToken, cancellationToken).ConfigureAwait(false))
            {
                match.Add(g);
            }
        }
        catch
        {
        }

        var groupLabelCache = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        async Task<string> CacheGroupLabelAsync(string groupObjectId)
        {
            if (groupLabelCache.TryGetValue(groupObjectId, out var c))
            {
                return c;
            }

            var gd = await GetJsonAsync(
                    $"https://graph.microsoft.com/v1.0/groups/{Uri.EscapeDataString(groupObjectId)}?$select=displayName",
                    graphToken,
                    cancellationToken)
                .ConfigureAwait(false);
            var dn = gd.HasValue && !string.IsNullOrWhiteSpace(GetString(gd.Value, "displayName"))
                ? GetString(gd.Value, "displayName")
                : "Group";
            groupLabelCache[groupObjectId] = dn;
            return dn;
        }

        async Task ConsumeRowsAsync(IReadOnlyDictionary<string, List<JsonElement>> byPrincipal, HashSet<string> seenRowIds)
        {
            foreach (var p in match)
            {
                if (!byPrincipal.TryGetValue(p, out var rows))
                {
                    continue;
                }

                foreach (var item in rows)
                {
                    var rid = GetString(item, "id");
                    if (!string.IsNullOrWhiteSpace(rid) && !seenRowIds.Add(rid))
                    {
                        continue;
                    }

                    var roleName = await GetUnifiedDirectoryRoleDisplayNameAsync(item, graphToken, cancellationToken).ConfigureAwait(false);
                    if (!IncludeEntraDirectoryRoleInPrivilegedReport(roleName))
                    {
                        continue;
                    }

                    var pidRow = GetString(item, "principalId");
                    if (pidRow.Equals(userId, StringComparison.OrdinalIgnoreCase))
                    {
                        active.Add(roleName);
                    }
                    else
                    {
                        var gl = await CacheGroupLabelAsync(pidRow).ConfigureAwait(false);
                        active.Add($"{roleName} (via group: {gl})");
                    }
                }
            }
        }

        await ConsumeRowsAsync(pim.AssignmentSchedulesByPrincipal, new HashSet<string>(StringComparer.OrdinalIgnoreCase)).ConfigureAwait(false);
        await ConsumeRowsAsync(pim.AssignmentInstancesByPrincipal, new HashSet<string>(StringComparer.OrdinalIgnoreCase)).ConfigureAwait(false);
        List<string> groupsForIgAppend = [..groupIds];
        try
        {
            var seenG = new HashSet<string>(groupsForIgAppend, StringComparer.OrdinalIgnoreCase);
            foreach (var g in await GetIdentityGovernancePrivilegedAccessGroupIdsForPrincipalAsync(userId, graphToken, cancellationToken).ConfigureAwait(false))
            {
                if (seenG.Add(g))
                {
                    groupsForIgAppend.Add(g);
                }
            }
        }
        catch
        {
        }

        await AppendEntraIdentityGovGroupActiveToSetAsync(active, groupsForIgAppend, groupLabelCache, CacheGroupLabelAsync, graphToken, cancellationToken).ConfigureAwait(false);
        return DedupeEntraRoleLines(active);
    }

    private async Task<List<string>> GetActiveRolesViaSchedulesLegacyAsync(string userId, string graphToken, CancellationToken cancellationToken)
    {
        var active = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            var directTask = GetJsonCollectionAsync($"https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentSchedules?$filter=principalId eq '{userId}'&$expand=roleDefinition($select=id,displayName,templateId)", graphToken, cancellationToken);
            var directInstancesTask = GetJsonCollectionAsync($"https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances?$filter=principalId eq '{userId}'&$expand=roleDefinition($select=id,displayName,templateId)", graphToken, cancellationToken);
            await Task.WhenAll(directTask, directInstancesTask).ConfigureAwait(false);
            foreach (var item in await directTask.ConfigureAwait(false))
            {
                var roleName = await GetUnifiedDirectoryRoleDisplayNameAsync(item, graphToken, cancellationToken).ConfigureAwait(false);
                if (IncludeEntraDirectoryRoleInPrivilegedReport(roleName))
                {
                    active.Add(roleName);
                }
            }

            foreach (var item in await directInstancesTask.ConfigureAwait(false))
            {
                var roleName = await GetUnifiedDirectoryRoleDisplayNameAsync(item, graphToken, cancellationToken).ConfigureAwait(false);
                if (IncludeEntraDirectoryRoleInPrivilegedReport(roleName))
                {
                    active.Add(roleName);
                }
            }
        }
        catch
        {
        }

        List<string> groupIds = [];
        try
        {
            groupIds = await GetUserTransitiveGroupIdsAsync(userId, graphToken, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            groupIds = [];
        }

        try
        {
            var seenGa = new HashSet<string>(groupIds, StringComparer.OrdinalIgnoreCase);
            foreach (var g in await GetIdentityGovernancePrivilegedAccessGroupIdsForPrincipalAsync(userId, graphToken, cancellationToken).ConfigureAwait(false))
            {
                if (seenGa.Add(g))
                {
                    groupIds.Add(g);
                }
            }
        }
        catch
        {
        }

        var sem = new SemaphoreSlim(12, 12);
        var groupTasks = groupIds.Select(async gid =>
        {
            await sem.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                try
                {
                    var lines = new List<string>();
                    var gd = await GetJsonAsync(
                            $"https://graph.microsoft.com/v1.0/groups/{Uri.EscapeDataString(gid)}?$select=displayName",
                            graphToken,
                            cancellationToken)
                        .ConfigureAwait(false);
                    var gName = gd.HasValue && !string.IsNullOrWhiteSpace(GetString(gd.Value, "displayName"))
                        ? GetString(gd.Value, "displayName")
                        : "Group";
                    var groupSchedulesTask = GetJsonCollectionAsync($"https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentSchedules?$filter=principalId eq '{gid}'&$expand=roleDefinition($select=id,displayName,templateId)", graphToken, cancellationToken);
                    var groupInstancesTask = GetJsonCollectionAsync($"https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances?$filter=principalId eq '{gid}'&$expand=roleDefinition($select=id,displayName,templateId)", graphToken, cancellationToken);
                    await Task.WhenAll(groupSchedulesTask, groupInstancesTask).ConfigureAwait(false);
                    foreach (var item in await groupSchedulesTask.ConfigureAwait(false))
                    {
                        var roleName = await GetUnifiedDirectoryRoleDisplayNameAsync(item, graphToken, cancellationToken).ConfigureAwait(false);
                        if (IncludeEntraDirectoryRoleInPrivilegedReport(roleName))
                        {
                            lines.Add($"{roleName} (via group: {gName})");
                        }
                    }

                    foreach (var item in await groupInstancesTask.ConfigureAwait(false))
                    {
                        var roleName = await GetUnifiedDirectoryRoleDisplayNameAsync(item, graphToken, cancellationToken).ConfigureAwait(false);
                        if (IncludeEntraDirectoryRoleInPrivilegedReport(roleName))
                        {
                            lines.Add($"{roleName} (via group: {gName})");
                        }
                    }

                    return lines;
                }
                catch
                {
                    return new List<string>();
                }
            }
            finally
            {
                sem.Release();
            }
        });
        foreach (var chunk in await Task.WhenAll(groupTasks).ConfigureAwait(false))
        {
            foreach (var line in chunk)
            {
                active.Add(line);
            }
        }

        var groupLabelCacheForIgActive = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        async Task<string> CacheGroupLabelForIgActiveAsync(string groupObjectId)
        {
            if (groupLabelCacheForIgActive.TryGetValue(groupObjectId, out var c))
            {
                return c;
            }

            var gd = await GetJsonAsync(
                    $"https://graph.microsoft.com/v1.0/groups/{Uri.EscapeDataString(groupObjectId)}?$select=displayName",
                    graphToken,
                    cancellationToken)
                .ConfigureAwait(false);
            var dn = gd.HasValue && !string.IsNullOrWhiteSpace(GetString(gd.Value, "displayName"))
                ? GetString(gd.Value, "displayName")
                : "Group";
            groupLabelCacheForIgActive[groupObjectId] = dn;
            return dn;
        }

        await AppendEntraIdentityGovGroupActiveToSetAsync(active, groupIds, groupLabelCacheForIgActive, CacheGroupLabelForIgActiveAsync, graphToken, cancellationToken).ConfigureAwait(false);
        return DedupeEntraRoleLines(active);
    }

    private static bool TryGetJsonPropertyIgnoreCase(JsonElement element, string propertyName, out JsonElement value)
    {
        value = default;
        if (element.ValueKind != JsonValueKind.Object)
        {
            return false;
        }

        if (element.TryGetProperty(propertyName, out value))
        {
            return true;
        }

        foreach (var prop in element.EnumerateObject())
        {
            if (prop.Name.Equals(propertyName, StringComparison.OrdinalIgnoreCase))
            {
                value = prop.Value;
                return true;
            }
        }

        return false;
    }

    private static string GetJsonElementScalarString(JsonElement value) =>
        value.ValueKind switch
        {
            JsonValueKind.String => value.GetString() ?? string.Empty,
            JsonValueKind.Number => value.GetRawText(),
            JsonValueKind.True => "true",
            JsonValueKind.False => "false",
            _ => value.ValueKind == JsonValueKind.Null ? string.Empty : value.ToString()
        };

    private static bool JsonElementBoolTrue(JsonElement root, string propertyName) =>
        TryGetJsonPropertyIgnoreCase(root, propertyName, out var p) && p.ValueKind == JsonValueKind.True;

    private static AuthRegistrationInfo ParseAuthRegistrationFromResource(JsonElement root)
    {
        var mfaRegistered = JsonElementBoolTrue(root, "isMfaRegistered") || JsonElementBoolTrue(root, "isMfaCapable");

        if (!TryGetJsonPropertyIgnoreCase(root, "methodsRegistered", out var methodsNode) || methodsNode.ValueKind != JsonValueKind.Array)
        {
            if (mfaRegistered)
            {
                return new AuthRegistrationInfo([], true, false);
            }

            return new AuthRegistrationInfo(["Unable to check"], false, false);
        }

        var methods = methodsNode.EnumerateArray()
            .Select(x => x.ValueKind == JsonValueKind.String ? x.GetString() ?? string.Empty : GetJsonElementScalarString(x))
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (methods.Count == 0 && TryGetJsonPropertyIgnoreCase(root, "defaultMfaMethod", out var dm) && dm.ValueKind == JsonValueKind.String)
        {
            var d = dm.GetString()?.Trim();
            if (!string.IsNullOrWhiteSpace(d) && !d.Equals("none", StringComparison.OrdinalIgnoreCase))
            {
                methods.Add(d);
            }
        }

        if (methods.Count == 0)
        {
            if (mfaRegistered)
            {
                return new AuthRegistrationInfo([], true, false);
            }

            methods.Add("None");
        }

        static bool IsRealAuthMethod(string m) =>
            !m.Equals("password", StringComparison.OrdinalIgnoreCase) &&
            !m.Equals("email", StringComparison.OrdinalIgnoreCase) &&
            !m.Equals("None", StringComparison.OrdinalIgnoreCase) &&
            !m.Equals("Unable to check", StringComparison.OrdinalIgnoreCase);

        var hasMfa = methods.Any(IsRealAuthMethod) || mfaRegistered;
        var hasPhishingResistant = methods.Any(m =>
            m.Equals("windowsHelloForBusiness", StringComparison.OrdinalIgnoreCase) ||
            m.Equals("fido2SecurityKey", StringComparison.OrdinalIgnoreCase) ||
            m.Equals("passkeyDeviceBound", StringComparison.OrdinalIgnoreCase) ||
            m.Equals("passkeyDeviceBoundAuthenticator", StringComparison.OrdinalIgnoreCase) ||
            m.Equals("passkeyDeviceBoundWindowsHello", StringComparison.OrdinalIgnoreCase) ||
            m.Contains("passkey", StringComparison.OrdinalIgnoreCase));

        return new AuthRegistrationInfo(methods, hasMfa, hasPhishingResistant);
    }

    private static (List<string> Methods, bool HasMfa, bool HasPhishingResistant) MergeAuthMethodSignals(
        (List<string> Methods, bool HasMfa, bool HasPhishingResistant) fromApi,
        AuthRegistrationInfo? fromRegistration)
    {
        static bool IsPlaceholder(string m) =>
            m.Equals("None", StringComparison.OrdinalIgnoreCase) ||
            m.Equals("Unable to check", StringComparison.OrdinalIgnoreCase);

        var merged = new List<string>();
        foreach (var m in fromApi.Methods.Where(m => !IsPlaceholder(m)))
        {
            merged.Add(m);
        }

        if (fromRegistration != null)
        {
            foreach (var m in fromRegistration.Methods.Where(m => !IsPlaceholder(m)))
            {
                if (!merged.Exists(x => string.Equals(x, m, StringComparison.OrdinalIgnoreCase)))
                {
                    merged.Add(m);
                }
            }
        }

        var hasMfa = fromApi.HasMfa || (fromRegistration?.HasMfa ?? false);
        var phish = fromApi.HasPhishingResistant || (fromRegistration?.HasPhishingResistant ?? false);

        if (merged.Count == 0)
        {
            merged.Add(hasMfa ? "mfaRegistered" : "None");
        }

        var distinct = merged.Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToList();
        return (distinct, hasMfa, phish);
    }

    private async Task<(List<string> Methods, bool HasMfa, bool HasPhishingResistant)> GetAuthInfoLightMergedAsync(
        string userId,
        string graphToken,
        Dictionary<string, AuthRegistrationInfo>? registrationMap,
        CancellationToken cancellationToken)
    {
        var fromApi = await GetAuthInfoFromUserAuthenticationMethodsAsync(userId, graphToken, cancellationToken).ConfigureAwait(false);

        AuthRegistrationInfo? reg = null;
        if (registrationMap != null && registrationMap.TryGetValue(userId, out var bulk))
        {
            reg = bulk;
        }

        var needsSingle = reg is null
                          || reg.Methods.Count == 0
                          || reg.Methods.TrueForAll(static m =>
                              m.Equals("None", StringComparison.OrdinalIgnoreCase) ||
                              m.Equals("Unable to check", StringComparison.OrdinalIgnoreCase));

        if (needsSingle
            && fromApi.Methods.TrueForAll(static m =>
                m.Equals("None", StringComparison.OrdinalIgnoreCase) ||
                m.Equals("Unable to check", StringComparison.OrdinalIgnoreCase)))
        {
            try
            {
                var doc = await GetJsonAsync(
                        $"https://graph.microsoft.com/beta/reports/authenticationMethods/userRegistrationDetails('{userId}')",
                        graphToken,
                        cancellationToken)
                    .ConfigureAwait(false);
                if (doc.HasValue)
                {
                    reg = ParseAuthRegistrationFromResource(doc.Value);
                }
            }
            catch
            {
            }
        }

        return MergeAuthMethodSignals(fromApi, reg);
    }

    private async Task<Dictionary<string, AuthRegistrationInfo>> LoadAuthRegistrationDetailsMapByUserIdAsync(string graphToken, CancellationToken cancellationToken)
    {
        var map = new Dictionary<string, AuthRegistrationInfo>(StringComparer.OrdinalIgnoreCase);
        const string baseUrl = "https://graph.microsoft.com/beta/reports/authenticationMethods/userRegistrationDetails";
        try
        {
            var rows = await GetJsonCollectionWithRetryAsync(baseUrl, graphToken, cancellationToken).ConfigureAwait(false);
            foreach (var row in rows)
            {
                var id = TryGetJsonPropertyIgnoreCase(row, "id", out var idEl)
                    ? GetJsonElementScalarString(idEl)
                    : GetString(row, "id");
                if (string.IsNullOrWhiteSpace(id))
                {
                    continue;
                }

                map[id.Trim()] = ParseAuthRegistrationFromResource(row);
            }
        }
        catch
        {
            // Fall back to per-user GetAuthInfoAsync
        }

        return map;
    }

    private async Task<(List<string> Methods, bool HasMfa, bool HasPhishingResistant)> GetAuthInfoAsync(string userId, string graphToken, CancellationToken cancellationToken)
    {
        var doc = await GetJsonAsync($"https://graph.microsoft.com/beta/reports/authenticationMethods/userRegistrationDetails('{userId}')", graphToken, cancellationToken);
        if (doc is null)
        {
            return (["Unable to check"], false, false);
        }

        var parsed = ParseAuthRegistrationFromResource(doc.Value);
        return (parsed.Methods, parsed.HasMfa, parsed.HasPhishingResistant);
    }

    /// <summary>Lightweight path: Graph list authentication methods (v1/beta) plus beta typed method collections when the aggregate list is incomplete.</summary>
    private async Task<(List<string> Methods, bool HasMfa, bool HasPhishingResistant)> GetAuthInfoFromUserAuthenticationMethodsAsync(
        string userId,
        string graphToken,
        CancellationToken cancellationToken)
    {
        var enc = Uri.EscapeDataString(userId);
        var labelByKey = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var anyHttpSuccess = false;

        void IngestRows(IReadOnlyList<JsonElement> rows)
        {
            foreach (var row in rows)
            {
                var odataRaw = TryGetJsonPropertyIgnoreCase(row, "@odata.type", out var odataEl)
                    ? GetJsonElementScalarString(odataEl)
                    : string.Empty;
                var label = MapAuthenticationMethodOdataType(odataRaw);
                if (string.IsNullOrWhiteSpace(label))
                {
                    continue;
                }

                var id = TryGetJsonPropertyIgnoreCase(row, "id", out var idEl) ? GetJsonElementScalarString(idEl) : string.Empty;
                var phone = TryGetJsonPropertyIgnoreCase(row, "phoneNumber", out var phEl) ? GetJsonElementScalarString(phEl) : GetString(row, "phoneNumber");
                var disp = TryGetJsonPropertyIgnoreCase(row, "displayName", out var dnEl) ? GetJsonElementScalarString(dnEl) : GetString(row, "displayName");
                var mail = TryGetJsonPropertyIgnoreCase(row, "emailAddress", out var emEl) ? GetJsonElementScalarString(emEl) : GetString(row, "emailAddress");
                var key = !string.IsNullOrWhiteSpace(id)
                    ? id
                    : $"{label}|{phone}|{disp}|{mail}";
                if (!labelByKey.ContainsKey(key))
                {
                    labelByKey[key] = label;
                }
            }
        }

        async Task TryUrlAsync(string url, bool countAsSuccessWhen200)
        {
            try
            {
                var rows = await GetJsonCollectionAsync(url, graphToken, cancellationToken).ConfigureAwait(false);
                if (countAsSuccessWhen200)
                {
                    anyHttpSuccess = true;
                }

                IngestRows(rows);
            }
            catch
            {
                // Continue with other endpoints
            }
        }

        await TryUrlAsync($"https://graph.microsoft.com/v1.0/users/{enc}/authentication/methods", true).ConfigureAwait(false);
        await TryUrlAsync($"https://graph.microsoft.com/beta/users/{enc}/authentication/methods", true).ConfigureAwait(false);

        var betaAuthBase = $"https://graph.microsoft.com/beta/users/{enc}/authentication/";
        foreach (var rel in new[]
                 {
                     "microsoftAuthenticatorMethods", "fido2Methods", "phoneMethods", "emailMethods", "emailOtpMethods",
                     "temporaryAccessPassMethods", "windowsHelloForBusinessMethods", "softwareOathMethods",
                     "passwordMethods", "hardwareOathMethods"
                 })
        {
            await TryUrlAsync(betaAuthBase + rel, true).ConfigureAwait(false);
        }

        if (!anyHttpSuccess)
        {
            return (["Unable to check"], false, false);
        }

        var labels = labelByKey.Values.ToList();
        if (labels.Count == 0)
        {
            labels.Add("None");
        }

        static bool IsRealAuthMethod(string m) =>
            !m.Equals("password", StringComparison.OrdinalIgnoreCase) &&
            !m.Equals("email", StringComparison.OrdinalIgnoreCase) &&
            !m.Equals("None", StringComparison.OrdinalIgnoreCase) &&
            !m.Equals("Unable to check", StringComparison.OrdinalIgnoreCase);

        var distinct = labels.Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToList();
        var hasMfa = distinct.Any(IsRealAuthMethod);
        var hasPhishingResistant = distinct.Any(IsPhishingResistantAuthMethodLabel);

        return (distinct, hasMfa, hasPhishingResistant);
    }

    private static bool IsPhishingResistantAuthMethodLabel(string m) =>
        m.Equals("windowsHelloForBusiness", StringComparison.OrdinalIgnoreCase) ||
        m.Equals("fido2SecurityKey", StringComparison.OrdinalIgnoreCase) ||
        m.Equals("passkey", StringComparison.OrdinalIgnoreCase) ||
        m.Contains("passkey", StringComparison.OrdinalIgnoreCase);

    /// <summary>Maps Graph <c>@odata.type</c> to stable labels; unknown types use a short derived name so nothing is silently dropped.</summary>
    private static string? MapAuthenticationMethodOdataType(string odataType)
    {
        if (string.IsNullOrWhiteSpace(odataType))
        {
            return null;
        }

        if (odataType.Contains("fido2AuthenticationMethod", StringComparison.OrdinalIgnoreCase))
        {
            return "fido2SecurityKey";
        }

        if (odataType.Contains("passkeyAuthenticationMethod", StringComparison.OrdinalIgnoreCase))
        {
            return "passkey";
        }

        if (odataType.Contains("windowsHelloForBusinessAuthenticationMethod", StringComparison.OrdinalIgnoreCase))
        {
            return "windowsHelloForBusiness";
        }

        if (odataType.Contains("microsoftAuthenticatorAuthenticationMethod", StringComparison.OrdinalIgnoreCase))
        {
            return "microsoftAuthenticator";
        }

        if (odataType.Contains("passwordlessMicrosoftAuthenticationMethod", StringComparison.OrdinalIgnoreCase))
        {
            return "passwordlessMicrosoftAuthenticator";
        }

        if (odataType.Contains("phoneAuthenticationMethod", StringComparison.OrdinalIgnoreCase))
        {
            return "phone";
        }

        if (odataType.Contains("emailAuthenticationMethod", StringComparison.OrdinalIgnoreCase))
        {
            return "email";
        }

        if (odataType.Contains("emailOtpAuthenticationMethod", StringComparison.OrdinalIgnoreCase))
        {
            return "emailOtp";
        }

        if (odataType.Contains("passwordAuthenticationMethod", StringComparison.OrdinalIgnoreCase))
        {
            return "password";
        }

        if (odataType.Contains("temporaryAccessPassAuthenticationMethod", StringComparison.OrdinalIgnoreCase))
        {
            return "temporaryAccessPass";
        }

        if (odataType.Contains("softwareOathAuthenticationMethod", StringComparison.OrdinalIgnoreCase))
        {
            return "softwareOath";
        }

        if (odataType.Contains("hardwareOathAuthenticationMethod", StringComparison.OrdinalIgnoreCase))
        {
            return "hardwareOath";
        }

        if (odataType.Contains("platformCredentialAuthenticationMethod", StringComparison.OrdinalIgnoreCase))
        {
            return "platformCredential";
        }

        if (odataType.Contains("x509CertificateAuthenticationMethod", StringComparison.OrdinalIgnoreCase))
        {
            return "x509Certificate";
        }

        if (odataType.Contains("qrCodePinAuthenticationMethod", StringComparison.OrdinalIgnoreCase))
        {
            return "qrCodePin";
        }

        if (odataType.Contains("federatedIdentityAuthenticationMethod", StringComparison.OrdinalIgnoreCase))
        {
            return "federatedIdentity";
        }

        if (odataType.Contains("voiceAuthenticationMethod", StringComparison.OrdinalIgnoreCase))
        {
            return "voice";
        }

        var t = odataType.Trim();
        const string prefix = "#microsoft.graph.";
        if (t.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) &&
            t.EndsWith("AuthenticationMethod", StringComparison.OrdinalIgnoreCase))
        {
            var inner = t[prefix.Length..^"AuthenticationMethod".Length];
            return inner.Length > 0 ? char.ToLowerInvariant(inner[0]) + inner[1..] : "authenticationMethod";
        }

        return t.Length > 0 ? t : null;
    }

    private async Task<List<string>> GetUserGroupIdsAsync(string userId, string graphToken, CancellationToken cancellationToken)
    {
        var groups = await GetJsonCollectionAsync($"https://graph.microsoft.com/v1.0/users/{userId}/memberOf?$select=id", graphToken, cancellationToken);
        return groups
            .Where(x => GetString(x, "@odata.type").Equals("#microsoft.graph.group", StringComparison.OrdinalIgnoreCase))
            .Select(x => GetString(x, "id"))
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    /// <summary>All group IDs (nested) for Azure RBAC inheritance — same idea as Entra PIM via nested groups.</summary>
    private Task<List<string>> GetUserTransitiveGroupIdsAsync(string userId, string graphToken, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(userId))
        {
            return Task.FromResult(new List<string>());
        }

        var uid = userId.Trim();
        if (_privilegedReportTransitiveGroupsByUserId is not null)
        {
            var lazy = _privilegedReportTransitiveGroupsByUserId.GetOrAdd(
                uid,
                _ => new Lazy<Task<List<string>>>(() => FetchUserTransitiveGroupIdsCoreAsync(uid, graphToken, cancellationToken)));
            return lazy.Value;
        }

        return FetchUserTransitiveGroupIdsCoreAsync(uid, graphToken, cancellationToken);
    }

    private async Task<List<string>> FetchUserTransitiveGroupIdsCoreAsync(string userId, string graphToken, CancellationToken cancellationToken)
    {
        var groups = await GetJsonCollectionAsync(
                $"https://graph.microsoft.com/v1.0/users/{Uri.EscapeDataString(userId)}/transitiveMemberOf?$select=id",
                graphToken,
                cancellationToken)
            .ConfigureAwait(false);
        return groups
            .Where(x => GetString(x, "@odata.type").Equals("#microsoft.graph.group", StringComparison.OrdinalIgnoreCase))
            .Select(x => GetString(x, "id"))
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    /// <summary>
    /// PIM for Groups: groups where the principal has eligible or active assignment schedules (Graph
    /// <c>Get-MgIdentityGovernancePrivilegedAccessGroupEligibilitySchedule*</c> / <c>AssignmentSchedule*</c> parity).
    /// These <c>groupId</c> values must be unioned with <see cref="GetUserTransitiveGroupIdsAsync"/> so Azure ARM and
    /// Entra directory-role PIM rows tied to the group principal are resolved before the user activates membership.
    /// </summary>
    private Task<List<string>> GetIdentityGovernancePrivilegedAccessGroupIdsForPrincipalAsync(
        string principalId,
        string graphToken,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(principalId))
        {
            return Task.FromResult(new List<string>());
        }

        var pid = principalId.Trim();
        if (_privilegedReportPrivilegedAccessGroupIdsByPrincipal is not null)
        {
            var lazy = _privilegedReportPrivilegedAccessGroupIdsByPrincipal.GetOrAdd(
                pid,
                _ => new Lazy<Task<List<string>>>(() => FetchIdentityGovernancePrivilegedAccessGroupIdsCoreAsync(pid, graphToken, cancellationToken)));
            return lazy.Value;
        }

        return FetchIdentityGovernancePrivilegedAccessGroupIdsCoreAsync(pid, graphToken, cancellationToken);
    }

    private async Task<List<string>> FetchIdentityGovernancePrivilegedAccessGroupIdsCoreAsync(
        string pid,
        string graphToken,
        CancellationToken cancellationToken)
    {
        var utcNow = DateTime.UtcNow;

        // v1 requires $filter principalId or groupId on instances; schedules support the same pattern on supported tenants.
        var urls = new[]
        {
            $"https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/eligibilityScheduleInstances?$filter=principalId eq '{pid}'",
            $"https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/assignmentScheduleInstances?$filter=principalId eq '{pid}'",
            $"https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/eligibilitySchedules?$filter=principalId eq '{pid}'",
            $"https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/assignmentSchedules?$filter=principalId eq '{pid}'",
        };

        var bag = new ConcurrentBag<string>();
        await Task.WhenAll(urls.Select(async url =>
        {
            try
            {
                var rows = await GetJsonCollectionAsync(url, graphToken, cancellationToken).ConfigureAwait(false);
                foreach (var row in rows)
                {
                    if (!IsPrivilegedAccessGroupRowStillEffective(row, utcNow))
                    {
                        continue;
                    }

                    var gid = GetString(row, "groupId");
                    if (string.IsNullOrWhiteSpace(gid))
                    {
                        continue;
                    }

                    var accessId = GetString(row, "accessId");
                    if (!string.IsNullOrWhiteSpace(accessId)
                        && !accessId.Equals("member", StringComparison.OrdinalIgnoreCase)
                        && !accessId.Equals("owner", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    bag.Add(gid.Trim());
                }
            }
            catch
            {
                // PrivilegedEligibilitySchedule.Read.AzureADGroup / PrivilegedAssignmentSchedule.Read.AzureADGroup or unsupported filters.
            }
        })).ConfigureAwait(false);

        return bag.ToHashSet(StringComparer.OrdinalIgnoreCase).ToList();
    }

    private async Task<(List<string> AppRolePermissions, List<string> DelegatedScopes)> GetApplicationPermissionsByAppIdAsync(string appId, string graphToken, CancellationToken cancellationToken)
    {
        var sp = await GetJsonCollectionAsync($"https://graph.microsoft.com/v1.0/servicePrincipals?$filter=appId eq '{appId}'&$select=id", graphToken, cancellationToken);
        var spId = sp.Select(x => GetString(x, "id")).FirstOrDefault(x => !string.IsNullOrWhiteSpace(x));
        if (string.IsNullOrWhiteSpace(spId))
        {
            return ([], []);
        }

        return await GetApplicationPermissionsByServicePrincipalIdAsync(spId, graphToken, cancellationToken);
    }

    private async Task<List<string>> GetAppRoleAssignmentStringsAsync(string servicePrincipalId, string graphToken, CancellationToken cancellationToken)
    {
        var lines = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var appRoleAssignments = await GetJsonCollectionAsync($"https://graph.microsoft.com/v1.0/servicePrincipals/{servicePrincipalId}/appRoleAssignments", graphToken, cancellationToken);
        foreach (var assignment in appRoleAssignments)
        {
            var resourceId = GetString(assignment, "resourceId");
            var resourceDisplayName = GetString(assignment, "resourceDisplayName");
            var appRoleId = GetString(assignment, "appRoleId");
            if (string.IsNullOrWhiteSpace(appRoleId))
            {
                continue;
            }

            if (appRoleId.Equals("00000000-0000-0000-0000-000000000000", StringComparison.OrdinalIgnoreCase))
            {
                lines.Add($"{resourceDisplayName}: (default access)");
                continue;
            }

            var resolved = await LookupAppRoleDisplayNameAsync(resourceId, appRoleId, graphToken, cancellationToken);
            if (!string.IsNullOrWhiteSpace(resolved))
            {
                lines.Add($"{resourceDisplayName}: {resolved}");
            }
            else
            {
                lines.Add($"{resourceDisplayName}: {appRoleId}");
            }
        }

        return lines.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToList();
    }

    private async Task<string?> LookupAppRoleDisplayNameAsync(string resourceServicePrincipalId, string appRoleId, string graphToken, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(resourceServicePrincipalId) || string.IsNullOrWhiteSpace(appRoleId))
        {
            return null;
        }

        var lazy = _resourceAppRoleLookup.GetOrAdd(
            resourceServicePrincipalId,
            _ => new Lazy<Task<Dictionary<string, string>>>(() => LoadAppRoleMapForResourceAsync(resourceServicePrincipalId, graphToken, cancellationToken), LazyThreadSafetyMode.ExecutionAndPublication));

        var map = await lazy.Value;
        return map.TryGetValue(appRoleId, out var label) ? label : null;
    }

    private async Task<Dictionary<string, string>> LoadAppRoleMapForResourceAsync(string resourceServicePrincipalId, string graphToken, CancellationToken cancellationToken)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var sp = await GetJsonAsync($"https://graph.microsoft.com/v1.0/servicePrincipals/{resourceServicePrincipalId}?$select=appRoles", graphToken, cancellationToken);
        if (sp is null || !sp.Value.TryGetProperty("appRoles", out var roles) || roles.ValueKind != JsonValueKind.Array)
        {
            return map;
        }

        foreach (var role in roles.EnumerateArray())
        {
            var id = GetString(role, "id");
            if (string.IsNullOrWhiteSpace(id))
            {
                continue;
            }

            var displayName = GetString(role, "displayName");
            var value = GetString(role, "value");
            // Prefer canonical permission value (e.g. Application.ReadWrite.All).
            var label = !string.IsNullOrWhiteSpace(value) ? value : displayName;
            if (string.IsNullOrWhiteSpace(label))
            {
                label = id;
            }

            map[id] = label;
        }

        return map;
    }

    private async Task<(List<string> AppRolePermissions, List<string> DelegatedScopes)> GetApplicationPermissionsByServicePrincipalIdAsync(string servicePrincipalId, string graphToken, CancellationToken cancellationToken)
    {
        var appRoles = await GetAppRoleAssignmentStringsAsync(servicePrincipalId, graphToken, cancellationToken);
        var delegated = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var delegatedGrants = await GetJsonCollectionAsync($"https://graph.microsoft.com/v1.0/oauth2PermissionGrants?$filter=clientId eq '{servicePrincipalId}'", graphToken, cancellationToken);
        foreach (var grant in delegatedGrants)
        {
            var scope = GetString(grant, "scope");
            foreach (var part in scope.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                delegated.Add(part);
            }
        }

        return (appRoles, delegated.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToList());
    }

    private static void AddRole(Dictionary<string, HashSet<string>> userRolesMap, string userId, string roleName)
    {
        if (!userRolesMap.TryGetValue(userId, out var roles))
        {
            roles = [];
            userRolesMap[userId] = roles;
        }

        roles.Add(roleName);
    }

    /// <summary>
    /// ARM PIM/RBAC often returns <c>roleDefinitionId</c> as a bare GUID; the role definition resource path must include the assignment <paramref name="scopePath"/>.
    /// </summary>
    private static string? NormalizeArmRoleDefinitionResourcePath(string? roleDefinitionId, string? scopePath)
    {
        if (string.IsNullOrWhiteSpace(roleDefinitionId))
        {
            return null;
        }

        var rd = roleDefinitionId.Trim();
        if (rd.StartsWith("/", StringComparison.Ordinal))
        {
            return rd;
        }

        static bool LooksLikeRoleDefGuid(string s) =>
            Guid.TryParse(s, out _) ||
            (s.Length == 36 && s[8] == '-' && s[13] == '-' && s[18] == '-' && s[23] == '-');

        if (!LooksLikeRoleDefGuid(rd))
        {
            return null;
        }

        var scope = string.IsNullOrWhiteSpace(scopePath) ? "/" : scopePath.Trim();
        if (scope == "/" || scope.Equals("/", StringComparison.Ordinal))
        {
            return $"/providers/Microsoft.Authorization/roleDefinitions/{rd}";
        }

        return $"{scope.TrimEnd('/')}/providers/Microsoft.Authorization/roleDefinitions/{rd}";
    }

    private async Task<string> ResolveAzureRoleNameAsync(string? roleDefinitionId, string? scopePath, string armToken, CancellationToken cancellationToken)
    {
        var resourcePath = NormalizeArmRoleDefinitionResourcePath(roleDefinitionId, scopePath);
        if (string.IsNullOrWhiteSpace(resourcePath))
        {
            return "Unknown";
        }

        if (_azureRoleNameCache.TryGetValue(resourcePath, out var cached))
        {
            return cached;
        }

        var roleDoc = await GetJsonAsync($"https://management.azure.com{resourcePath}?api-version=2022-04-01", armToken, cancellationToken);
        if (roleDoc is null || !roleDoc.Value.TryGetProperty("properties", out var props))
        {
            return "Unknown";
        }

        var name = GetString(props, "roleName");
        if (!string.IsNullOrWhiteSpace(name))
        {
            _azureRoleNameCache[resourcePath] = name;
            return name;
        }

        return "Unknown";
    }

    private static bool IsPrivilegedAzureRole(string roleName) =>
        PrivilegedRoleCatalog.IsAzurePrivilegedRoleForReport(roleName);

    private static bool IncludeEntraDirectoryRoleInPrivilegedReport(string? roleName) =>
        PrivilegedRoleCatalog.IsEntraRoleInPrivilegedScope(roleName);

    /// <summary>Built-in directory roles to enumerate for membership. Skips Directory Readers only (would expand nearly every user). All other Entra admin roles—including those listed in Microsoft’s role reference—are enumerated when returned by Graph.</summary>
    private static bool IncludeEntraDirectoryRoleInMembershipEnumeration(string? directoryRoleDisplayName)
    {
        if (string.IsNullOrWhiteSpace(directoryRoleDisplayName))
        {
            return false;
        }

        return !directoryRoleDisplayName.Trim().Equals("Directory Readers", StringComparison.OrdinalIgnoreCase);
    }

    private static string TryGetRoleNameFromProperties(JsonElement props, string fallback)
    {
        var direct = GetString(props, "roleDefinitionDisplayName");
        if (!string.IsNullOrWhiteSpace(direct))
        {
            return direct;
        }

        if (props.TryGetProperty("expandedProperties", out var exp) && exp.ValueKind == JsonValueKind.Object)
        {
            if (exp.TryGetProperty("roleDefinition", out var rd) && rd.ValueKind == JsonValueKind.Object)
            {
                var rdName = GetString(rd, "displayName");
                if (!string.IsNullOrWhiteSpace(rdName))
                {
                    return rdName;
                }
            }
        }

        return fallback;
    }

    private static bool TryParseGraphODataDateTime(string? s, out DateTime utc)
    {
        utc = default;
        if (string.IsNullOrWhiteSpace(s))
        {
            return false;
        }

        if (DateTimeOffset.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var dto))
        {
            utc = dto.UtcDateTime;
            return true;
        }

        return false;
    }

    /// <summary>
    /// Graph/OData often use 0001-01-01 (or other pre-1970 values) as a sentinel for "no end"; those must not be treated as expired.
    /// </summary>
    private static bool IsDefiniteExpiredEligibilityEnd(DateTime endUtc, DateTime utcNow) =>
        endUtc.Year >= 1970 && endUtc < utcNow;

    /// <summary>
    /// PIM <c>unifiedRoleEligibilityScheduleRequest</c> rows (see
    /// <see href="https://learn.microsoft.com/en-us/graph/api/rbacapplication-list-roleeligibilityschedulerequests">List roleEligibilityScheduleRequests</see>):
    /// skip revoked/canceled/denied and pending-approval rows; schedules/instances omit <c>status</c> and pass through.
    /// </summary>
    private static bool ShouldIncludeEntraEligibilityScheduleRequest(JsonElement item)
    {
        var status = GetString(item, "status");
        if (!string.IsNullOrWhiteSpace(status))
        {
            if (status.Equals("Revoked", StringComparison.OrdinalIgnoreCase)
                || status.Equals("Canceled", StringComparison.OrdinalIgnoreCase)
                || status.Equals("Cancelled", StringComparison.OrdinalIgnoreCase)
                || status.Equals("Denied", StringComparison.OrdinalIgnoreCase)
                || status.Equals("Failed", StringComparison.OrdinalIgnoreCase)
                || status.Equals("ApprovalPending", StringComparison.OrdinalIgnoreCase)
                || status.Equals("PendingApproval", StringComparison.OrdinalIgnoreCase)
                || status.Equals("CanceledApproval", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>False when Graph exposes a real end time in the past (expired eligibility). Sentinels and noEnd stay effective.</summary>
    private static bool IsEntraEligibilityRowStillEffective(JsonElement item, DateTime utcNow)
    {
        if (item.TryGetProperty("scheduleInfo", out var si0) && si0.ValueKind == JsonValueKind.Object
            && si0.TryGetProperty("expiration", out var exp0) && exp0.ValueKind == JsonValueKind.Object)
        {
            if (exp0.TryGetProperty("type", out var tp0) && tp0.ValueKind == JsonValueKind.String
                && (tp0.GetString() ?? string.Empty).Equals("noEnd", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        if (item.TryGetProperty("endDateTime", out var endTop) && endTop.ValueKind == JsonValueKind.String)
        {
            if (TryParseGraphODataDateTime(endTop.GetString(), out var endUtc)
                && IsDefiniteExpiredEligibilityEnd(endUtc, utcNow))
            {
                return false;
            }
        }

        if (item.TryGetProperty("scheduleInfo", out var si) && si.ValueKind == JsonValueKind.Object
            && si.TryGetProperty("expiration", out var exp) && exp.ValueKind == JsonValueKind.Object)
        {
            if (exp.TryGetProperty("endDateTime", out var endExp) && endExp.ValueKind == JsonValueKind.String)
            {
                if (TryParseGraphODataDateTime(endExp.GetString(), out var endUtc)
                    && IsDefiniteExpiredEligibilityEnd(endUtc, utcNow))
                {
                    return false;
                }
            }
        }

        return true;
    }

    /// <summary>
    /// PIM for Groups resources use <c>startDateTime</c> / <c>endDateTime</c> on the resource root (not directory <c>scheduleInfo</c>).
    /// </summary>
    private static bool IsPrivilegedAccessGroupRowStillEffective(JsonElement item, DateTime utcNow)
    {
        if (item.TryGetProperty("startDateTime", out var st) && st.ValueKind == JsonValueKind.String)
        {
            if (TryParseGraphODataDateTime(st.GetString(), out var startUtc) && startUtc > utcNow)
            {
                return false;
            }
        }

        if (item.TryGetProperty("endDateTime", out var en) && en.ValueKind == JsonValueKind.String)
        {
            if (TryParseGraphODataDateTime(en.GetString(), out var endUtc)
                && IsDefiniteExpiredEligibilityEnd(endUtc, utcNow))
            {
                return false;
            }
        }

        return true;
    }

    private static string ScopeToDisplay(string scope, string subscriptionName)
    {
        if (string.IsNullOrWhiteSpace(scope))
        {
            return "Azure tenant root (/)";
        }

        if (scope.Equals("/", StringComparison.Ordinal))
        {
            return "Azure tenant root (/)";
        }

        if (scope.StartsWith("/providers/Microsoft.Management/managementGroups/", StringComparison.OrdinalIgnoreCase))
        {
            var segmentsMg = scope.Split('/', StringSplitOptions.RemoveEmptyEntries);
            var mgIndex = Array.FindIndex(segmentsMg, x => x.Equals("managementGroups", StringComparison.OrdinalIgnoreCase));
            if (mgIndex >= 0 && mgIndex + 1 < segmentsMg.Length)
            {
                return $"Management group / {segmentsMg[mgIndex + 1]}";
            }
            return "Management group (unresolved id)";
        }

        if (scope.StartsWith("/providers/Microsoft.Authorization", StringComparison.OrdinalIgnoreCase))
        {
            return "Azure tenant root (authorization scope)";
        }

        var segments = scope.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (scope.Contains("/resourceGroups/", StringComparison.OrdinalIgnoreCase))
        {
            var rgIndex = Array.FindIndex(segments, x => x.Equals("resourceGroups", StringComparison.OrdinalIgnoreCase));
            if (rgIndex >= 0 && rgIndex + 1 < segments.Length)
            {
                var subLabel = !string.IsNullOrWhiteSpace(subscriptionName) ? subscriptionName : FindSubscriptionIdInSegments(segments);
                return $"Resource group / {segments[rgIndex + 1]} (subscription: {subLabel})";
            }
        }

        if (segments.Length == 2 && segments[0].Equals("subscriptions", StringComparison.OrdinalIgnoreCase))
        {
            var subId = segments[1];
            if (!string.IsNullOrWhiteSpace(subscriptionName))
            {
                return $"Subscription / {subscriptionName}";
            }
            return $"Subscription / {subId}";
        }

        return scope;
    }

    private sealed class ArmScopeDisplayCache
    {
        /// <summary>Concurrent: many ARM scope tasks call <see cref="ScopeToDisplayAsync"/> in parallel per user.</summary>
        public ConcurrentDictionary<string, string?> SubscriptionDisplay { get; } = new(StringComparer.OrdinalIgnoreCase);

        public ConcurrentDictionary<string, string?> ManagementGroupDisplay { get; } = new(StringComparer.OrdinalIgnoreCase);
    }

    private async Task<string?> TryGetSubscriptionDisplayNameAsync(
        string subscriptionId,
        string armToken,
        ArmScopeDisplayCache cache,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(subscriptionId) || subscriptionId == "?")
        {
            return null;
        }

        if (cache.SubscriptionDisplay.TryGetValue(subscriptionId, out var cached))
        {
            return cached;
        }

        var doc = await GetJsonAsync(
            $"https://management.azure.com/subscriptions/{Uri.EscapeDataString(subscriptionId)}?api-version=2022-12-01",
            armToken,
            cancellationToken);
        string? name = null;
        if (doc.HasValue)
        {
            name = GetString(doc.Value, "displayName");
        }

        cache.SubscriptionDisplay[subscriptionId] = name;
        return name;
    }

    private async Task<string?> TryGetManagementGroupDisplayNameAsync(
        string mgName,
        string armToken,
        ArmScopeDisplayCache cache,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(mgName))
        {
            return null;
        }

        if (cache.ManagementGroupDisplay.TryGetValue(mgName, out var cached))
        {
            return cached;
        }

        var doc = await GetJsonAsync(
            $"https://management.azure.com/providers/Microsoft.Management/managementGroups/{Uri.EscapeDataString(mgName)}?api-version=2021-04-01",
            armToken,
            cancellationToken);
        string? name = null;
        if (doc.HasValue && doc.Value.TryGetProperty("properties", out var props))
        {
            name = GetString(props, "displayName");
        }

        cache.ManagementGroupDisplay[mgName] = name;
        return name;
    }

    private async Task<string> ScopeToDisplayAsync(
        string scope,
        string armToken,
        ArmScopeDisplayCache cache,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(armToken))
        {
            return ScopeToDisplay(scope, string.Empty);
        }

        if (string.IsNullOrWhiteSpace(scope))
        {
            return "Azure tenant root (/)";
        }

        if (scope.Equals("/", StringComparison.Ordinal))
        {
            return "Azure tenant root (/)";
        }

        if (scope.StartsWith("/providers/Microsoft.Management/managementGroups/", StringComparison.OrdinalIgnoreCase))
        {
            var segmentsMg = scope.Split('/', StringSplitOptions.RemoveEmptyEntries);
            var mgIndex = Array.FindIndex(segmentsMg, x => x.Equals("managementGroups", StringComparison.OrdinalIgnoreCase));
            if (mgIndex >= 0 && mgIndex + 1 < segmentsMg.Length)
            {
                var mgId = segmentsMg[mgIndex + 1];
                var friendly = await TryGetManagementGroupDisplayNameAsync(mgId, armToken, cache, cancellationToken).ConfigureAwait(false);
                var label = !string.IsNullOrWhiteSpace(friendly) ? friendly : mgId;
                return $"Management group / {label}";
            }

            return "Management group (unresolved id)";
        }

        if (scope.StartsWith("/providers/Microsoft.Authorization", StringComparison.OrdinalIgnoreCase))
        {
            return "Azure tenant root (authorization scope)";
        }

        var segments = scope.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (scope.Contains("/resourceGroups/", StringComparison.OrdinalIgnoreCase))
        {
            var rgIndex = Array.FindIndex(segments, x => x.Equals("resourceGroups", StringComparison.OrdinalIgnoreCase));
            if (rgIndex >= 0 && rgIndex + 1 < segments.Length)
            {
                var subId = FindSubscriptionIdInSegments(segments);
                var subLabel = await TryGetSubscriptionDisplayNameAsync(subId, armToken, cache, cancellationToken).ConfigureAwait(false);
                var subPart = !string.IsNullOrWhiteSpace(subLabel) ? subLabel : subId;
                return $"Resource group / {segments[rgIndex + 1]} (subscription: {subPart})";
            }
        }

        if (segments.Length == 2 && segments[0].Equals("subscriptions", StringComparison.OrdinalIgnoreCase))
        {
            var subId = segments[1];
            var friendly = await TryGetSubscriptionDisplayNameAsync(subId, armToken, cache, cancellationToken).ConfigureAwait(false);
            if (!string.IsNullOrWhiteSpace(friendly))
            {
                return $"Subscription / {friendly}";
            }

            return $"Subscription / {subId}";
        }

        return scope;
    }

    private static string FindSubscriptionIdInSegments(string[] segments)
    {
        var idx = Array.FindIndex(segments, x => x.Equals("subscriptions", StringComparison.OrdinalIgnoreCase));
        if (idx >= 0 && idx + 1 < segments.Length)
        {
            return segments[idx + 1];
        }

        return "?";
    }

    private static string FormatDate(JsonElement signInActivity, string propertyName)
    {
        if (signInActivity.ValueKind != JsonValueKind.Object || !signInActivity.TryGetProperty(propertyName, out var dateNode))
        {
            return "Never";
        }

        var raw = dateNode.GetString();
        if (string.IsNullOrWhiteSpace(raw))
        {
            return "Never";
        }

        return DateTime.TryParse(raw, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal, out var dt)
            ? dt.ToString("yyyy-MM-dd HH:mm")
            : "Never";
    }

    private static DateTime? ParseDateUtc(JsonElement signInActivity, string propertyName)
    {
        if (signInActivity.ValueKind != JsonValueKind.Object || !signInActivity.TryGetProperty(propertyName, out var dateNode))
        {
            return null;
        }

        var raw = dateNode.GetString();
        if (string.IsNullOrWhiteSpace(raw))
        {
            return null;
        }

        return DateTime.TryParse(raw, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal, out var dt)
            ? dt.ToUniversalTime()
            : null;
    }

    private static bool IsStaleBySignIns(JsonElement signInActivity)
    {
        var i = ParseDateUtc(signInActivity, "lastSignInDateTime");
        var n = ParseDateUtc(signInActivity, "lastNonInteractiveSignInDateTime");
        var latest = new[] { i, n }.Where(x => x.HasValue).Select(x => x!.Value).DefaultIfEmpty(DateTime.MinValue).Max();
        if (latest == DateTime.MinValue)
        {
            return true;
        }

        return latest < DateTime.UtcNow.AddDays(-90);
    }

    private async Task<JsonElement?> GetJsonAsync(string url, string accessToken, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        using var response = await httpClient.SendAsync(request, cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            return null;
        }

        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken));
        return document.RootElement.Clone();
    }

    /// <summary>Graph directory reads sometimes require <c>ConsistencyLevel: eventual</c> (e.g. directoryObjects).</summary>
    private async Task<JsonElement?> GetJsonAsyncWithConsistencyAsync(
        string url,
        string accessToken,
        CancellationToken cancellationToken,
        string consistencyLevel)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        request.Headers.TryAddWithoutValidation("ConsistencyLevel", consistencyLevel);
        using var response = await httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            return null;
        }

        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false));
        return document.RootElement.Clone();
    }

    /// <summary>Resolves group displayName via <see href="https://learn.microsoft.com/en-us/graph/api/directoryobject-getbyids">directoryObjects/getByIds</see>.</summary>
    private async Task<string?> DirectoryObjectsGetByIdsLookupGroupDisplayNameAsync(
        string objectId,
        string graphToken,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(objectId))
        {
            return null;
        }

        try
        {
            var payload = JsonSerializer.Serialize(new
            {
                ids = new[] { objectId },
                types = new[] { "microsoft.graph.group" }
            });
            foreach (var url in new[]
                     {
                         "https://graph.microsoft.com/v1.0/directoryObjects/getByIds",
                         "https://graph.microsoft.com/v1.0/directoryObjects/microsoft.graph.getByIds"
                     })
            {
                using var request = new HttpRequestMessage(HttpMethod.Post, url);
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", graphToken);
                request.Content = new StringContent(payload, Encoding.UTF8, "application/json");
                using var response = await httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
                if (!response.IsSuccessStatusCode)
                {
                    continue;
                }

                using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false));
                var root = document.RootElement;
                if (!root.TryGetProperty("value", out var value) || value.ValueKind != JsonValueKind.Array)
                {
                    continue;
                }

                foreach (var el in value.EnumerateArray())
                {
                    var otype = GetString(el, "@odata.type");
                    if (!otype.Contains("group", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    var dn = GetString(el, "displayName");
                    if (!string.IsNullOrWhiteSpace(dn))
                    {
                        return dn;
                    }
                }
            }
        }
        catch
        {
            // ignore
        }

        return null;
    }

    private static string? PickArmExpandedPrincipalFriendlyName(JsonElement prin)
    {
        foreach (var key in new[] { "displayName", "principalName", "email", "mail", "userPrincipalName", "mailNickname" })
        {
            var s = GetString(prin, key);
            if (string.IsNullOrWhiteSpace(s))
            {
                continue;
            }

            s = s.Trim();
            if (Guid.TryParse(s, out _))
            {
                continue;
            }

            return s;
        }

        return null;
    }

    private static void ApplyArmExpandedGroupPrincipal(JsonElement props, ref bool viaGroup, ref string? groupName)
    {
        if (!props.TryGetProperty("expandedProperties", out var exp) || exp.ValueKind != JsonValueKind.Object)
        {
            return;
        }

        if (!exp.TryGetProperty("principal", out var prin) || prin.ValueKind != JsonValueKind.Object)
        {
            return;
        }

        var ptype = GetString(prin, "type");
        if (!ptype.Contains("Group", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        viaGroup = true;
        var picked = PickArmExpandedPrincipalFriendlyName(prin);
        if (!string.IsNullOrWhiteSpace(picked))
        {
            groupName = picked;
        }
    }

    /// <summary>
    /// ARM often sets <c>memberType</c> to <c>Inherited</c> for PIM rows even when the assignment principal is the user (direct eligible/active).
    /// Only treat as &quot;via group&quot; when the role is actually assigned to a group principal (or a group the user belongs to), not <paramref name="userId"/>.
    /// </summary>
    private static void FinalizeAzureViaGroupForPrincipal(string userId, string principalId, ref bool viaGroup, ref string? groupName)
    {
        if (string.IsNullOrWhiteSpace(userId) || string.IsNullOrWhiteSpace(principalId))
        {
            return;
        }

        if (principalId.Equals(userId, StringComparison.OrdinalIgnoreCase))
        {
            viaGroup = false;
            groupName = null;
        }
    }

    /// <summary>GET single resource with 429 / 503 retries (Retry-After aware).</summary>
    private async Task<JsonElement?> GetJsonWithRetryAsync(string url, string accessToken, CancellationToken cancellationToken, int maxAttempts = 6)
    {
        for (var attempt = 1; attempt <= maxAttempts; attempt++)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            using var response = await httpClient.SendAsync(request, cancellationToken);
            if (response.IsSuccessStatusCode)
            {
                using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken));
                return document.RootElement.Clone();
            }

            if (response.StatusCode == HttpStatusCode.TooManyRequests && attempt < maxAttempts)
            {
                var wait = ParseRetryAfterSeconds(response) ?? Math.Min(60, 2 * attempt);
                await Task.Delay(TimeSpan.FromSeconds(wait), cancellationToken);
                continue;
            }

            if (response.StatusCode == HttpStatusCode.ServiceUnavailable && attempt < maxAttempts)
            {
                await Task.Delay(TimeSpan.FromSeconds(Math.Min(30, attempt * 2)), cancellationToken);
                continue;
            }

            return null;
        }

        return null;
    }

    private static int? ParseRetryAfterSeconds(HttpResponseMessage response)
    {
        if (response.Headers.RetryAfter?.Delta is TimeSpan d)
        {
            return (int)Math.Ceiling(Math.Min(Math.Max(d.TotalSeconds, 1), 120));
        }

        if (response.Headers.TryGetValues("Retry-After", out var values))
        {
            var first = values.FirstOrDefault();
            if (int.TryParse(first, NumberStyles.Integer, CultureInfo.InvariantCulture, out var sec) && sec >= 0)
            {
                return Math.Min(sec, 120);
            }
        }

        return null;
    }

    /// <summary>Paginated GET with 429 / 503 retries per page (beta report lists).</summary>
    private async Task<List<JsonElement>> GetJsonCollectionWithRetryAsync(
        string url,
        string accessToken,
        CancellationToken cancellationToken,
        int maxAttemptsPerPage = 8)
    {
        var output = new List<JsonElement>();
        var next = url;
        while (!string.IsNullOrWhiteSpace(next))
        {
            List<JsonElement>? pageElements = null;
            string? nextLink = null;

            for (var attempt = 1; attempt <= maxAttemptsPerPage; attempt++)
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, next);
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
                request.Headers.TryAddWithoutValidation("ConsistencyLevel", "eventual");
                using var response = await httpClient.SendAsync(request, cancellationToken);
                if (response.StatusCode == HttpStatusCode.OK)
                {
                    using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken));
                    var root = document.RootElement;
                    if (root.TryGetProperty("value", out var value) && value.ValueKind == JsonValueKind.Array)
                    {
                        pageElements = value.EnumerateArray().Select(x => x.Clone()).ToList();
                        nextLink = ReadCollectionNextPageLink(root);
                    }
                    else
                    {
                        pageElements = [root.Clone()];
                        nextLink = null;
                    }

                    break;
                }

                if (response.StatusCode == HttpStatusCode.TooManyRequests && attempt < maxAttemptsPerPage)
                {
                    var wait = ParseRetryAfterSeconds(response) ?? Math.Min(60, 2 * attempt);
                    await Task.Delay(TimeSpan.FromSeconds(wait), cancellationToken);
                    continue;
                }

                if (response.StatusCode == HttpStatusCode.ServiceUnavailable && attempt < maxAttemptsPerPage)
                {
                    await Task.Delay(TimeSpan.FromSeconds(Math.Min(30, attempt * 2)), cancellationToken);
                    continue;
                }

                pageElements = null;
                break;
            }

            if (pageElements is null)
            {
                break;
            }

            output.AddRange(pageElements);
            next = string.IsNullOrWhiteSpace(nextLink) ? null : nextLink;
        }

        return output;
    }

    /// <summary>Graph uses <c>@odata.nextLink</c>; Azure Resource Manager uses <c>nextLink</c>.</summary>
    private static string? ReadCollectionNextPageLink(JsonElement root)
    {
        if (root.TryGetProperty("@odata.nextLink", out var odata) && odata.ValueKind == JsonValueKind.String)
        {
            return odata.GetString();
        }

        if (root.TryGetProperty("nextLink", out var arm) && arm.ValueKind == JsonValueKind.String)
        {
            return arm.GetString();
        }

        return null;
    }

    private Task<List<JsonElement>> PrivilegedReportArmFetchAsync(string url, string armToken, CancellationToken cancellationToken)
    {
        if (_privilegedReportArmJsonCache is null)
        {
            return GetArmJsonCollectionAsync(url, armToken, cancellationToken);
        }

        var lazy = _privilegedReportArmJsonCache.GetOrAdd(
            url,
            _ => new Lazy<Task<List<JsonElement>>>(
                () => GetArmJsonCollectionAsync(url, armToken, cancellationToken),
                LazyThreadSafetyMode.ExecutionAndPublication));
        return lazy.Value;
    }

    /// <summary>Graph $batch user GETs so the privileged report avoids one round-trip per user for profile fields.</summary>
    private async Task<Dictionary<string, JsonDocument>> PrefetchPrivilegedUserJsonDocumentsAsync(
        IReadOnlyList<string> userIds,
        string graphAccessToken,
        CancellationToken cancellationToken)
    {
        var map = new Dictionary<string, JsonDocument>(StringComparer.OrdinalIgnoreCase);
        if (userIds.Count == 0)
        {
            return map;
        }

        const string select =
            "id,userPrincipalName,displayName,accountEnabled,onPremisesSyncEnabled,onPremisesImmutableId,onPremisesDistinguishedName,onPremisesSecurityIdentifier,onPremisesSamAccountName,onPremisesUserPrincipalName";
        const int batchSize = 20;

        for (var offset = 0; offset < userIds.Count; offset += batchSize)
        {
            var chunk = userIds.Skip(offset).Take(batchSize).Where(static id => !string.IsNullOrWhiteSpace(id)).ToList();
            if (chunk.Count == 0)
            {
                continue;
            }

            var requests = new List<object>(chunk.Count);
            for (var j = 0; j < chunk.Count; j++)
            {
                var uid = chunk[j];
                requests.Add(new
                {
                    id = j.ToString(),
                    method = "GET",
                    url = $"/users/{uid}?$select={select}"
                });
            }

            var batchPayload = JsonSerializer.Serialize(new { requests });
            using var req = new HttpRequestMessage(HttpMethod.Post, "https://graph.microsoft.com/v1.0/$batch");
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", graphAccessToken);
            req.Content = new StringContent(batchPayload, Encoding.UTF8, "application/json");
            using var resp = await httpClient.SendAsync(req, cancellationToken).ConfigureAwait(false);
            var body = await resp.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode)
            {
                continue;
            }

            using var doc = JsonDocument.Parse(body);
            if (!doc.RootElement.TryGetProperty("responses", out var responses) || responses.ValueKind != JsonValueKind.Array)
            {
                continue;
            }

            foreach (var item in responses.EnumerateArray())
            {
                if (!item.TryGetProperty("status", out var st) || st.GetInt32() < 200 || st.GetInt32() > 299)
                {
                    continue;
                }

                if (!item.TryGetProperty("body", out var b))
                {
                    continue;
                }

                JsonDocument? userDoc = null;
                if (b.ValueKind == JsonValueKind.Object)
                {
                    userDoc = JsonDocument.Parse(b.GetRawText());
                }
                else if (b.ValueKind == JsonValueKind.String)
                {
                    var txt = b.GetString();
                    if (!string.IsNullOrWhiteSpace(txt))
                    {
                        userDoc = JsonDocument.Parse(txt);
                    }
                }

                if (userDoc is null)
                {
                    continue;
                }

                var oid = GetString(userDoc.RootElement, "id");
                if (!string.IsNullOrWhiteSpace(oid))
                {
                    map[oid] = userDoc;
                }
                else
                {
                    userDoc.Dispose();
                }
            }
        }

        return map;
    }

    /// <summary>ARM Authorization / Subscription APIs: paginate with <c>nextLink</c> and omit Graph-only headers.</summary>
    private Task<List<JsonElement>> GetArmJsonCollectionAsync(string url, string accessToken, CancellationToken cancellationToken) =>
        GetJsonCollectionAsync(url, accessToken, cancellationToken, forAzureResourceManager: true);

    private async Task<List<JsonElement>> GetJsonCollectionAsync(
        string url,
        string accessToken,
        CancellationToken cancellationToken,
        bool forAzureResourceManager = false)
    {
        var output = new List<JsonElement>();
        var next = url;
        const int maxArmAttempts = 8;
        while (!string.IsNullOrWhiteSpace(next))
        {
            List<JsonElement>? pageElements = null;
            string? pageNextLink = null;
            var maxAttempts = forAzureResourceManager ? maxArmAttempts : 1;

            for (var attempt = 1; attempt <= maxAttempts; attempt++)
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, next);
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
                // Microsoft Entra directory PIM / RBAC: eventual consistency is required for complete results on
                // /roleManagement/directory/* (list-all and $filter). Graph Explorer uses the same for transitiveRoleAssignments.
                var isGraph = next.Contains("graph.microsoft.com", StringComparison.OrdinalIgnoreCase);
                var isGraphDirectoryRoleMgmt = isGraph && next.Contains("/roleManagement/directory/", StringComparison.OrdinalIgnoreCase);
                var isGraphOtherRoleMgmt = isGraph && next.Contains("/roleManagement/", StringComparison.OrdinalIgnoreCase) && !isGraphDirectoryRoleMgmt;
                if (!forAzureResourceManager)
                {
                    if (isGraphDirectoryRoleMgmt || !isGraphOtherRoleMgmt || (isGraphOtherRoleMgmt && next.Contains("$filter", StringComparison.OrdinalIgnoreCase)))
                    {
                        request.Headers.TryAddWithoutValidation("ConsistencyLevel", "eventual");
                    }
                }

                using var response = await httpClient.SendAsync(request, cancellationToken);
                if (response.IsSuccessStatusCode)
                {
                    using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken));
                    var root = document.RootElement;
                    if (root.TryGetProperty("value", out var value) && value.ValueKind == JsonValueKind.Array)
                    {
                        pageElements = value.EnumerateArray().Select(x => x.Clone()).ToList();
                        pageNextLink = ReadCollectionNextPageLink(root);
                    }
                    else
                    {
                        pageElements = [root.Clone()];
                        pageNextLink = null;
                    }

                    break;
                }

                if (forAzureResourceManager && attempt < maxAttempts)
                {
                    var sc = response.StatusCode;
                    if (sc == HttpStatusCode.TooManyRequests
                        || sc == HttpStatusCode.ServiceUnavailable
                        || sc == HttpStatusCode.BadGateway
                        || sc == HttpStatusCode.GatewayTimeout)
                    {
                        var wait = sc == HttpStatusCode.TooManyRequests
                            ? (ParseRetryAfterSeconds(response) ?? Math.Min(60, 2 * attempt))
                            : Math.Min(30, attempt * 2);
                        await Task.Delay(TimeSpan.FromSeconds(wait), cancellationToken);
                        continue;
                    }
                }

                pageElements = null;
                break;
            }

            if (pageElements is null)
            {
                break;
            }

            output.AddRange(pageElements);
            next = string.IsNullOrWhiteSpace(pageNextLink) ? null : pageNextLink;
        }

        return output;
    }

    private static string GetString(JsonElement element, string propertyName) =>
        element.TryGetProperty(propertyName, out var prop) && prop.ValueKind != JsonValueKind.Null ? prop.ToString() ?? string.Empty : string.Empty;

    private static bool GetBool(JsonElement element, string propertyName) =>
        element.TryGetProperty(propertyName, out var prop) && prop.ValueKind == JsonValueKind.True;
}
