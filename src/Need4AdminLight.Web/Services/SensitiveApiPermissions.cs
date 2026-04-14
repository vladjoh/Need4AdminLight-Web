namespace Need4AdminLight.Web.Services;

/// <summary>Delegated and application permission names to highlight in the Applications report (and treat as high-risk for sorting).</summary>
public static class SensitiveApiPermissions
{
    private static readonly HashSet<string> HighlightSet = BuildSet();

    public static bool IsHighlightMatch(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return false;
        }

        var t = raw.Trim();
        const string graphSuffix = " (Microsoft Graph)";
        if (t.EndsWith(graphSuffix, StringComparison.OrdinalIgnoreCase))
        {
            t = t[..^graphSuffix.Length].TrimEnd();
        }

        return HighlightSet.Contains(t);
    }

    private static HashSet<string> BuildSet()
    {
        var names = new[]
        {
            // Directory / hybrid / sync
            "Directory.ReadWrite.All",
            "Directory.Read.All",
            "Directory.AccessAsUser.All",
            "Directory.Write.Restricted",
            "ADSynchronization.ReadWrite.All",
            "OnPremDirectorySynchronization.Read.All",
            "OnPremDirectorySynchronization.ReadWrite.All",
            "Synchronization.ReadWrite.All",
            "Synchronization.Read.All",
            "PasswordWriteback.OffboardClient.All",
            "PasswordWriteback.RefreshClient.All",
            "PasswordWriteback.RegisterClientVersion.All",

            // Role / PIM / assignment schedules (incl. IoE RoleManagementPolicy.*, PrivilegedAssignmentSchedule.*)
            "RoleManagement.ReadWrite.Directory",
            "RoleManagement.Read.Directory",
            "RoleManagement.ReadWrite.All",
            "RoleManagement.Read.All",
            "RoleManagementPolicy.ReadWrite.AzureADGroup",
            "RoleManagementPolicy.ReadWrite.Directory",
            "PrivilegedAccess.ReadWrite.AzureAD",
            "PrivilegedAccess.ReadWrite.AzureResources",
            "PrivilegedAccess.ReadWrite.AzureADGroup",
            "PrivilegedAccess.Read.AzureAD",
            "PrivilegedAccess.Read.AzureResources",
            "PrivilegedAccess.Read.AzureADGroup",
            "PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup",
            "PrivilegedEligibilitySchedule.Read.AzureADGroup",
            "PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup",
            "PrivilegedAssignmentSchedule.Read.AzureADGroup",
            "RoleAssignmentSchedule.ReadWrite.Directory",
            "RoleAssignmentSchedule.Read.Directory",
            "RoleEligibilitySchedule.ReadWrite.Directory",
            "RoleEligibilitySchedule.Read.Directory",

            // Applications / service principals / consent
            "Application.ReadWrite.All",
            "Application.ReadWrite.OwnedBy",
            "Application.Read.All",
            "AppRoleAssignment.ReadWrite.All",
            "AppRoleAssignment.Read.All",
            "DelegatedPermissionGrant.ReadWrite.All",
            "DelegatedPermissionGrant.Read.All",
            "ServicePrincipalEndpoint.ReadWrite.All",
            "ServicePrincipalEndpoint.Read.All",
            "ServicePrincipalEndpointReadWrite.All",

            // Users / groups / AU / domain
            "User.ReadWrite.All",
            "User.Read.All",
            "User.Invite.All",
            "User.Export.All",
            "User.ManageIdentities.All",
            "User.DeleteRestore.All",
            "User.EnableDisableAccount.All",
            "User-PasswordProfile.ReadWrite.All",
            "UserAuthenticationMethod.ReadWrite.All",
            "UserAuthenticationMethod.Read.All",
            "Authentication.ReadWrite.All",
            "Group.ReadWrite.All",
            "Group.Read.All",
            "GroupMember.ReadWrite.All",
            "GroupMember.Read.All",
            "AdministrativeUnit.ReadWrite.All",
            "AdministrativeUnit.Read.All",
            "Domain.ReadWrite.All",
            "Domain.Read.All",
            "Member.Read.Hidden",

            // Conditional access / auth policies / permission grants
            "Policy.ReadWrite.ConditionalAccess",
            "Policy.Read.ConditionalAccess",
            "Policy.ReadWrite.AuthenticationMethod",
            "Policy.Read.AuthenticationMethod",
            "Policy.ReadWrite.Authorization",
            "Policy.ReadWrite.PermissionGrant",
            "Policy.Read.PermissionGrant",
            "Policy.ReadWrite.ApplicationConfiguration",
            "Policy.ReadWrite.CrossTenantAccess",
            "Policy.ReadWrite.TrustFramework",
            "Policy.ReadWrite.FeatureRollout",
            "Policy.ReadWrite.ExternalIdentities",
            "Policy.ReadWrite.SecurityDefaults",
            "Policy.ReadWrite.AuthenticationFlows",
            "Policy.Read.All",

            // Mail / files / SharePoint
            "Mail.ReadWrite",
            "Mail.Read",
            "Mail.Send",
            "Mail.ReadBasic.All",
            "Mail.ReadWrite.Shared",
            "MailboxSettings.ReadWrite",
            "MailboxSettings.Read",
            "Files.ReadWrite.All",
            "Files.Read.All",
            "Sites.ReadWrite.All",
            "Sites.Read.All",
            "Sites.FullControl.All",
            "Sites.Manage.All",

            // Teams / calls / meetings
            "Chat.Read.All",
            "Chat.ReadWrite.All",
            "Chat.ReadBasic.All",
            "ChannelMessage.Read.All",
            "Channel.ReadBasic.All",
            "TeamSettings.ReadWrite.All",
            "TeamSettings.Read.All",
            "TeamsAppInstallation.ReadWriteForChat.All",
            "TeamsAppInstallation.ReadWriteForTeam.All",
            "TeamsAppInstallation.ReadWriteSelfForChat.All",
            "TeamsAppInstallation.Read.All",
            "CallRecords.Read.All",
            "Calls.AccessMedia.All",
            "Calls.Read.All",
            "OnlineMeetings.Read.All",
            "OnlineMeetings.ReadWrite.All",
            "TeamMember.Read.All",
            "TeamMember.ReadWrite.All",
            "ChannelMember.Read.All",
            "ChannelMember.ReadWrite.All",

            // Intune / devices / Cloud PC
            "DeviceManagementManagedDevices.ReadWrite.All",
            "DeviceManagementManagedDevices.Read.All",
            "DeviceManagementConfiguration.ReadWrite.All",
            "DeviceManagementConfiguration.Read.All",
            "DeviceManagementApps.ReadWrite.All",
            "DeviceManagementApps.Read.All",
            "DeviceManagementRBAC.ReadWrite.All",
            "DeviceManagementRBAC.Read.All",
            "DeviceManagementServiceConfig.ReadWrite.All",
            "DeviceManagementServiceConfig.Read.All",
            "DeviceManagementScripts.ReadWrite.All",
            "DeviceManagementScripts.Read.All",
            "Device.ReadWrite.All",
            "Device.Read.All",
            "CloudPC.ReadWrite.All",
            "CloudPC.Read.All",
            "WindowsUpdates.ReadWrite.All",
            "WindowsUpdates.Read.All",

            // Security / identity protection / threat
            "SecurityEvents.ReadWrite.All",
            "SecurityEvents.Read.All",
            "SecurityAlert.ReadWrite.All",
            "SecurityAlert.Read.All",
            "SecurityActions.ReadWrite.All",
            "SecurityActions.Read.All",
            "IdentityRiskyUser.ReadWrite.All",
            "IdentityRiskyUser.Read.All",
            "IdentityRiskEvent.Read.All",
            "IdentityRiskyServicePrincipal.ReadWrite.All",
            "IdentityRiskyServicePrincipal.Read.All",
            "IdentityUserFlow.ReadWrite.All",
            "IdentityUserFlow.Read.All",
            "ThreatIndicators.ReadWrite.OwnedBy",
            "ThreatIndicators.Read.All",
            "ThreatHunting.Read.All",
            "ThreatAssessment.Read.All",
            "ThreatAssessment.ReadWrite.All",
            "InformationProtectionPolicy.Read.All",
            "AuditLog.Read.All",
            "SignIn.Read.All",
            "IdentityProvider.ReadWrite.All",
            "IdentityProvider.Read.All",

            // Exchange / eDiscovery / calendars
            "eDiscovery.ReadWrite.All",
            "eDiscovery.Read.All",
            "ExchangeManageAsApp",
            "full_access_as_app",
            "Calendars.ReadWrite",
            "Calendars.Read",
            "Contacts.ReadWrite",
            "Contacts.Read",

            // Entitlement / access reviews / lifecycle / cross-tenant
            "AccessReview.ReadWrite.All",
            "AccessReview.Read.All",
            "EntitlementManagement.ReadWrite.All",
            "EntitlementManagement.Read.All",
            "LifecycleWorkflows.ReadWrite.All",
            "LifecycleWorkflows.Read.All",
            "CrossTenantInformation.ReadBasic.All",
            "CrossTenantUserProfileSharing.ReadWrite.All",
            "CrossTenantUserProfileSharing.Read.All",

            // Organization / reports / network access (Entra)
            "Organization.Read.All",
            "Organization.ReadWrite.All",
            "OrgContact.Read.All",
            "Reports.Read.All",
            "ServiceHealth.Read.All",
            "ServiceMessage.Read.All",
            "NetworkAccess.Read.All",
            "NetworkAccess.ReadWrite.All",
            "NetworkAccessPolicy.Read.All",
            "NetworkAccessPolicy.ReadWrite.All",

            // Security attributes / shifts / records / search / tasks / notes
            "CustomSecAttributeAssignment.Read.All",
            "CustomSecAttributeAssignment.ReadWrite.All",
            "CustomSecAttributeDefinition.Read.All",
            "CustomSecAttributeDefinition.ReadWrite.All",
            "UserShiftPreferences.Read.All",
            "UserShiftPreferences.ReadWrite.All",
            "Schedule.Read.All",
            "Schedule.ReadWrite.All",
            "RecordsManagement.Read.All",
            "RecordsManagement.ReadWrite.All",
            "TermStore.Read.All",
            "TermStore.ReadWrite.All",
            "ExternalConnection.Read.All",
            "ExternalConnection.ReadWrite.All",
            "ExternalItem.Read.All",
            "ExternalItem.ReadWrite.All",
            "Tasks.Read.All",
            "Tasks.ReadWrite.All",
            "Notes.Read.All",
            "Notes.ReadWrite.All",
            "Presence.Read.All",
            "People.Read.All",
        };

        return new HashSet<string>(names, StringComparer.OrdinalIgnoreCase);
    }
}
