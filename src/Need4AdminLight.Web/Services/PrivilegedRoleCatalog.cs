using System.Collections.Generic;

namespace Need4AdminLight.Web.Services;

/// <summary>
/// Display names for Azure RBAC and Entra directory roles that this product treats as in-scope for privileged reporting.
/// ARM rows keep <c>Unknown</c> role names when definition lookup fails so assignments do not flicker out under throttling.
/// </summary>
internal static class PrivilegedRoleCatalog
{
    private static readonly HashSet<string> AzureRoleDisplayNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "Contributor", "Owner", "Reservations Administrator", "Role Based Access Control Administrator", "User Access Administrator", "Reader",
        "Azure Arc VMware VM Contributor", "Azure Batch Account Contributor", "Azure Batch Account Reader", "Azure Batch Data Contributor", "Azure Batch Job Submitter", "Classic Virtual Machine Contributor", "Compute Fleet Contributor", "Compute Gallery Artifacts Publisher", "Compute Gallery Image Reader", "Compute Gallery Sharing Admin", "Compute Limit Operator", "Data Operator for Managed Disks", "Desktop Virtualization Application Group Contributor", "Desktop Virtualization Application Group Reader", "Desktop Virtualization Contributor", "Desktop Virtualization Host Pool Contributor", "Desktop Virtualization Host Pool Reader", "Desktop Virtualization Power On Contributor", "Desktop Virtualization Power On Off Contributor", "Desktop Virtualization Reader", "Desktop Virtualization Session Host Operator", "Desktop Virtualization User", "Desktop Virtualization User Session Operator", "Desktop Virtualization Virtual Machine Contributor", "Desktop Virtualization Workspace Contributor", "Desktop Virtualization Workspace Reader", "Disk Backup Reader", "Disk Pool Operator", "Disk Restore Operator", "Disk Snapshot Contributor", "Quantum Workspace Data Contributor", "Virtual Machine Administrator Login", "Virtual Machine Contributor", "Virtual Machine Data Access Administrator", "Virtual Machine Local User Login", "Virtual Machine User Login", "VM Restore Operator", "Windows 365 Network Interface Contributor", "Windows 365 Network User", "Windows Admin Center Administrator Login",
        "Azure Front Door Domain Contributor", "Azure Front Door Domain Reader", "Azure Front Door Profile Reader", "Azure Front Door Secret Contributor", "Azure Front Door Secret Reader", "CDN Endpoint Contributor", "CDN Endpoint Reader", "CDN Profile Contributor", "CDN Profile Reader", "Classic Network Contributor", "DNS Zone Contributor", "Network Contributor", "Private DNS Zone Contributor", "Traffic Manager Contributor",
        "Avere Contributor", "Avere Operator", "Azure File Sync Administrator", "Azure File Sync Reader", "Backup Contributor", "Backup MUA Admin", "Backup MUA Operator", "Backup Operator", "Backup Reader", "Classic Storage Account Contributor", "Classic Storage Account Key Operator Service Role", "Data Box Contributor", "Data Box Reader", "Data Lake Analytics Developer", "Defender for Storage Data Scanner", "Elastic SAN Network Admin", "Elastic SAN Owner", "Elastic SAN Reader", "Elastic SAN Volume Group Owner", "Reader and Data Access", "Storage Account Backup Contributor", "Storage Account Contributor", "Storage Account Key Operator Service Role", "Storage Actions Blob Data Operator", "Storage Actions Contributor", "Storage Actions Task Assignment Contributor", "Storage Blob Data Contributor", "Storage Blob Data Owner", "Storage Blob Data Reader", "Storage Blob Delegator", "Storage Connector Contributor", "Storage DataShare Contributor", "Storage File Data Privileged Contributor", "Storage File Data Privileged Reader", "Storage File Data SMB Admin", "Storage File Data SMB MI Admin", "Storage File Data SMB Share Contributor", "Storage File Data SMB Share Elevated Contributor", "Storage File Data SMB Share Reader", "Storage File Data SMB Take Ownership", "Storage File Delegator", "Storage Queue Data Contributor", "Storage Queue Data Message Processor", "Storage Queue Data Message Sender", "Storage Queue Data Reader", "Storage Queue Delegator", "Storage Table Data Contributor", "Storage Table Data Reader", "Storage Table Delegator",
        "Azure Maps Data Contributor", "Azure Maps Data Reader", "Azure Maps Search and Render Data Reader", "Azure Spring Apps Application Configuration Service Config File Pattern Reader Role", "Azure Spring Apps Application Configuration Service Log Reader Role", "Azure Spring Apps Connect Role", "Azure Spring Apps Job Log Reader Role", "Azure Spring Apps Remote Debugging Role", "Azure Spring Apps Spring Cloud Gateway Log Reader Role", "Azure Spring Cloud Config Server Contributor", "Azure Spring Cloud Config Server Reader", "Azure Spring Cloud Data Reader", "Azure Spring Cloud Service Registry Contributor", "Azure Spring Cloud Service Registry Reader", "SignalR AccessKey Reader", "SignalR App Server", "SignalR REST API Owner", "SignalR REST API Reader", "SignalR Service Owner", "SignalR/Web PubSub Contributor", "Web Plan Contributor", "Web PubSub Service Owner", "Web PubSub Service Reader", "Website Contributor",
        "AcrDelete", "AcrImageSigner", "AcrPull", "AcrPush", "AcrQuarantineReader", "AcrQuarantineWriter", "Azure Arc Enabled Kubernetes Cluster User Role", "Azure Arc Kubernetes Admin", "Azure Arc Kubernetes Cluster Admin", "Azure Arc Kubernetes Viewer", "Azure Arc Kubernetes Writer", "Azure Container Instances Contributor Role", "Azure Container Storage Contributor", "Azure Container Storage Operator", "Azure Container Storage Owner", "Azure Kubernetes Fleet Manager Contributor Role", "Azure Kubernetes Fleet Manager Hub Agent Role", "Azure Kubernetes Fleet Manager Hub Cluster User Role", "Azure Kubernetes Fleet Manager RBAC Admin", "Azure Kubernetes Fleet Manager RBAC Admin for Member Clusters", "Azure Kubernetes Fleet Manager RBAC Cluster Admin", "Azure Kubernetes Fleet Manager RBAC Cluster Admin for Member Clusters", "Azure Kubernetes Fleet Manager RBAC Reader", "Azure Kubernetes Fleet Manager RBAC Reader for Member Clusters", "Azure Kubernetes Fleet Manager RBAC Writer", "Azure Kubernetes Fleet Manager RBAC Writer for Member Clusters", "Azure Kubernetes Service Arc Cluster Admin Role", "Azure Kubernetes Service Arc Cluster User Role", "Azure Kubernetes Service Arc Contributor Role", "Azure Kubernetes Service Cluster Admin Role", "Azure Kubernetes Service Cluster Monitoring User", "Azure Kubernetes Service Cluster User Role", "Azure Kubernetes Service Contributor Role", "Azure Kubernetes Service Namespace Contributor", "Azure Kubernetes Service Namespace User", "Azure Kubernetes Service RBAC Admin", "Azure Kubernetes Service RBAC Cluster Admin", "Azure Kubernetes Service RBAC Reader", "Azure Kubernetes Service RBAC Writer", "Azure Red Hat OpenShift Cloud Controller Manager", "Azure Red Hat OpenShift Cluster Ingress Operator", "Azure Red Hat OpenShift Disk Storage Operator", "Azure Red Hat OpenShift Federated Credential", "Azure Red Hat OpenShift File Storage Operator", "Azure Red Hat OpenShift Image Registry Operator", "Azure Red Hat OpenShift Machine API Operator", "Azure Red Hat OpenShift Network Operator", "Azure Red Hat OpenShift Service Operator",
        "Azure Connected SQL Server Onboarding", "Cosmos DB Account Reader Role", "Cosmos DB Operator", "CosmosBackupOperator", "CosmosRestoreOperator", "DocumentDB Account Contributor", "PostgreSQL Flexible Server Long Term Retention Backup Role", "Redis Cache Contributor", "SQL DB Contributor", "SQL Managed Instance Contributor", "SQL Security Manager", "SQL Server Contributor",
        "Azure Event Hubs Data Owner", "Azure Event Hubs Data Receiver", "Azure Event Hubs Data Sender", "Data Factory Contributor", "HDInsight Cluster Operator", "HDInsight Domain Services Contributor", "HDInsight on AKS Cluster Admin", "HDInsight on AKS Cluster Pool Admin", "Schema Registry Contributor", "Schema Registry Reader", "Stream Analytics Query Tester",
        "Azure AI Account Owner", "Azure AI Administrator", "Azure AI Developer", "Azure AI Enterprise Network Connection Approver", "Azure AI Inference Deployment Operator", "Azure AI Owner", "Azure AI Project Manager", "Azure AI User", "AzureML Compute Operator", "AzureML Data Scientist", "AzureML Metrics Writer", "AzureML Registry User", "Cognitive Services Contributor", "Cognitive Services Custom Vision Contributor", "Cognitive Services Custom Vision Deployment", "Cognitive Services Custom Vision Labeler", "Cognitive Services Custom Vision Reader", "Cognitive Services Custom Vision Trainer", "Cognitive Services Data Reader", "Cognitive Services Face Recognizer", "Cognitive Services Immersive Reader User", "Cognitive Services Language Owner", "Cognitive Services Language Reader", "Cognitive Services Language Writer", "Cognitive Services LUIS Owner", "Cognitive Services LUIS Reader", "Cognitive Services LUIS Writer", "Cognitive Services Metrics Advisor Administrator", "Cognitive Services Metrics Advisor User", "Cognitive Services OpenAI Contributor", "Cognitive Services OpenAI User", "Cognitive Services QnA Maker Editor", "Cognitive Services QnA Maker Reader", "Cognitive Services Speech Contributor", "Cognitive Services Speech User", "Cognitive Services Usages Reader", "Cognitive Services User",
    };

    private static readonly HashSet<string> EntraDirectoryRoleDisplayNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "Agent ID Administrator", "Agent ID Developer", "Agent Registry Administrator", "AI Administrator", "Application Administrator", "Application Developer", "Attack Payload Author", "Attack Simulation Administrator", "Attribute Assignment Administrator", "Attribute Assignment Reader", "Attribute Definition Administrator", "Attribute Definition Reader", "Attribute Log Administrator", "Attribute Log Reader", "Attribute Provisioning Administrator", "Attribute Provisioning Reader", "Authentication Administrator", "Authentication Extensibility Administrator", "Authentication Extensibility Password Administrator", "Authentication Policy Administrator", "Azure DevOps Administrator", "Azure Information Protection Administrator", "B2C IEF Keyset Administrator", "B2C IEF Policy Administrator", "Billing Administrator", "Cloud App Security Administrator", "Cloud Application Administrator", "Cloud Device Administrator", "Compliance Administrator", "Compliance Data Administrator", "Conditional Access Administrator", "Customer Lockbox Access Approver", "Desktop Analytics Administrator", "Directory Readers", "Directory Synchronization Accounts", "Directory Writers", "Domain Name Administrator", "Dragon Administrator", "Dynamics 365 Administrator", "Dynamics 365 Business Central Administrator", "Edge Administrator", "Entra Backup Administrator", "Entra Backup Reader", "Exchange Administrator", "Exchange Backup Administrator", "Exchange Recipient Administrator", "Extended Directory User Administrator", "External ID User Flow Administrator", "External ID User Flow Attribute Administrator", "External Identity Provider Administrator", "Fabric Administrator", "Global Administrator", "Global Reader", "Global Secure Access Administrator", "Global Secure Access Log Reader", "Groups Administrator", "Guest Inviter", "Helpdesk Administrator", "Hybrid Identity Administrator", "Identity Governance Administrator", "Insights Administrator", "Insights Analyst", "Insights Business Leader", "Intune Administrator", "IoT Device Administrator", "Kaizala Administrator", "Knowledge Administrator", "Knowledge Manager", "License Administrator", "Lifecycle Workflows Administrator", "Message Center Privacy Reader", "Message Center Reader", "Microsoft 365 Backup Administrator", "Microsoft 365 Migration Administrator", "Microsoft Entra Joined Device Local Administrator", "Microsoft Graph Data Connect Administrator", "Microsoft Hardware Warranty Administrator", "Microsoft Hardware Warranty Specialist", "Network Administrator", "Office Apps Administrator", "Organizational Branding Administrator", "Organizational Data Source Administrator", "Organizational Messages Approver", "Organizational Messages Writer", "Partner Tier1 Support", "Partner Tier2 Support", "Password Administrator", "People Administrator", "Permissions Management Administrator", "Places Administrator", "Power Platform Administrator", "Printer Administrator", "Printer Technician", "Privileged Authentication Administrator", "Privileged Role Administrator", "Reports Reader", "Search Administrator", "Search Editor", "Security Administrator", "Security Operator", "Security Reader", "Service Support Administrator", "SharePoint Administrator", "SharePoint Advanced Management Administrator", "SharePoint Backup Administrator", "SharePoint Embedded Administrator", "Skype for Business Administrator", "Teams Administrator", "Teams Communications Administrator", "Teams Communications Support Engineer", "Teams Communications Support Specialist", "Teams Devices Administrator", "Teams External Collaboration Administrator", "Teams Reader", "Teams Telephony Administrator", "Tenant Creator", "Tenant Governance Administrator", "Tenant Governance Reader", "Tenant Governance Relationship Administrator", "Tenant Governance Relationship Reader", "Usage Summary Reports Reader", "User Administrator", "User Experience Success Manager", "Virtual Visits Administrator", "Viva Glint Tenant Administrator", "Viva Goals Administrator", "Viva Pulse Administrator", "Windows 365 Administrator", "Windows Update Deployment Administrator", "Yammer Administrator",
    };

    /// <summary>Strip <c> (via group: …)</c> suffix so PIM / nested group lines match catalog entries.</summary>
    public static string StripEntraRoleViaGroupSuffix(string line)
    {
        if (string.IsNullOrWhiteSpace(line))
        {
            return line;
        }

        const string marker = " (via group:";
        var idx = line.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
        return idx < 0 ? line.Trim() : line[..idx].TrimEnd();
    }

    /// <summary>
    /// Azure assignments: in-list roles, plus <c>Unknown</c> when ARM cannot resolve the definition name (keeps rows stable).
    /// </summary>
    public static bool IsAzurePrivilegedRoleForReport(string? roleName)
    {
        if (string.IsNullOrWhiteSpace(roleName))
        {
            return false;
        }

        var t = roleName.Trim();
        if (t.Equals("Unknown", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return AzureRoleDisplayNames.Contains(t);
    }

    /// <summary>
    /// Entra directory / PIM lines: explicit catalog match after via-group normalization, plus unresolved Graph placeholders.
    /// </summary>
    public static bool IsEntraRoleInPrivilegedScope(string? roleDisplayLine)
    {
        if (string.IsNullOrWhiteSpace(roleDisplayLine))
        {
            return false;
        }

        var t = roleDisplayLine.Trim();
        if (t.Equals("Unknown", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (t.Contains("unresolved", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (t.StartsWith("Directory role (", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var core = StripEntraRoleViaGroupSuffix(t);
        return EntraDirectoryRoleDisplayNames.Contains(core);
    }
}
