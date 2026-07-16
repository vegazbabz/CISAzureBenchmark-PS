# Control metadata catalog — the single source for control titles, levels, and sections.
#
# Every result factory (New-CISResult and the shorthands) resolves Title/Level/Section
# from here when the caller passes only a control id, so a control's metadata can never
# differ between emission branches (portal title typos in one catch block used to produce
# inconsistent report rows and break SARIF rule dedup). When the benchmark version bumps,
# this file is the one place control metadata changes.
#
# CIS Microsoft Azure Foundations Benchmark v6.0.0 — 127 controls.

$script:CONTROL_SECTIONS = @{
    '2' = '2 - Azure Databricks'
    '3' = '3 - Compute Services'
    '5' = '5 - Identity Services'
    '6' = '6 - Management & Governance'
    '7' = '7 - Networking Services'
    '8' = '8 - Security Services'
    '9' = '9 - Storage Services'
}

$script:CONTROLS = @{
    '2.1.1' = @{ Title = 'Ensure that Azure Databricks is deployed in a customer-managed virtual network (VNet)'; Level = 1 }
    '2.1.2' = @{ Title = 'Ensure that Network Security Groups are Configured for Databricks Subnets'; Level = 1 }
    '2.1.3' = @{ Title = 'Ensure that Traffic is Encrypted Between Cluster Worker Nodes'; Level = 2 }
    '2.1.4' = @{ Title = 'Ensure that Users and Groups are Synced from Microsoft Entra ID to Azure Databricks'; Level = 1 }
    '2.1.5' = @{ Title = 'Ensure that Unity Catalog is Configured for Azure Databricks'; Level = 1 }
    '2.1.6' = @{ Title = 'Ensure that Usage is Restricted and Expiry is Enforced for Databricks Personal Access Tokens'; Level = 1 }
    '2.1.7' = @{ Title = 'Ensure that Diagnostic Log Delivery is Configured for Azure Databricks'; Level = 1 }
    '2.1.8' = @{ Title = 'Ensure Critical Data in Azure Databricks is Encrypted with Customer-managed Keys (CMK)'; Level = 2 }
    '2.1.9' = @{ Title = 'Ensure ''No Public IP'' is Set to ''Enabled'''; Level = 1 }
    '2.1.10' = @{ Title = 'Ensure ''Allow Public Network Access'' is set to ''Disabled'''; Level = 1 }
    '2.1.11' = @{ Title = 'Ensure Private Endpoints are used to access Azure Databricks workspaces'; Level = 2 }
    '2.1.12' = @{ Title = 'Ensure Azure Databricks groups are reviewed periodically'; Level = 1 }
    '3.1.1' = @{ Title = 'Ensure only MFA Enabled Identities can Access Privileged Virtual Machine'; Level = 2 }
    '5.1.1' = @{ Title = 'Ensure that ''security defaults'' is Enabled in Microsoft Entra ID'; Level = 1 }
    '5.1.2' = @{ Title = 'Ensure that ''Require Multifactor Authentication to register or join devices with Microsoft Entra'' is set to ''Yes'''; Level = 1 }
    '5.1.3' = @{ Title = 'Ensure that ''multifactor authentication'' is ''enabled'' For All Users'; Level = 1 }
    '5.1.4' = @{ Title = 'Ensure that ''Allow users to remember multifactor authentication on devices they trust'' is Disabled'; Level = 1 }
    '5.3.1' = @{ Title = 'Ensure that Azure Admin Accounts Are Not Used for Daily Operations'; Level = 1 }
    '5.3.2' = @{ Title = 'Ensure that Guest Users are Reviewed on a Regular Basis'; Level = 1 }
    '5.3.3' = @{ Title = 'Ensure That Use of the ''User Access Administrator'' Role is Restricted'; Level = 1 }
    '5.3.4' = @{ Title = 'Ensure that All ''Privileged'' Role Assignments are Periodically Reviewed'; Level = 1 }
    '5.3.5' = @{ Title = 'Ensure Disabled User Accounts do not Have Read, Write, or Owner Permissions'; Level = 1 }
    '5.3.6' = @{ Title = 'Ensure ''Tenant Creator'' Role Assignments are Periodically Reviewed'; Level = 1 }
    '5.3.7' = @{ Title = 'Ensure All Non-privileged Role Assignments are Periodically Reviewed'; Level = 1 }
    '5.4' = @{ Title = 'Ensure that No Custom Subscription Administrator Roles Exist'; Level = 1 }
    '5.5' = @{ Title = 'Ensure that a Custom Role is Assigned Permissions for Administering Resource Locks'; Level = 2 }
    '5.6' = @{ Title = 'Ensure that ''Subscription leaving Microsoft Entra tenant'' and ''Subscription entering Microsoft Entra tenant'' is set to ''Permit no one'''; Level = 2 }
    '5.7' = @{ Title = 'Ensure there are between 2 and 3 Subscription Owners'; Level = 1 }
    '6.1.1.1' = @{ Title = 'Ensure that a ''Diagnostic Setting'' Exists for Subscription Activity Logs'; Level = 1 }
    '6.1.1.2' = @{ Title = 'Ensure Diagnostic Setting Captures Appropriate Categories'; Level = 1 }
    '6.1.1.3' = @{ Title = 'Ensure the Storage Account Containing the Container with Activity Logs is Encrypted with Customer-managed Key (CMK)'; Level = 2 }
    '6.1.1.4' = @{ Title = 'Ensure that Logging for Azure Key Vault is ''Enabled'''; Level = 1 }
    '6.1.1.5' = @{ Title = 'Ensure that Network Security Group Flow Logs are Captured and Sent to Log Analytics'; Level = 2 }
    '6.1.1.6' = @{ Title = 'Ensure that Virtual Network Flow Logs are Captured and Sent to Log Analytics'; Level = 2 }
    '6.1.1.7' = @{ Title = 'Ensure that a Microsoft Entra Diagnostic Setting Exists to Send Microsoft Graph Activity Logs to an Appropriate Destination'; Level = 2 }
    '6.1.1.8' = @{ Title = 'Ensure that a Microsoft Entra Diagnostic Setting Exists to Send Microsoft Entra Activity Logs to an Appropriate Destination'; Level = 2 }
    '6.1.1.9' = @{ Title = 'Ensure that Intune Logs are Captured and Sent to Log Analytics'; Level = 2 }
    '6.1.2.1' = @{ Title = 'Ensure that Activity Log Alert Exists for Create Policy Assignment'; Level = 1 }
    '6.1.2.2' = @{ Title = 'Ensure that Activity Log Alert exists for Delete Policy Assignment'; Level = 1 }
    '6.1.2.3' = @{ Title = 'Ensure that Activity Log Alert Exists for Create or Update Network Security Group'; Level = 1 }
    '6.1.2.4' = @{ Title = 'Ensure that Activity Log Alert Exists for Delete Network Security Group'; Level = 1 }
    '6.1.2.5' = @{ Title = 'Ensure that Activity Log Alert Exists for Create or Update Security Solution'; Level = 1 }
    '6.1.2.6' = @{ Title = 'Ensure that Activity Log Alert Exists for Delete Security Solution'; Level = 1 }
    '6.1.2.7' = @{ Title = 'Ensure that Activity Log Alert Exists for Create or Update SQL Server Firewall Rule'; Level = 1 }
    '6.1.2.8' = @{ Title = 'Ensure that Activity Log Alert Exists for Delete SQL Server Firewall Rule'; Level = 1 }
    '6.1.2.9' = @{ Title = 'Ensure that Activity Log Alert Exists for Create or Update Public IP Address rule'; Level = 1 }
    '6.1.2.10' = @{ Title = 'Ensure that Activity Log Alert Exists for Delete Public IP Address rule'; Level = 1 }
    '6.1.2.11' = @{ Title = 'Ensure that an Activity Log Alert Exists for Service Health'; Level = 1 }
    '6.1.3.1' = @{ Title = 'Ensure Application Insights are Configured'; Level = 2 }
    '6.1.4' = @{ Title = 'Ensure that Azure Monitor Resource Logging is Enabled for All Services that Support it'; Level = 1 }
    '6.1.5' = @{ Title = 'Ensure Basic, Free, and Consumption SKUs are not used on Production artifacts requiring monitoring and SLA'; Level = 2 }
    '6.2' = @{ Title = 'Ensure that Resource Locks are set for Mission-Critical Azure Resources'; Level = 2 }
    '7.1' = @{ Title = 'Ensure that RDP Access from the Internet is Evaluated and Restricted'; Level = 1 }
    '7.2' = @{ Title = 'Ensure that SSH Access from the Internet is Evaluated and Restricted'; Level = 1 }
    '7.3' = @{ Title = 'Ensure that UDP Port Access from the Internet is Evaluated and Restricted'; Level = 1 }
    '7.4' = @{ Title = 'Ensure that HTTP(S) Access from the Internet is Evaluated and Restricted'; Level = 1 }
    '7.5' = @{ Title = 'Ensure that Network Security Group Flow Log Retention Days is Set to Greater than or equal to 90'; Level = 2 }
    '7.6' = @{ Title = 'Ensure that Network Watcher is ''Enabled'' for Azure Regions That are in Use'; Level = 2 }
    '7.7' = @{ Title = 'Ensure that Public IP Addresses are Evaluated on a Periodic Basis'; Level = 1 }
    '7.8' = @{ Title = 'Ensure that Virtual Network Flow Log Retention Days is Set to Greater than or Equal to 90'; Level = 2 }
    '7.9' = @{ Title = 'Ensure ''Authentication type'' is Set to ''Azure Active Directory'' only for Azure VPN Gateway Point-to-Site Configuration'; Level = 2 }
    '7.10' = @{ Title = 'Ensure Azure Web Application Firewall (WAF) is Enabled on Azure Application Gateway'; Level = 2 }
    '7.11' = @{ Title = 'Ensure Subnets Are Associated with Network Security Groups'; Level = 1 }
    '7.12' = @{ Title = 'Ensure the SSL Policy''s ''Min protocol version'' is Set to ''TLSv1_2'' or Higher on Azure Application Gateway'; Level = 1 }
    '7.13' = @{ Title = 'Ensure ''HTTP2'' is Set to ''Enabled'' on Azure Application Gateway'; Level = 1 }
    '7.14' = @{ Title = 'Ensure Request Body Inspection is Enabled in Azure Web Application Firewall policy on Azure Application Gateway'; Level = 2 }
    '7.15' = @{ Title = 'Ensure Bot Protection is Enabled in Azure Web Application Firewall Policy on Azure Application Gateway'; Level = 2 }
    '7.16' = @{ Title = 'Ensure Azure Network Security Perimeter is Used to Secure Azure Platform-as-a-service Resources'; Level = 2 }
    '8.1.1.1' = @{ Title = 'Ensure Microsoft Defender CSPM is Set to ''On'''; Level = 2 }
    '8.1.2.1' = @{ Title = 'Ensure Microsoft Defender for APIs is Set to ''On'''; Level = 2 }
    '8.1.3.1' = @{ Title = 'Ensure that Defender for Servers is Set to ''On'''; Level = 2 }
    '8.1.3.2' = @{ Title = 'Ensure that ''Vulnerability assessment for machines'' Component Status is set to ''On'''; Level = 2 }
    '8.1.3.3' = @{ Title = 'Ensure that ''Endpoint protection'' Component Status is set to ''On'''; Level = 2 }
    '8.1.3.4' = @{ Title = 'Ensure that ''Agentless scanning for machines'' Component Status is Set to ''On'''; Level = 2 }
    '8.1.3.5' = @{ Title = 'Ensure that ''File Integrity Monitoring'' Component Status is Set to ''On'''; Level = 2 }
    '8.1.4.1' = @{ Title = 'Ensure That Microsoft Defender for Containers Is Set To ''On'''; Level = 2 }
    '8.1.5.1' = @{ Title = 'Ensure That Microsoft Defender for Storage Is Set To ''On'''; Level = 2 }
    '8.1.5.2' = @{ Title = 'Ensure Advanced Threat Protection Alerts for Storage Accounts Are Monitored'; Level = 2 }
    '8.1.6.1' = @{ Title = 'Ensure That Microsoft Defender for App Services Is Set To ''On'''; Level = 2 }
    '8.1.7.1' = @{ Title = 'Ensure That Microsoft Defender for Azure Cosmos DB Is Set To ''On'''; Level = 2 }
    '8.1.7.2' = @{ Title = 'Ensure That Microsoft Defender for Open-Source Relational Databases Is Set To ''On'''; Level = 2 }
    '8.1.7.3' = @{ Title = 'Ensure That Microsoft Defender for (Managed Instance) Azure SQL Databases Is Set To ''On'''; Level = 2 }
    '8.1.7.4' = @{ Title = 'Ensure That Microsoft Defender for SQL Servers on Machines Is Set To ''On'''; Level = 2 }
    '8.1.8.1' = @{ Title = 'Ensure That Microsoft Defender for Key Vault Is Set To ''On'''; Level = 2 }
    '8.1.9.1' = @{ Title = 'Ensure That Microsoft Defender for Resource Manager Is Set To ''On'''; Level = 2 }
    '8.1.10' = @{ Title = 'Ensure that Microsoft Defender for Cloud is Configured to Check VM Operating Systems for Updates'; Level = 1 }
    '8.1.11' = @{ Title = 'Ensure that non-deprecated Microsoft Cloud Security Benchmark policies are not set to ''Disabled'''; Level = 1 }
    '8.1.12' = @{ Title = 'Ensure That ''All users with the following roles'' is Set to ''Owner'''; Level = 1 }
    '8.1.13' = @{ Title = 'Ensure ''Additional email addresses'' is Configured with a Security Contact Email'; Level = 1 }
    '8.1.14' = @{ Title = 'Ensure that ''Notify about alerts with the following severity (or higher)'' is Enabled'; Level = 1 }
    '8.1.15' = @{ Title = 'Ensure that ''Notify about attack paths with the following risk level (or higher)'' is Enabled'; Level = 1 }
    '8.1.16' = @{ Title = 'Ensure that Microsoft Defender External Attack Surface Monitoring (EASM) is Enabled'; Level = 2 }
    '8.2.1' = @{ Title = 'Ensure That Microsoft Defender for IoT Hub Is Set To ''On'''; Level = 2 }
    '8.3.1' = @{ Title = 'Ensure that the Expiration Date is Set for all Keys in Key Vaults using RBAC'; Level = 1 }
    '8.3.2' = @{ Title = 'Ensure that the Expiration Date is set for All Keys in Key Vaults using access policies (legacy)'; Level = 1 }
    '8.3.3' = @{ Title = 'Ensure that the Expiration Date is set for All Secrets in Key Vaults using RBAC'; Level = 1 }
    '8.3.4' = @{ Title = 'Ensure that the Expiration Date is set for All Secrets in Key Vaults using access policies (legacy)'; Level = 1 }
    '8.3.5' = @{ Title = 'Ensure ''Purge protection'' is Set to ''Enabled'''; Level = 1 }
    '8.3.6' = @{ Title = 'Ensure that Role Based Access Control for Azure Key Vault is Enabled'; Level = 2 }
    '8.3.7' = @{ Title = 'Ensure Public Network Access is Disabled'; Level = 1 }
    '8.3.8' = @{ Title = 'Ensure Private Endpoints are Used to Access Azure Key Vault'; Level = 2 }
    '8.3.9' = @{ Title = 'Ensure Automatic Key Rotation is Enabled within Azure Key Vault'; Level = 2 }
    '8.3.10' = @{ Title = 'Ensure that Azure Key Vault Managed HSM is Used when Required'; Level = 2 }
    '8.3.11' = @{ Title = 'Ensure Certificate ''Validity Period (in months)'' is Less Than or Equal to ''12'''; Level = 1 }
    '8.4.1' = @{ Title = 'Ensure an Azure Bastion Host Exists'; Level = 2 }
    '8.5' = @{ Title = 'Ensure Azure DDoS Network Protection is Enabled on Virtual Networks'; Level = 2 }
    '9.1.1' = @{ Title = 'Ensure Soft Delete for Azure File Shares is Enabled'; Level = 1 }
    '9.1.2' = @{ Title = 'Ensure ''SMB protocol version'' is Set to ''SMB 3.1.1'' or Higher for SMB file shares'; Level = 1 }
    '9.1.3' = @{ Title = 'Ensure ''SMB channel encryption'' is Set to ''AES-256-GCM'' or Higher for SMB file shares'; Level = 1 }
    '9.2.1' = @{ Title = 'Ensure That Soft Delete for Blobs on Azure Blob Storage Storage Accounts is Enabled'; Level = 1 }
    '9.2.2' = @{ Title = 'Ensure that Soft Delete for Containers on Azure Blob Storage Storage Accounts is Enabled'; Level = 1 }
    '9.2.3' = @{ Title = 'Ensure ''Versioning'' is Set to ''Enabled'' on Azure Blob Storage Storage Accounts'; Level = 2 }
    '9.3.1.1' = @{ Title = 'Ensure That ''Enable key rotation reminders'' is Enabled for Each Storage Account'; Level = 1 }
    '9.3.1.2' = @{ Title = 'Ensure That Storage Account Access keys are Periodically Regenerated'; Level = 1 }
    '9.3.1.3' = @{ Title = 'Ensure ''Allow storage account key access'' for Azure Storage Accounts is ''Disabled'''; Level = 1 }
    '9.3.2.1' = @{ Title = 'Ensure Private Endpoints are Used to Access Storage Accounts'; Level = 2 }
    '9.3.2.2' = @{ Title = 'Ensure that ''Public Network Access'' is ''Disabled'' for Storage Accounts'; Level = 1 }
    '9.3.2.3' = @{ Title = 'Ensure Default Network Access Rule for Storage Accounts is Set to Deny'; Level = 1 }
    '9.3.3.1' = @{ Title = 'Ensure that ''Default to Microsoft Entra authorization in the Azure portal'' is Set to ''Enabled'''; Level = 1 }
    '9.3.4' = @{ Title = 'Ensure that ''Secure transfer required'' is Set to ''Enabled'''; Level = 1 }
    '9.3.5' = @{ Title = 'Ensure ''Allow trusted Microsoft services to access this resource'' is Enabled for Storage Account Access'; Level = 2 }
    '9.3.6' = @{ Title = 'Ensure the ''Minimum TLS version'' for Storage Accounts is Set to ''Version 1.2'''; Level = 1 }
    '9.3.7' = @{ Title = 'Ensure ''Cross Tenant Replication'' is Not Enabled'; Level = 1 }
    '9.3.8' = @{ Title = 'Ensure that ''Allow Blob Anonymous Access'' is Set to ''Disabled'''; Level = 1 }
    '9.3.9' = @{ Title = 'Ensure Azure Resource Manager Delete Locks are Applied to Azure Storage Accounts'; Level = 1 }
    '9.3.10' = @{ Title = 'Ensure Azure Resource Manager ReadOnly Locks are Considered for Azure Storage Accounts'; Level = 2 }
    '9.3.11' = @{ Title = 'Ensure Redundancy is Set to ''geo-redundant storage (GRS)'' on Critical Azure Storage Accounts'; Level = 2 }
}

function Get-ControlMeta {
    <#
    .SYNOPSIS
    Resolve a control id to its Title/Level/Section from the catalog.
    Throws on an unknown id — an id absent from the catalog is a bug in the check
    (or a missing catalog entry), and failing loudly beats emitting a blank row.
    #>
    param([Parameter(Mandatory)][string]$ControlId)

    $meta = $script:CONTROLS[$ControlId]
    if (-not $meta) {
        throw "Unknown control id '$ControlId' — not in the catalog (Private\Controls.ps1)."
    }
    $section = $script:CONTROL_SECTIONS[($ControlId -split '\.')[0]]
    [PSCustomObject]@{
        ControlId = $ControlId
        Title     = [string]$meta.Title
        Level     = [int]$meta.Level
        Section   = [string]$section
    }
}
