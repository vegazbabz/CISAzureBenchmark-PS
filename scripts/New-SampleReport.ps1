<#
.SYNOPSIS
    Generates a sample CIS Azure Benchmark audit report with synthetic data.
.DESCRIPTION
    Creates a realistic-looking HTML report using New-CISHtmlReport with
    fabricated subscription names, resource names, and randomised statuses.
    No Azure connection is required.  The output is saved to docs/sample_report.html.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Load project functions ────────────────────────────────────────────────────
$root = Split-Path $PSScriptRoot -Parent
foreach ($f in Get-ChildItem "$root/Private/*.ps1") { . $f }

# ── Synthetic identifiers ────────────────────────────────────────────────────
$tenantId = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
$subs = @(
    @{ Id = "11111111-aaaa-bbbb-cccc-111111111111"; Name = "Production" }
    @{ Id = "22222222-dddd-eeee-ffff-222222222222"; Name = "Staging" }
    @{ Id = "33333333-1111-2222-3333-333333333333"; Name = "Development" }
)

# ── Fake resource names ──────────────────────────────────────────────────────
$storageAccounts = @("stproddata01", "stprodlogs02", "ststagapp01", "stdevdata01", "stdevbackup01")
$keyVaults       = @("kv-prod-keys", "kv-prod-secrets", "kv-stag-app", "kv-dev-test")
$nsgs            = @("nsg-web-tier", "nsg-app-tier", "nsg-db-tier", "nsg-mgmt")

# ── All check definitions (mirrors the full set implemented in Checks/) ───────
$checks = @(
    # Section 2 — Azure Databricks
    @{ Id="2.1.2";  Title="Ensure That NSGs Are Configured for Azure Databricks Subnets"; Level=1; Section="2 - Azure Databricks" }
    @{ Id="2.1.7";  Title="Ensure That Azure Databricks Workspace Has Logging Enabled"; Level=2; Section="2 - Azure Databricks" }
    @{ Id="2.1.9";  Title="Ensure That Azure Databricks Workspace Has 'No Public IP' Enabled"; Level=2; Section="2 - Azure Databricks" }
    @{ Id="2.1.10"; Title="Ensure That Azure Databricks Workspace Has Public Network Access Disabled"; Level=2; Section="2 - Azure Databricks" }
    @{ Id="2.1.11"; Title="Ensure That Azure Databricks Workspace Uses Private Endpoints"; Level=2; Section="2 - Azure Databricks" }

    # Section 3 — Compute Services
    @{ Id="3.1.1";  Title="Ensure Only MFA Enabled Identities Can Access Privileged Virtual Machine"; Level=2; Section="3 - Compute Services"; Tenant=$true }

    # Section 5 — Identity Services
    @{ Id="5.1.1";  Title="Ensure Security Defaults Are Enabled on Microsoft Entra ID"; Level=1; Section="5 - Identity Services"; Tenant=$true }
    @{ Id="5.1.2";  Title="Ensure MFA Is Enabled for All Users in Administrative Roles"; Level=1; Section="5 - Identity Services"; Tenant=$true }
    @{ Id="5.1.3";  Title="Ensure That 'Remember Multi-Factor Authentication on Trusted Devices' Is Disabled"; Level=1; Section="5 - Identity Services"; Tenant=$true }
    @{ Id="5.28";   Title="Ensure Privileged Users Are Protected by Phishing-Resistant MFA"; Level=1; Section="5 - Identity Services"; Tenant=$true }
    @{ Id="5.4";    Title="Ensure That 'Restrict Non-Admin Users From Creating Tenants' Is Set to 'Yes'"; Level=1; Section="5 - Identity Services"; Tenant=$true }
    @{ Id="5.14";   Title="Ensure That 'Users Can Register Applications' Is Set to 'No'"; Level=1; Section="5 - Identity Services"; Tenant=$true }
    @{ Id="5.15";   Title="Ensure That 'Guest Users Access Restrictions' Is Set to 'Guest user access is restricted'"; Level=1; Section="5 - Identity Services"; Tenant=$true }
    @{ Id="5.16";   Title="Ensure That 'Guest Invite Restrictions' Is Set to 'Only Admins and Users in the Guest Inviter Role'"; Level=2; Section="5 - Identity Services"; Tenant=$true }
    @{ Id="5.3.3";  Title="Ensure 'User Access Administrator' Role Is Not Assigned at Subscription Level"; Level=1; Section="5 - Identity Services" }
    @{ Id="5.23";   Title="Ensure That No Custom Subscription Owner Roles Are Created"; Level=1; Section="5 - Identity Services" }
    @{ Id="5.27";   Title="Ensure That the Subscription Has Between 2 and 3 Owners"; Level=1; Section="5 - Identity Services" }

    # Section 6 — Management & Governance
    @{ Id="6.1.1.1";  Title="Ensure That a Diagnostic Setting Exists for the Subscription"; Level=1; Section="6 - Management & Governance" }
    @{ Id="6.1.1.2";  Title="Ensure Diagnostic Setting Captures Required Log Categories"; Level=1; Section="6 - Management & Governance" }
    @{ Id="6.1.1.3";  Title="Ensure the Activity Retention Log Is Set to at Least One Year"; Level=1; Section="6 - Management & Governance" }
    @{ Id="6.1.1.4";  Title="Ensure Diagnostic Logging for Key Vaults Is Enabled"; Level=1; Section="6 - Management & Governance" }
    @{ Id="6.1.1.6";  Title="Ensure App Service Resource Logs Are Enabled"; Level=2; Section="6 - Management & Governance" }
    @{ Id="6.1.2.1";  Title="Ensure Activity Log Alert: Create Policy Assignment"; Level=1; Section="6 - Management & Governance" }
    @{ Id="6.1.2.2";  Title="Ensure Activity Log Alert: Delete Policy Assignment"; Level=1; Section="6 - Management & Governance" }
    @{ Id="6.1.2.3";  Title="Ensure Activity Log Alert: Create/Update NSG"; Level=1; Section="6 - Management & Governance" }
    @{ Id="6.1.2.4";  Title="Ensure Activity Log Alert: Delete NSG"; Level=1; Section="6 - Management & Governance" }
    @{ Id="6.1.2.5";  Title="Ensure Activity Log Alert: Create/Update Security Solution"; Level=1; Section="6 - Management & Governance" }
    @{ Id="6.1.2.6";  Title="Ensure Activity Log Alert: Delete Security Solution"; Level=1; Section="6 - Management & Governance" }
    @{ Id="6.1.2.7";  Title="Ensure Activity Log Alert: Create/Update SQL Server Firewall Rule"; Level=1; Section="6 - Management & Governance" }
    @{ Id="6.1.2.8";  Title="Ensure Activity Log Alert: Delete SQL Server Firewall Rule"; Level=1; Section="6 - Management & Governance" }
    @{ Id="6.1.2.9";  Title="Ensure Activity Log Alert: Create/Update Public IP Address"; Level=1; Section="6 - Management & Governance" }
    @{ Id="6.1.2.10"; Title="Ensure Activity Log Alert: Delete Public IP Address"; Level=1; Section="6 - Management & Governance" }
    @{ Id="6.1.2.11"; Title="Ensure Activity Log Alert: Service Health Notifications"; Level=1; Section="6 - Management & Governance" }
    @{ Id="6.1.3.1";  Title="Ensure Application Insights Are Configured"; Level=2; Section="6 - Management & Governance" }

    # Section 7 — Networking Services
    @{ Id="7.1";  Title="Ensure RDP Access From the Internet Is Evaluated and Restricted"; Level=1; Section="7 - Networking Services"; Multi=$true }
    @{ Id="7.2";  Title="Ensure SSH Access From the Internet Is Evaluated and Restricted"; Level=1; Section="7 - Networking Services"; Multi=$true }
    @{ Id="7.3";  Title="Ensure That UDP Access From the Internet Is Evaluated and Restricted"; Level=1; Section="7 - Networking Services"; Multi=$true }
    @{ Id="7.4";  Title="Ensure That HTTP(S) Access From the Internet Is Evaluated and Restricted"; Level=1; Section="7 - Networking Services"; Multi=$true }
    @{ Id="7.5";  Title="Ensure That Network Watcher NSG Flow Log Retention Period Is 'Greater than 90 Days'"; Level=2; Section="7 - Networking Services" }
    @{ Id="7.6";  Title="Ensure That Network Watcher Is 'Enabled'"; Level=1; Section="7 - Networking Services" }
    @{ Id="7.8";  Title="Ensure That VNet Flow Log Retention Period Is 'Greater than 90 Days'"; Level=2; Section="7 - Networking Services" }
    @{ Id="7.10"; Title="Ensure That Azure Web Application Firewall Is Enabled for Azure Application Gateway"; Level=2; Section="7 - Networking Services" }
    @{ Id="7.11"; Title="Ensure That Virtual Network Security Groups Are Associated to Subnets"; Level=1; Section="7 - Networking Services"; Multi=$true }
    @{ Id="7.12"; Title="Ensure Application Gateway Is Configured with a Minimum TLS Version of 1.2"; Level=1; Section="7 - Networking Services" }
    @{ Id="7.13"; Title="Ensure Application Gateway Is Configured with HTTP2 Enabled"; Level=2; Section="7 - Networking Services" }
    @{ Id="7.14"; Title="Ensure That Web Application Firewall Request Body Inspection Is Enabled"; Level=2; Section="7 - Networking Services" }
    @{ Id="7.15"; Title="Ensure That Web Application Firewall Bot Protection Is Enabled"; Level=2; Section="7 - Networking Services" }

    # Section 8 — Security Services
    @{ Id="8.1.1.1";  Title="Ensure Microsoft Defender CSPM Is Set to 'On'"; Level=2; Section="8 - Security Services" }
    @{ Id="8.1.2.1";  Title="Ensure Microsoft Defender for APIs Is Set to 'On'"; Level=2; Section="8 - Security Services" }
    @{ Id="8.1.3.1";  Title="Ensure Microsoft Defender for Servers Is Set to 'On'"; Level=2; Section="8 - Security Services" }
    @{ Id="8.1.3.3";  Title="Ensure That Microsoft Defender for Endpoint Integration With Microsoft Defender for Cloud Is Enabled"; Level=1; Section="8 - Security Services" }
    @{ Id="8.1.4.1";  Title="Ensure Microsoft Defender for Containers Is Set to 'On'"; Level=2; Section="8 - Security Services" }
    @{ Id="8.1.5.1";  Title="Ensure Microsoft Defender for Storage Is Set to 'On'"; Level=2; Section="8 - Security Services" }
    @{ Id="8.1.6.1";  Title="Ensure Microsoft Defender for App Service Is Set to 'On'"; Level=2; Section="8 - Security Services" }
    @{ Id="8.1.7.1";  Title="Ensure Microsoft Defender for Azure Cosmos DB Is Set to 'On'"; Level=2; Section="8 - Security Services" }
    @{ Id="8.1.7.2";  Title="Ensure Microsoft Defender for Open-Source Relational Databases Is Set to 'On'"; Level=2; Section="8 - Security Services" }
    @{ Id="8.1.7.3";  Title="Ensure Microsoft Defender for Azure SQL Databases Is Set to 'On'"; Level=2; Section="8 - Security Services" }
    @{ Id="8.1.7.4";  Title="Ensure Microsoft Defender for SQL Servers on Machines Is Set to 'On'"; Level=2; Section="8 - Security Services" }
    @{ Id="8.1.8.1";  Title="Ensure Microsoft Defender for Key Vault Is Set to 'On'"; Level=2; Section="8 - Security Services" }
    @{ Id="8.1.9.1";  Title="Ensure Microsoft Defender for Resource Manager Is Set to 'On'"; Level=2; Section="8 - Security Services" }
    @{ Id="8.1.10";   Title="Ensure That Microsoft Defender for Cloud Is Set to Assess VMs for OS Updates"; Level=1; Section="8 - Security Services" }
    @{ Id="8.1.12";   Title="Ensure That 'All Users with the Following Roles' Is Set to 'Owner'"; Level=1; Section="8 - Security Services" }
    @{ Id="8.1.13";   Title="Ensure a Security Contact Email Is Set for Microsoft Defender for Cloud Notifications"; Level=1; Section="8 - Security Services" }
    @{ Id="8.1.14";   Title="Ensure That 'Send Notifications About Alerts with Severity High or Above' Is Set to 'On'"; Level=1; Section="8 - Security Services" }
    @{ Id="8.1.15";   Title="Ensure That Attack Path Notifications Are Configured"; Level=1; Section="8 - Security Services" }
    @{ Id="8.3.1";    Title="Ensure That the Expiration Date Is Set on All Keys (RBAC)"; Level=1; Section="8 - Security Services"; KV=$true }
    @{ Id="8.3.2";    Title="Ensure That the Expiration Date Is Set on All Keys (Non-RBAC)"; Level=1; Section="8 - Security Services"; KV=$true }
    @{ Id="8.3.3";    Title="Ensure That the Expiration Date Is Set on All Secrets (RBAC)"; Level=1; Section="8 - Security Services"; KV=$true }
    @{ Id="8.3.4";    Title="Ensure That the Expiration Date Is Set on All Secrets (Non-RBAC)"; Level=1; Section="8 - Security Services"; KV=$true }
    @{ Id="8.3.5";    Title="Ensure That Azure Key Vault Has Purge Protection Enabled"; Level=1; Section="8 - Security Services"; KV=$true }
    @{ Id="8.3.6";    Title="Ensure That Azure Key Vault Uses RBAC for Authorization"; Level=2; Section="8 - Security Services"; KV=$true }
    @{ Id="8.3.7";    Title="Ensure That Azure Key Vault Disables Public Network Access"; Level=1; Section="8 - Security Services"; KV=$true }
    @{ Id="8.3.8";    Title="Ensure That Private Endpoints Are Used for Azure Key Vaults"; Level=2; Section="8 - Security Services"; KV=$true }
    @{ Id="8.3.9";    Title="Ensure That Automatic Key Rotation Is Enabled for Key Vault Keys"; Level=2; Section="8 - Security Services"; KV=$true }
    @{ Id="8.3.11";   Title="Ensure That Certificate Validity Period Is Not More Than 12 Months"; Level=1; Section="8 - Security Services"; KV=$true }
    @{ Id="8.4.1";    Title="Ensure That Azure Bastion Host Exists"; Level=2; Section="8 - Security Services" }
    @{ Id="8.5";      Title="Ensure That Azure DDoS Network Protection Is Enabled"; Level=2; Section="8 - Security Services" }

    # Section 9 — Storage Services
    @{ Id="9.1.1";    Title="Ensure Soft Delete Is Enabled for Azure File Shares"; Level=1; Section="9 - Storage Services"; Storage=$true }
    @{ Id="9.1.2";    Title="Ensure SMB Access Is Restricted to SMB 3.1.1+"; Level=1; Section="9 - Storage Services"; Storage=$true }
    @{ Id="9.1.3";    Title="Ensure 'SMB' Channel Encryption Is Set to AES-256-GCM"; Level=1; Section="9 - Storage Services"; Storage=$true }
    @{ Id="9.2.1";    Title="Ensure That 'Blob Service' Soft Delete Is Set to 'Enabled'"; Level=1; Section="9 - Storage Services"; Storage=$true }
    @{ Id="9.2.2";    Title="Ensure That Container Soft Delete Is Set to 'Enabled'"; Level=1; Section="9 - Storage Services"; Storage=$true }
    @{ Id="9.2.3";    Title="Ensure That Blob Versioning Is Enabled for Storage Accounts"; Level=2; Section="9 - Storage Services"; Storage=$true }
    @{ Id="9.2.4";    Title="Ensure Storage Logging Is Enabled for Blob Service for 'Read' Requests"; Level=2; Section="9 - Storage Services"; Storage=$true }
    @{ Id="9.2.5";    Title="Ensure Storage Logging Is Enabled for Blob Service for 'Write' Requests"; Level=2; Section="9 - Storage Services"; Storage=$true }
    @{ Id="9.2.6";    Title="Ensure Storage Logging Is Enabled for Blob Service for 'Delete' Requests"; Level=2; Section="9 - Storage Services"; Storage=$true }
    @{ Id="9.3.1.1";  Title="Ensure that 'Enable key rotation reminders' is enabled for each Storage Account"; Level=1; Section="9 - Storage Services"; Storage=$true }
    @{ Id="9.3.1.2";  Title="Ensure that Storage Account access keys are periodically regenerated"; Level=1; Section="9 - Storage Services"; Storage=$true }
    @{ Id="9.3.1.3";  Title="Ensure That 'Shared Key Access' Is Disabled for Storage Accounts"; Level=2; Section="9 - Storage Services"; Storage=$true }
    @{ Id="9.3.2.1";  Title="Ensure That 'Private Endpoints' Are Used for Storage Accounts"; Level=2; Section="9 - Storage Services"; Storage=$true }
    @{ Id="9.3.2.2";  Title="Ensure That Storage Account Public Network Access Is Disabled"; Level=1; Section="9 - Storage Services"; Storage=$true }
    @{ Id="9.3.2.3";  Title="Ensure That Storage Account Default Network Rule Is Set to 'Deny'"; Level=1; Section="9 - Storage Services"; Storage=$true }
    @{ Id="9.3.3.1";  Title="Ensure That 'Default to Microsoft Entra ID Authorization' Is Set to 'Enabled'"; Level=2; Section="9 - Storage Services"; Storage=$true }
    @{ Id="9.3.4";    Title="Ensure 'Secure Transfer Required' Is Enabled for Storage Accounts"; Level=1; Section="9 - Storage Services"; Storage=$true }
    @{ Id="9.3.5";    Title="Ensure That 'Allow Azure Services on the Trusted Services List to Access This Storage Account' Is Enabled"; Level=2; Section="9 - Storage Services"; Storage=$true }
    @{ Id="9.3.6";    Title="Ensure That Storage Account Has the Minimum TLS Version of 'Version 1.2'"; Level=1; Section="9 - Storage Services"; Storage=$true }
    @{ Id="9.3.7";    Title="Ensure That 'Cross Tenant Replication' Is Not Enabled for Storage Accounts"; Level=1; Section="9 - Storage Services"; Storage=$true }
    @{ Id="9.3.8";    Title="Ensure That 'Public Access Level' Is Disabled for Storage Accounts With Blob Containers"; Level=1; Section="9 - Storage Services"; Storage=$true }
    @{ Id="9.3.9";    Title="Ensure That Storage Accounts Have a CanNotDelete Resource Lock"; Level=1; Section="9 - Storage Services"; Storage=$true }
    @{ Id="9.3.10";   Title="Ensure That Storage Accounts Have a ReadOnly Resource Lock"; Level=2; Section="9 - Storage Services"; Storage=$true }
    @{ Id="9.3.11";   Title="Ensure That Storage Account Replication Type Is Set to Geo-Redundant Storage"; Level=2; Section="9 - Storage Services"; Storage=$true }
)

# ── Remediation hints keyed by section ────────────────────────────────────────
$remediations = @{
    "2" = "Databricks > Workspace > Settings"
    "5" = "Entra ID > Properties / Users / External Identities"
    "6" = "Monitor > Activity Log > Diagnostic Settings / Alerts"
    "7" = "NSG > Inbound Rules / Network Watcher > Flow Logs / App Gateway > Configuration"
    "8" = "Defender for Cloud > Environment Settings > Plans / Key Vault > Settings"
    "9" = "Storage Account > Configuration / Data Protection / Networking"
}

# ── Deterministic seed for reproducibility ────────────────────────────────────
$rng = [System.Random]::new(42)

function Get-SyntheticStatus {
    # Weight toward PASS for a realistic-looking report (~65% pass, ~20% fail, ~8% error, ~5% info, ~2% manual)
    $roll = $rng.Next(100)
    if ($roll -lt 65)  { return "PASS" }
    if ($roll -lt 85)  { return "FAIL" }
    if ($roll -lt 93)  { return "ERROR" }
    if ($roll -lt 98)  { return "INFO" }
    return "MANUAL"
}

# ── Generate results ──────────────────────────────────────────────────────────
$results = [System.Collections.Generic.List[object]]::new()

foreach ($chk in $checks) {
    $secNum = $chk.Id.Split('.')[0]

    # Tenant-level checks: one result only
    if ($chk.ContainsKey('Tenant') -and $chk.Tenant) {
        $status = Get-SyntheticStatus
        $detail = switch ($status) {
            "PASS"   { "Compliant. Setting is correctly configured." }
            "FAIL"   { "Non-compliant. Setting needs to be updated." }
            "ERROR"  { "Could not evaluate: insufficient Graph API permissions (Policy.Read.All required)." }
            "INFO"   { "Security defaults disabled; Conditional Access policies detected (stronger control)." }
            "MANUAL" { "Requires manual verification in the Entra ID portal." }
        }
        $rem = if ($status -eq "FAIL") { $remediations[$secNum] } else { "" }
        $results.Add((New-CISResult -ControlId $chk.Id -Title $chk.Title -Level $chk.Level `
            -Section $chk.Section -Status $status -Details $detail -Remediation $rem))
        continue
    }

    # Per-subscription checks
    foreach ($sub in $subs) {
        # Resource-level checks: produce per-resource results
        if ($chk.ContainsKey('Multi') -and $chk.Multi) {
            foreach ($nsg in $nsgs) {
                $status = Get-SyntheticStatus
                $detail = switch ($status) {
                    "PASS"   { "NSG '$nsg': No internet-exposed rules found." }
                    "FAIL"   { "NSG '$nsg': Inbound rule 'AllowAll' allows 0.0.0.0/0 access on restricted port." }
                    "ERROR"  { "NSG '$nsg': Query timed out after 20s." }
                    default  { "NSG '$nsg': Not applicable." }
                }
                $rem = if ($status -eq "FAIL") { "NSG > Inbound Rules > Remove or restrict the open rule." } else { "" }
                $results.Add((New-CISResult -ControlId $chk.Id -Title $chk.Title -Level $chk.Level `
                    -Section $chk.Section -Status $status -Details $detail -Remediation $rem `
                    -SubscriptionId $sub.Id -SubscriptionName $sub.Name -Resource $nsg))
            }
            continue
        }
        if ($chk.ContainsKey('Storage') -and $chk.Storage) {
            foreach ($sa in $storageAccounts) {
                $status = Get-SyntheticStatus
                $detail = switch ($status) {
                    "PASS"   { "Account '$sa': Compliant." }
                    "FAIL"   { "Account '$sa': Non-compliant. Setting needs to be enabled." }
                    "ERROR"  { "Account '$sa': Access denied or query error." }
                    "INFO"   { "Account '$sa': ADLS Gen2 — control does not apply." }
                    default  { "Account '$sa': Not applicable." }
                }
                $rem = if ($status -eq "FAIL") { $remediations[$secNum] } else { "" }
                $results.Add((New-CISResult -ControlId $chk.Id -Title $chk.Title -Level $chk.Level `
                    -Section $chk.Section -Status $status -Details $detail -Remediation $rem `
                    -SubscriptionId $sub.Id -SubscriptionName $sub.Name -Resource $sa))
            }
            continue
        }
        if ($chk.ContainsKey('KV') -and $chk.KV) {
            foreach ($kv in $keyVaults) {
                $status = Get-SyntheticStatus
                $detail = switch ($status) {
                    "PASS"   { "Vault '$kv': Compliant." }
                    "FAIL"   { "Vault '$kv': Non-compliant. Setting needs to be enabled." }
                    "ERROR"  { "Vault '$kv': Cannot access data plane. Assign Key Vault Reader role." }
                    default  { "Vault '$kv': Not applicable." }
                }
                $rem = if ($status -eq "FAIL") { "Key Vault > Settings > Update the configuration." } else { "" }
                $results.Add((New-CISResult -ControlId $chk.Id -Title $chk.Title -Level $chk.Level `
                    -Section $chk.Section -Status $status -Details $detail -Remediation $rem `
                    -SubscriptionId $sub.Id -SubscriptionName $sub.Name -Resource $kv))
            }
            continue
        }

        # Standard per-subscription check: one result per sub
        $status = Get-SyntheticStatus
        $detail = switch ($status) {
            "PASS"   { "Compliant." }
            "FAIL"   { "Non-compliant. Configuration update required." }
            "ERROR"  { "Could not evaluate: permission denied or timeout." }
            "INFO"   { "Not applicable for this subscription." }
            "MANUAL" { "Requires manual verification." }
        }
        $rem = if ($status -eq "FAIL") { $remediations[$secNum] } else { "" }
        $results.Add((New-CISResult -ControlId $chk.Id -Title $chk.Title -Level $chk.Level `
            -Section $chk.Section -Status $status -Details $detail -Remediation $rem `
            -SubscriptionId $sub.Id -SubscriptionName $sub.Name))
    }
}

# ── Synthetic history (3 prior runs for trend chart) ──────────────────────────
# Scores use PASS/(PASS+FAIL) — consistent with the report's compliance formula.
$history = @(
    [PSCustomObject]@{ timestamp = "2026-02-15T10:00:00Z"; score = 69.5; pass = 410; fail = 180; error = 115 }
    [PSCustomObject]@{ timestamp = "2026-03-01T10:00:00Z"; score = 74.2; pass = 445; fail = 155; error = 110 }
    [PSCustomObject]@{ timestamp = "2026-03-15T10:00:00Z"; score = 76.7; pass = 460; fail = 140; error = 108 }
)

# ── Scope info ────────────────────────────────────────────────────────────────
$scopeInfo = @{
    tenant       = $tenantId
    user         = "auditor@contoso.onmicrosoft.com"
    caller_type  = "user"
    scope_label  = "All subscriptions (tenant-wide)"
    subscriptions = $subs | ForEach-Object { $_.Name }
    level_filter = "both"
}

$subTimestamps = @{}
foreach ($sub in $subs) {
    $subTimestamps[$sub.Name] = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
}

# ── Generate the report ──────────────────────────────────────────────────────
$docsDir = Join-Path $root "docs"
if (-not (Test-Path $docsDir)) { New-Item -ItemType Directory -Path $docsDir | Out-Null }
$outputPath = Join-Path $docsDir "sample_report.html"

New-CISHtmlReport -Results $results.ToArray() `
    -OutputPath $outputPath `
    -ScopeLabel "All subscriptions (tenant-wide)" `
    -History $history `
    -ScopeInfo $scopeInfo `
    -SubTimestamps $subTimestamps

Write-Host "Sample report generated: $outputPath" -ForegroundColor Green
Write-Host "Total results: $($results.Count)" -ForegroundColor Cyan
