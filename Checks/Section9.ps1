# Section 9 — Storage Services
# CIS Microsoft Azure Foundations Benchmark v5.0.0

function Invoke-Section9Checks {
    [CmdletBinding()]
    param(
        [string]$SubscriptionId,
        [string]$SubscriptionName,
        [hashtable]$PrefetchData
    )

    $results  = [System.Collections.Generic.List[object]]::new()
    $sec      = "9 - Storage Services"
    $sid      = $SubscriptionId
    $sname    = $SubscriptionName

    $accounts = @(Get-PrefetchData -PrefetchData $PrefetchData -Key "storage" -SubscriptionId $sid)

    # Fallback: if prefetch returned nothing, fetch directly
    if ($accounts.Count -eq 0) {
        $r = Invoke-AzCli -Arguments @(
            "storage", "account", "list", "--subscription", $sid,
            "--query", "[].{id:id,name:name,resourceGroup:resourceGroup,kind:kind,sku:sku}"
        ) -TimeoutSec $script:TIMEOUTS.storage_list
        if ($r.Success -and $r.Data) { $accounts = @($r.Data) }
    }

    if ($accounts.Count -eq 0) {
        $noAccountInfo = "No storage accounts found."
        $storageControls = @(
            ,@("9.3.4","Ensure 'Secure Transfer Required' Is Enabled for Storage Accounts",1)
            ,@("9.1.2","Ensure SMB Access Is Restricted to SMB 3.1.1+",1)
            ,@("9.1.3","Ensure 'SMB' Channel Encryption Is Set to AES-256-GCM",1)
            ,@("9.3.8","Ensure That 'Public Access Level' Is Disabled for Storage Accounts With Blob Containers",1)
            ,@("9.2.1","Ensure That 'Blob Service' Soft Delete Is Set to 'Enabled'",1)
            ,@("9.2.2","Ensure That Container Soft Delete Is Set to 'Enabled'",1)
            ,@("9.2.3","Ensure That Blob Versioning Is Enabled for Storage Accounts",2)
            ,@("9.2.4","Ensure Storage Logging Is Enabled for Blob Service for 'Read' Requests",2)
            ,@("9.2.5","Ensure Storage Logging Is Enabled for Blob Service for 'Write' Requests",2)
            ,@("9.2.6","Ensure Storage Logging Is Enabled for Blob Service for 'Delete' Requests",2)
            ,@("9.3.7","Ensure That 'Cross Tenant Replication' Is Not Enabled for Storage Accounts",1)
            ,@("9.3.1.3","Ensure That 'Shared Key Access' Is Disabled for Storage Accounts",2)
            ,@("9.3.3.1","Ensure That 'Default to Microsoft Entra ID Authorization' Is Set to 'Enabled'",2)
            ,@("9.3.2.2","Ensure That Storage Account Public Network Access Is Disabled",1)
            ,@("9.3.2.3","Ensure That Storage Account Default Network Rule Is Set to 'Deny'",1)
            ,@("9.3.5","Ensure That 'Allow Azure Services on the Trusted Services List to Access This Storage Account' Is Enabled",2)
            ,@("9.3.1.1","Ensure Storage Account Key Rotation Reminders Are Enabled",1)
            ,@("9.3.1.2","Ensure That Storage Accounts Are Configured to Use Access Keys Rotated Within 90 Days",1)
            ,@("9.3.6","Ensure That Storage Account Has the Minimum TLS Version of 'Version 1.2'",1)
            ,@("9.3.2.1","Ensure That 'Private Endpoints' Are Used for Storage Accounts",2)
            ,@("9.3.9","Ensure That Storage Accounts Have a CanNotDelete Resource Lock",1)
            ,@("9.1.1","Ensure Soft Delete Is Enabled for Azure File Shares",1)
            ,@("9.3.10","Ensure That Storage Accounts Have a ReadOnly Resource Lock",2)
            ,@("9.3.11","Ensure That Storage Account Replication Type Is Set to Geo-Redundant Storage",2)
        )
        foreach ($c in $storageControls) {
            $results.Add((New-InfoResult $c[0] $c[1] ([int]$c[2]) $sec $noAccountInfo $sid $sname))
        }
        return $results.ToArray()
    }

    foreach ($acct in $accounts) {
        $acctName = [string]($acct.PSObject.Properties['name']?.Value)
        $acctId   = [string]($acct.PSObject.Properties['id']?.Value)
        $acctRg   = [string]($acct.PSObject.Properties['resourceGroup']?.Value)
        $kind     = [string]($acct.PSObject.Properties['kind']?.Value)

        # ── Group 1: Static checks from Resource Graph ────────────────────────

        # 9.3.4 — Secure transfer required (HTTPS only)
        $httpsOnly = [string]($acct.PSObject.Properties['httpsOnly']?.Value)
        $httpsOk   = $httpsOnly -eq "true" -or $httpsOnly -eq "True"
        $results.Add((New-CISResult `
            -ControlId "9.3.4" -Title "Ensure 'Secure Transfer Required' Is Enabled for Storage Accounts" `
            -Level 1 -Section $sec `
            -Status $(if ($httpsOk) { $script:PASS } else { $script:FAIL }) `
            -Details $(if ($httpsOk) { "Secure transfer (HTTPS only): Required." } else { "Secure transfer (HTTPS only): Not required — HTTP connections are allowed." }) `
            -Remediation $(if (-not $httpsOk) { "Storage account > $acctName > Configuration > Require secure transfer > Enabled" } else { "" }) `
            -SubscriptionId $sid -SubscriptionName $sname -Resource $acctName))

        # 9.3.8 — No anonymous blob public access
        $blobAnon    = [string]($acct.PSObject.Properties['blobAnon']?.Value)
        $anonDisabled = $blobAnon -eq "false" -or $blobAnon -eq "False"
        $results.Add((New-CISResult `
            -ControlId "9.3.8" -Title "Ensure That 'Public Access Level' Is Disabled for Storage Accounts With Blob Containers" `
            -Level 1 -Section $sec `
            -Status $(if ($anonDisabled) { $script:PASS } else { $script:FAIL }) `
            -Details $(if ($anonDisabled) { "Blob public access: Disabled." } else { "Blob public access: Enabled — anonymous access to blob containers is allowed." }) `
            -Remediation $(if (-not $anonDisabled) { "Storage account > $acctName > Configuration > Allow Blob public access > Disabled" } else { "" }) `
            -SubscriptionId $sid -SubscriptionName $sname -Resource $acctName))

        # 9.3.7 — Cross-tenant replication disabled
        $crossTenant    = [string]($acct.PSObject.Properties['crossTenant']?.Value)
        $crossTenantOff = $crossTenant -eq "false" -or $crossTenant -eq "False"
        $results.Add((New-CISResult `
            -ControlId "9.3.7" -Title "Ensure That 'Cross Tenant Replication' Is Not Enabled for Storage Accounts" `
            -Level 1 -Section $sec `
            -Status $(if ($crossTenantOff) { $script:PASS } else { $script:FAIL }) `
            -Details $(if ($crossTenantOff) { "Cross-tenant replication: Disabled." } else { "Cross-tenant replication: Enabled — data can be replicated to storage accounts in other tenants." }) `
            -Remediation $(if (-not $crossTenantOff) { "Storage account > $acctName > Object replication > Disable cross-tenant replication" } else { "" }) `
            -SubscriptionId $sid -SubscriptionName $sname -Resource $acctName))

        # 9.3.1.3 — Shared Key access disabled
        $keyAccess    = [string]($acct.PSObject.Properties['keyAccess']?.Value)
        $keyAccessOff = $keyAccess -eq "false" -or $keyAccess -eq "False"
        $results.Add((New-CISResult `
            -ControlId "9.3.1.3" -Title "Ensure That 'Shared Key Access' Is Disabled for Storage Accounts" `
            -Level 2 -Section $sec `
            -Status $(if ($keyAccessOff) { $script:PASS } else { $script:FAIL }) `
            -Details $(if ($keyAccessOff) { "Shared key (storage account key) access: Disabled." } else { "Shared key (storage account key) access: Enabled — disable to enforce Entra ID authentication." }) `
            -Remediation $(if (-not $keyAccessOff) { "Storage account > $acctName > Configuration > Allow storage account key access > Disabled" } else { "" }) `
            -SubscriptionId $sid -SubscriptionName $sname -Resource $acctName))

        # 9.3.3.1 — Default to Entra ID (OAuth) authorization
        $oauthDefault   = [string]($acct.PSObject.Properties['oauthDefault']?.Value)
        $oauthDefaultOn = $oauthDefault -eq "true" -or $oauthDefault -eq "True"
        $results.Add((New-CISResult `
            -ControlId "9.3.3.1" -Title "Ensure That 'Default to Microsoft Entra ID Authorization' Is Set to 'Enabled'" `
            -Level 2 -Section $sec `
            -Status $(if ($oauthDefaultOn) { $script:PASS } else { $script:FAIL }) `
            -Details $(if ($oauthDefaultOn) { "Default to Microsoft Entra ID authorization: Enabled." } else { "Default to Microsoft Entra ID authorization: Disabled — storage data requests are not automatically authorized with Entra ID." }) `
            -Remediation $(if (-not $oauthDefaultOn) { "Storage account > $acctName > Configuration > Default to Entra ID authorization in Azure portal > Enabled" } else { "" }) `
            -SubscriptionId $sid -SubscriptionName $sname -Resource $acctName))

        # Variable setup for 9.3.2.2, 9.3.2.3, and downstream checks
        $pubAccess    = [string]($acct.PSObject.Properties['publicAccess']?.Value)
        $defaultAction = [string]($acct.PSObject.Properties['defaultAction']?.Value)
        $bypass       = ([string]($acct.PSObject.Properties['bypass']?.Value)).ToLower()
        $acctSku      = ([string]($acct.PSObject.Properties['sku']?.Value)).ToUpper()
        $isGrs        = @("GRS","GZRS","RAGRS","RAGZRS") | Where-Object { $acctSku -match $_ }

        # 9.3.2.2 — Public network access must be "Disabled"
        $pubDisabled = $pubAccess -eq "Disabled"
        $results.Add((New-CISResult `
            -ControlId "9.3.2.2" -Title "Ensure That Storage Account Public Network Access Is Disabled" `
            -Level 1 -Section $sec `
            -Status $(if ($pubDisabled) { $script:PASS } else { $script:FAIL }) `
            -Details "publicNetworkAccess = $pubAccess" `
            -Remediation $(if (-not $pubDisabled) { "Storage account > $acctName > Networking > Public network access > Disabled" } else { "" }) `
            -SubscriptionId $sid -SubscriptionName $sname -Resource $acctName))

        # 9.3.2.3 — Default network ACL action must be "Deny"
        $denyDefault = $defaultAction -eq "Deny"
        $results.Add((New-CISResult `
            -ControlId "9.3.2.3" -Title "Ensure That Storage Account Default Network Rule Is Set to 'Deny'" `
            -Level 1 -Section $sec `
            -Status $(if ($denyDefault) { $script:PASS } else { $script:FAIL }) `
            -Details "networkAcls.defaultAction = $defaultAction" `
            -Remediation $(if (-not $denyDefault) { "Storage account > $acctName > Networking > Firewall and virtual networks > Default action: Deny" } else { "" }) `
            -SubscriptionId $sid -SubscriptionName $sname -Resource $acctName))

        # 9.3.6 — TLS 1.2+
        $minTls  = [string]($acct.PSObject.Properties['minTls']?.Value)
        $tlsOk   = $minTls -match "TLS1_2|TLS1_3"
        $results.Add((New-CISResult `
            -ControlId "9.3.6" -Title "Ensure That Storage Account Has the Minimum TLS Version of 'Version 1.2'" `
            -Level 1 -Section $sec `
            -Status $(if ($tlsOk) { $script:PASS } else { $script:FAIL }) `
            -Details $(if ($tlsOk) { "Minimum TLS version: $minTls." } else { "Minimum TLS version: $minTls — must be TLS 1.2 or higher." }) `
            -Remediation $(if (-not $tlsOk) { "Storage account > $acctName > Configuration > Minimum TLS version > TLS 1.2" } else { "" }) `
            -SubscriptionId $sid -SubscriptionName $sname -Resource $acctName))

        # 9.3.5 — Trusted Azure services bypass
        $bypassOk = $bypass -match "azureservices"
        $results.Add((New-CISResult `
            -ControlId "9.3.5" -Title "Ensure That 'Allow Azure Services on the Trusted Services List to Access This Storage Account' Is Enabled" `
            -Level 2 -Section $sec `
            -Status $(if ($bypassOk) { $script:PASS } else { $script:FAIL }) `
            -Details $(if ($bypassOk) { "networkAcls.bypass includes AzureServices." } else { "networkAcls.bypass: $([string]($acct.PSObject.Properties['bypass']?.Value)) — AzureServices not listed." }) `
            -Remediation $(if (-not $bypassOk) { "Storage account > $acctName > Networking > Exceptions > Allow Azure services on the trusted services list." } else { "" }) `
            -SubscriptionId $sid -SubscriptionName $sname -Resource $acctName))

        # 9.3.11 — Geo-redundant storage (GRS)
        $results.Add((New-CISResult `
            -ControlId "9.3.11" -Title "Ensure That Storage Account Replication Type Is Set to Geo-Redundant Storage" `
            -Level 2 -Section $sec `
            -Status $(if ($isGrs) { $script:PASS } else { $script:FAIL }) `
            -Details "Storage SKU: $acctSku$(if (-not $isGrs) { ' — not geo-redundant' } else { '' })" `
            -Remediation $(if (-not $isGrs) { "Storage account > $acctName > Data Management > Redundancy > Select GRS, GZRS, RA-GRS, or RA-GZRS." } else { "" }) `
            -SubscriptionId $sid -SubscriptionName $sname -Resource $acctName))

        # 9.3.2.1 — Private endpoints
        $privateEps = [int]($acct.PSObject.Properties['privateEps']?.Value)
        $results.Add((New-CISResult `
            -ControlId "9.3.2.1" -Title "Ensure That 'Private Endpoints' Are Used for Storage Accounts" `
            -Level 2 -Section $sec `
            -Status $(if ($privateEps -gt 0) { $script:PASS } else { $script:FAIL }) `
            -Details $(if ($privateEps -gt 0) { "Private endpoints: $privateEps configured." } else { "Private endpoints: $privateEps — at least one private endpoint is required." }) `
            -Remediation $(if ($privateEps -eq 0) { "Storage account > $acctName > Networking > Private endpoint connections > Add" } else { "" }) `
            -SubscriptionId $sid -SubscriptionName $sname -Resource $acctName))

        # ── Group 2: Blob service properties (dynamic call per account) ───────

        # Skip blob/file checks for Azure Data Lake Gen2 (no blob service API)
        $acctSku = [string]($acct.PSObject.Properties['sku']?.Value)
        $isAdls = $kind -eq "StorageV2" -and ($acctSku -match "HNS" -or $acctSku -match "Premium")

        if (-not $isAdls) {
            try {
                $r = Invoke-AzCli -Arguments @(
                    "storage", "blob", "service-properties", "show",
                    "--account-name", $acctName, "--auth-mode", "login"
                ) -TimeoutSec $script:TIMEOUTS.storage_svc

                if (-not $r.Success) {
                    if (Test-NotApplicableError $r.Error) {
                        $results.Add((New-InfoResult "9.2.1" "Blob Soft Delete" 1 $sec "Blob service not supported for this account type." $sid $sname $acctName))
                        $results.Add((New-InfoResult "9.2.2" "Container Soft Delete" 1 $sec "Blob service not supported for this account type." $sid $sname $acctName))
                        $results.Add((New-InfoResult "9.2.3" "Blob Versioning" 2 $sec "Blob service not supported." $sid $sname $acctName))
                        $results.Add((New-InfoResult "9.2.4" "Blob Logging Read" 2 $sec "Blob service not supported." $sid $sname $acctName))
                        $results.Add((New-InfoResult "9.2.5" "Blob Logging Write" 2 $sec "Blob service not supported." $sid $sname $acctName))
                        $results.Add((New-InfoResult "9.2.6" "Blob Logging Delete" 2 $sec "Blob service not supported." $sid $sname $acctName))
                    } elseif (Test-AuthzError $r.Error) {
                        $results.Add((New-ErrorResult "9.2.1" "Blob Soft Delete" 1 $sec "Insufficient permissions to read blob service properties." $sid $sname $acctName))
                        $results.Add((New-ErrorResult "9.2.2" "Container Soft Delete" 1 $sec "Insufficient permissions." $sid $sname $acctName))
                        $results.Add((New-ErrorResult "9.2.3" "Blob Versioning" 2 $sec "Insufficient permissions." $sid $sname $acctName))
                        $results.Add((New-ErrorResult "9.2.4" "Blob Logging Read" 2 $sec "Insufficient permissions." $sid $sname $acctName))
                        $results.Add((New-ErrorResult "9.2.5" "Blob Logging Write" 2 $sec "Insufficient permissions." $sid $sname $acctName))
                        $results.Add((New-ErrorResult "9.2.6" "Blob Logging Delete" 2 $sec "Insufficient permissions." $sid $sname $acctName))
                    } elseif (Test-FirewallError $r.Error) {
                        foreach ($cid in @("9.2.1","9.2.2","9.2.3","9.2.4","9.2.5","9.2.6")) {
                            $results.Add((New-ErrorResult $cid "Blob service check" 1 $sec "Storage account firewall or network configuration is blocking access. Verify that the storage account is accessible from the audit machine." $sid $sname $acctName))
                        }
                    } else {
                        $results.Add((New-ErrorResult "9.2.1" "Blob Soft Delete" 1 $sec $r.Error $sid $sname $acctName))
                    }
                } else {
                    $bp = $r.Data

                    # 9.2.1 — Blob soft delete enabled
                    $drpObj     = $bp.PSObject.Properties['deleteRetentionPolicy']?.Value
                    $softDel    = if ($drpObj) { [string]($drpObj.PSObject.Properties['enabled']?.Value) } else { 'False' }
                    $softDelOn  = $softDel -eq "true" -or $softDel -eq "True"
                    $retDays    = if ($drpObj) { [int]($drpObj.PSObject.Properties['days']?.Value) } else { 0 }
                    $blobSdOk   = $softDelOn -and $retDays -ge 7
                    $results.Add((New-CISResult `
                        -ControlId "9.2.1" -Title "Ensure That 'Blob Service' Soft Delete Is Set to 'Enabled'" `
                        -Level 1 -Section $sec `
                        -Status $(if ($blobSdOk) { $script:PASS } else { $script:FAIL }) `
                        -Details "Blob soft delete: enabled=$softDel, days=$retDays" `
                        -Remediation $(if (-not $blobSdOk) { "Storage account > $acctName > Data management > Data protection > Enable soft delete for blobs (>= 7 days)" } else { "" }) `
                        -SubscriptionId $sid -SubscriptionName $sname -Resource $acctName))

                    # 9.2.2 — Container soft delete enabled
                    $conDelObj     = $bp.PSObject.Properties['containerDeleteRetentionPolicy']?.Value
                    $conDelEnabled = if ($conDelObj) { [string]($conDelObj.PSObject.Properties['enabled']?.Value) } else { 'False' }
                    $conDelOn      = $conDelEnabled -eq "true" -or $conDelEnabled -eq "True"
                    $conDays       = if ($conDelObj) { [int]($conDelObj.PSObject.Properties['days']?.Value) } else { 0 }
                    $conOk         = $conDelOn -and $conDays -ge 7
                    $results.Add((New-CISResult `
                        -ControlId "9.2.2" -Title "Ensure That Container Soft Delete Is Set to 'Enabled'" `
                        -Level 1 -Section $sec `
                        -Status $(if ($conOk) { $script:PASS } else { $script:FAIL }) `
                        -Details "Container soft delete: enabled=$conDelEnabled, days=$conDays" `
                        -Remediation $(if (-not $conOk) { "Storage account > $acctName > Data management > Data protection > Enable soft delete for containers (>= 7 days)" } else { "" }) `
                        -SubscriptionId $sid -SubscriptionName $sname -Resource $acctName))

                    # 9.2.3 — Blob versioning enabled
                    $versionVal = [string]($bp.PSObject.Properties['isVersioningEnabled']?.Value)
                    $versionOn = $versionVal -eq "true" -or $versionVal -eq "True"
                    $results.Add((New-CISResult `
                        -ControlId "9.2.3" -Title "Ensure That Blob Versioning Is Enabled for Storage Accounts" `
                        -Level 2 -Section $sec `
                        -Status $(if ($versionOn) { $script:PASS } else { $script:FAIL }) `
                        -Details "Blob versioning: $(if($versionOn){'Enabled'}else{'Disabled'})" `
                        -Remediation $(if (-not $versionOn) { "Storage account > $acctName > Data management > Data protection > Enable blob versioning" } else { "" }) `
                        -SubscriptionId $sid -SubscriptionName $sname -Resource $acctName))

                    # 9.2.4/5/6 — Blob logging (Read/Write/Delete)
                    $bpLog     = $bp.PSObject.Properties['logging']?.Value
                    $logReadVal   = if ($bpLog) { [string]($bpLog.PSObject.Properties['read']?.Value)   } else { '' }
                    $logWriteVal  = if ($bpLog) { [string]($bpLog.PSObject.Properties['write']?.Value)  } else { '' }
                    $logDeleteVal = if ($bpLog) { [string]($bpLog.PSObject.Properties['delete']?.Value) } else { '' }
                    $logRead   = $logReadVal   -eq "true" -or $logReadVal   -eq "True"
                    $logWrite  = $logWriteVal  -eq "true" -or $logWriteVal  -eq "True"
                    $logDelete = $logDeleteVal -eq "true" -or $logDeleteVal -eq "True"

                    $results.Add((New-CISResult `
                        -ControlId "9.2.4" -Title "Ensure Storage Logging Is Enabled for Blob Service for 'Read' Requests" `
                        -Level 2 -Section $sec `
                        -Status $(if ($logRead) { $script:PASS } else { $script:FAIL }) `
                        -Details "Blob logging read: $logRead" `
                        -Remediation $(if (-not $logRead) { "Storage account > $acctName > Monitoring > Diagnostic settings > Enable Read logging" } else { "" }) `
                        -SubscriptionId $sid -SubscriptionName $sname -Resource $acctName))

                    $results.Add((New-CISResult `
                        -ControlId "9.2.5" -Title "Ensure Storage Logging Is Enabled for Blob Service for 'Write' Requests" `
                        -Level 2 -Section $sec `
                        -Status $(if ($logWrite) { $script:PASS } else { $script:FAIL }) `
                        -Details "Blob logging write: $logWrite" `
                        -Remediation $(if (-not $logWrite) { "Storage account > $acctName > Monitoring > Diagnostic settings > Enable Write logging" } else { "" }) `
                        -SubscriptionId $sid -SubscriptionName $sname -Resource $acctName))

                    $results.Add((New-CISResult `
                        -ControlId "9.2.6" -Title "Ensure Storage Logging Is Enabled for Blob Service for 'Delete' Requests" `
                        -Level 2 -Section $sec `
                        -Status $(if ($logDelete) { $script:PASS } else { $script:FAIL }) `
                        -Details "Blob logging delete: $logDelete" `
                        -Remediation $(if (-not $logDelete) { "Storage account > $acctName > Monitoring > Diagnostic settings > Enable Delete logging" } else { "" }) `
                        -SubscriptionId $sid -SubscriptionName $sname -Resource $acctName))
                }
            } catch {
                $results.Add((New-ErrorResult "9.2.1" "Blob Service Properties" 1 $sec $_.Exception.Message $sid $sname $acctName))
            }
        } else {
            foreach ($cid in @("9.2.1","9.2.2","9.2.3","9.2.4","9.2.5","9.2.6")) {
                $results.Add((New-InfoResult $cid "Blob service check" 2 $sec "ADLS Gen2 — blob service properties API not applicable." $sid $sname $acctName))
            }
        }

        # ── Group 3: File service soft delete ─────────────────────────────────

        # 9.1.1 — File share soft delete
        try {
            $r = Invoke-AzCli -Arguments @(
                "storage", "account", "file-service-properties", "show",
                "--account-name", $acctName, "--resource-group", $acctRg
            ) -SubscriptionId $sid -TimeoutSec $script:TIMEOUTS.storage_svc

            if (-not $r.Success) {
                if (Test-NotApplicableError $r.Error) {
                    $results.Add((New-InfoResult "9.1.1" "Ensure Soft Delete Is Enabled for Azure File Shares" 1 $sec "File service not supported." $sid $sname $acctName))
                    $results.Add((New-InfoResult "9.1.2" "Ensure SMB Access Is Restricted to SMB 3.1.1+" 1 $sec "File service not supported for this account type." $sid $sname $acctName))
                    $results.Add((New-InfoResult "9.1.3" "Ensure 'SMB' Channel Encryption Is Set to AES-256-GCM" 1 $sec "File service not supported for this account type." $sid $sname $acctName))
                } elseif (Test-FirewallError $r.Error) {
                    $results.Add((New-ErrorResult "9.1.1" "Ensure Soft Delete Is Enabled for Azure File Shares" 1 $sec "Storage account firewall or network configuration is blocking access." $sid $sname $acctName))
                    $results.Add((New-ErrorResult "9.1.2" "Ensure SMB Access Is Restricted to SMB 3.1.1+" 1 $sec "Storage account firewall or network configuration is blocking access." $sid $sname $acctName))
                    $results.Add((New-ErrorResult "9.1.3" "Ensure 'SMB' Channel Encryption Is Set to AES-256-GCM" 1 $sec "Storage account firewall or network configuration is blocking access." $sid $sname $acctName))
                } else {
                    $results.Add((New-ErrorResult "9.1.1" "Ensure Soft Delete Is Enabled for Azure File Shares" 1 $sec $r.Error $sid $sname $acctName))
                    $results.Add((New-ErrorResult "9.1.2" "Ensure SMB Access Is Restricted to SMB 3.1.1+" 1 $sec $r.Error $sid $sname $acctName))
                    $results.Add((New-ErrorResult "9.1.3" "Ensure 'SMB' Channel Encryption Is Set to AES-256-GCM" 1 $sec $r.Error $sid $sname $acctName))
                }
            } else {
                $fp   = $r.Data
                $sdrp = $fp.PSObject.Properties['shareDeleteRetentionPolicy']
                if ($sdrp -and $sdrp.Value) {
                    $fsDelOn = [string]$sdrp.Value.enabled -eq "true" -or [string]$sdrp.Value.enabled -eq "True"
                    $fsDays  = [int]($sdrp.Value.PSObject.Properties['days']?.Value)
                } else {
                    $fsDelOn = $false
                    $fsDays  = 0
                }
                $fsOk    = $fsDelOn -and $fsDays -ge 7

                $results.Add((New-CISResult `
                    -ControlId "9.1.1" -Title "Ensure Soft Delete Is Enabled for Azure File Shares" `
                    -Level 1 -Section $sec `
                    -Status $(if ($fsOk) { $script:PASS } else { $script:FAIL }) `
                    -Details "File share soft delete: enabled=$fsDelOn, days=$fsDays" `
                    -Remediation $(if (-not $fsOk) { "Storage account > $acctName > Data management > Data protection > Enable soft delete for file shares (>= 7 days)" } else { "" }) `
                    -SubscriptionId $sid -SubscriptionName $sname -Resource $acctName))

                # 9.1.2 — SMB protocol version >= 3.1.1
                # 9.1.3 — SMB channel encryption AES-256-GCM or higher
                $smbProt  = $fp.PSObject.Properties['protocolSettings']?.Value
                $smb      = if ($smbProt) { $smbProt.PSObject.Properties['smb']?.Value } else { $null }
                $smbVers  = if ($smb) { [string]($smb.PSObject.Properties['versions']?.Value) } else { "" }
                $smbEnc   = if ($smb) { [string]($smb.PSObject.Properties['channelEncryption']?.Value) } else { "" }
                $goodVers = @("SMB3.1.1","SMB3.11")
                $goodEnc  = @("AES-256-GCM","AES256GCM")

                if ($smb) {
                    $hasGoodVer = @($smbVers -split '[;, ]' | Where-Object { $goodVers -contains $_.Trim() }).Count -gt 0
                    $results.Add((New-CISResult `
                        -ControlId "9.1.2" -Title "Ensure SMB Access Is Restricted to SMB 3.1.1+" `
                        -Level 1 -Section $sec `
                        -Status $(if ($hasGoodVer) { $script:PASS } else { $script:FAIL }) `
                        -Details "SMB protocol versions: $(if($smbVers){$smbVers}else{'Not configured'})" `
                        -Remediation $(if (-not $hasGoodVer) { "Storage account > $acctName > File shares > SMB settings > Protocol version: SMB 3.1.1" } else { "" }) `
                        -SubscriptionId $sid -SubscriptionName $sname -Resource $acctName))

                    $hasGoodEnc = @($smbEnc -split '[;, ]' | Where-Object { $goodEnc -contains $_.Trim() }).Count -gt 0
                    $results.Add((New-CISResult `
                        -ControlId "9.1.3" -Title "Ensure 'SMB' Channel Encryption Is Set to AES-256-GCM" `
                        -Level 1 -Section $sec `
                        -Status $(if ($hasGoodEnc) { $script:PASS } else { $script:FAIL }) `
                        -Details "SMB channel encryption: $(if($smbEnc){$smbEnc}else{'Not configured'})" `
                        -Remediation $(if (-not $hasGoodEnc) { "Storage account > $acctName > File shares > SMB settings > Channel encryption: AES-256-GCM" } else { "" }) `
                        -SubscriptionId $sid -SubscriptionName $sname -Resource $acctName))
                } else {
                    $results.Add((New-InfoResult "9.1.2" "Ensure SMB Access Is Restricted to SMB 3.1.1+" 1 $sec "No SMB protocolSettings found for this account; SMB protocol may not be applicable." $sid $sname $acctName))
                    $results.Add((New-InfoResult "9.1.3" "Ensure 'SMB' Channel Encryption Is Set to AES-256-GCM" 1 $sec "No SMB protocolSettings found for this account; SMB encryption may not be applicable." $sid $sname $acctName))
                }
            }
        } catch {
            $results.Add((New-ErrorResult "9.1.1" "File Service Soft Delete" 1 $sec $_.Exception.Message $sid $sname $acctName))
            $results.Add((New-ErrorResult "9.1.2" "Ensure SMB Access Is Restricted to SMB 3.1.1+" 1 $sec $_.Exception.Message $sid $sname $acctName))
            $results.Add((New-ErrorResult "9.1.3" "Ensure 'SMB' Channel Encryption Is Set to AES-256-GCM" 1 $sec $_.Exception.Message $sid $sname $acctName))
        }

        # ── Group 4: Key rotation ─────────────────────────────────────────────

        # 9.3.1.1 — Key rotation reminder + 9.3.1.2 — Key rotation < 90 days
        try {
            $r = Invoke-AzCli -Arguments @(
                "storage", "account", "show", "--name", $acctName, "--resource-group", $acctRg,
                "--query", "{keyCreationTime:keyCreationTime,keyExpirationPeriodInDays:keyPolicy.keyExpirationPeriodInDays}"
            ) -SubscriptionId $sid -TimeoutSec $script:TIMEOUTS.default

            if ($r.Success -and $r.Data) {
                $acctData = $r.Data

                # 9.3.1.1 — Key expiration / rotation reminder
                $reminderDays = $acctData.keyExpirationPeriodInDays
                $results.Add((New-CISResult `
                    -ControlId "9.3.1.1" -Title "Ensure Storage Account Key Rotation Reminders Are Enabled" `
                    -Level 1 -Section $sec `
                    -Status $(if ($reminderDays) { $script:PASS } else { $script:FAIL }) `
                    -Details "Account '$acctName': keyExpirationPeriodInDays = $reminderDays" `
                    -Remediation $(if (-not $reminderDays) { "Storage Account > Access keys > Set rotation reminder" } else { "" }) `
                    -SubscriptionId $sid -SubscriptionName $sname -Resource $(if (-not $reminderDays) { $acctName } else { "" })))

                # 9.3.1.2 — Key rotation within 90 days
                $keyTimes = $acctData.keyCreationTime
                if ($keyTimes) {
                    $now      = [datetime]::UtcNow
                    $oldKeys  = [System.Collections.Generic.List[string]]::new()

                    foreach ($prop in @("key1","key2")) {
                        $keyTime = $keyTimes.$prop
                        if ($keyTime) {
                            $created = [datetime]$keyTime
                            $days    = ($now - $created).TotalDays
                            if ($days -gt 90) { $oldKeys.Add("$prop ($([int]$days) days old)") }
                        }
                    }

                    $pass = $oldKeys.Count -eq 0
                    $results.Add((New-CISResult `
                        -ControlId "9.3.1.2" -Title "Ensure That Storage Accounts Are Configured to Use Access Keys Rotated Within 90 Days" `
                        -Level 1 -Section $sec `
                        -Status $(if ($pass) { $script:PASS } else { $script:FAIL }) `
                        -Details $(if ($pass) { "Both access keys rotated within 90 days." } else { "Key(s) not rotated in 90 days: $($oldKeys -join '; ')" }) `
                        -Remediation $(if (-not $pass) { "Storage account > $acctName > Security > Access keys > Rotate key" } else { "" }) `
                        -SubscriptionId $sid -SubscriptionName $sname -Resource $acctName))
                } else {
                    $results.Add((New-ErrorResult "9.3.1.2" "Key Rotation" 1 $sec "Could not retrieve key creation times." $sid $sname $acctName))
                }
            } else {
                $results.Add((New-ErrorResult "9.3.1.1" "Key Rotation Reminder" 1 $sec ($r.Error ?? "Could not retrieve storage account details.") $sid $sname $acctName))
                $results.Add((New-ErrorResult "9.3.1.2" "Key Rotation" 1 $sec ($r.Error ?? "Could not retrieve key creation times.") $sid $sname $acctName))
            }
        } catch {
            $results.Add((New-ErrorResult "9.3.1.1" "Key Rotation Reminder" 1 $sec $_.Exception.Message $sid $sname $acctName))
            $results.Add((New-ErrorResult "9.3.1.2" "Key Rotation" 1 $sec $_.Exception.Message $sid $sname $acctName))
        }
    }

    # ── 9.3.9 / 9.3.11 — Resource locks on storage accounts (subscription-wide)
    # 9.3.9: account is covered by a CanNotDelete OR ReadOnly lock (Level 1)
    # 9.3.11: account is covered by a ReadOnly lock specifically (Level 2)
    try {
        $r = Invoke-AzCli -Arguments @(
            "lock", "list", "--subscription", $sid
        ) -TimeoutSec $script:TIMEOUTS.default

        $locks = @()
        if ($r.Success -and $r.Data) { $locks = @($r.Data) }

        foreach ($acct in $accounts) {
            $acctName = [string]($acct.PSObject.Properties['name']?.Value)
            $acctId   = [string]($acct.PSObject.Properties['id']?.Value)
            $acctRg   = [string]($acct.PSObject.Properties['resourceGroup']?.Value)
            $rgScope  = ($acctId -split '/providers/')[0].ToLower()
            $subScope = "/subscriptions/$sid".ToLower()

            $covering = @()
            $acctScope = $acctId.ToLower()
            foreach ($lk in $locks) {
                $lkId = [string]$lk.id
                $lkIdLower = $lkId.ToLower()
                if ($lkIdLower.StartsWith($acctScope + "/providers/microsoft.authorization/locks/") -or
                    $lkIdLower.StartsWith($rgScope + "/providers/microsoft.authorization/locks/") -or
                    $lkIdLower.StartsWith($subScope + "/providers/microsoft.authorization/locks/")) {
                    $covering += [string]$lk.level
                }
            }
            $coveringLower = @($covering | ForEach-Object { $_.ToLower() })
            $hasDeleteLock = ($coveringLower -contains "cannotdelete" -or $coveringLower -contains "readonly")
            $hasReadOnly   = ($coveringLower -contains "readonly")
            $summary       = if ($covering.Count -gt 0) { "Lock(s) found: $($covering -join ', ')" } else { "No resource locks found at account, RG, or subscription scope." }

            # 9.3.9 — CanNotDelete or ReadOnly lock (protects against accidental deletion)
            $results.Add((New-CISResult `
                -ControlId "9.3.9" -Title "Ensure That Storage Accounts Have a CanNotDelete Resource Lock" `
                -Level 1 -Section $sec `
                -Status $(if ($hasDeleteLock) { $script:PASS } else { $script:FAIL }) `
                -Details "$($acctName): $summary" `
                -Remediation $(if (-not $hasDeleteLock) { "Storage account > $acctName > Locks > Add lock > Lock type: Delete" } else { "" }) `
                -SubscriptionId $sid -SubscriptionName $sname -Resource $acctName))

            # 9.3.10 — ReadOnly lock (full freeze, highest protection)
            $results.Add((New-CISResult `
                -ControlId "9.3.10" -Title "Ensure That Storage Accounts Have a ReadOnly Resource Lock" `
                -Level 2 -Section $sec `
                -Status $(if ($hasReadOnly) { $script:PASS } else { $script:FAIL }) `
                -Details "$($acctName): $summary" `
                -Remediation $(if (-not $hasReadOnly) { "Storage account > $acctName > Locks > Add lock > Lock type: Read-only" } else { "" }) `
                -SubscriptionId $sid -SubscriptionName $sname -Resource $acctName))
        }
    } catch {
        $results.Add((New-ErrorResult "9.3.9" "Resource Locks (CanNotDelete)" 1 $sec $_.Exception.Message $sid $sname))
        $results.Add((New-ErrorResult "9.3.10" "Resource Locks (ReadOnly)" 2 $sec $_.Exception.Message $sid $sname))
    }

    return $results.ToArray()
}
