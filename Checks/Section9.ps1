# Section 9 — Storage Services
# CIS Microsoft Azure Foundations Benchmark v6.0.0

function Invoke-Section9Checks {
    [CmdletBinding()]
    param(
        [string]$SubscriptionId,
        [string]$SubscriptionName,
        [hashtable]$PrefetchData
    )

    $results  = [System.Collections.Generic.List[object]]::new()
    $sid      = $SubscriptionId
    $sname    = $SubscriptionName

    $accounts = @(Get-PrefetchData -PrefetchData $PrefetchData -Key "storage" -SubscriptionId $sid)
    $storErr  = Get-PrefetchError -PrefetchData $PrefetchData -Key "storage"

    # Fallback: if the "storage" key was never prefetched, or the prefetch query
    # failed, try reading storage accounts directly before giving up.
    if ($accounts.Count -eq 0 -and ($storErr -or -not $PrefetchData.ContainsKey("storage"))) {
        $rawAccts = @(Get-AzStorageAccount -ErrorAction SilentlyContinue)
        if ($rawAccts.Count -gt 0) {
            $storErr  = $null   # direct read succeeded — prefetch failure no longer masks data
            $accounts = @($rawAccts | Select-Object `
                @{N='id';E={$_.Id}},
                @{N='name';E={$_.StorageAccountName}},
                @{N='resourceGroup';E={$_.ResourceGroupName}},
                @{N='isHns';E={[string]$_.EnableHierarchicalNamespace}},
                @{N='sku';E={$_.Sku.Name}})
        }
    }

    if ($accounts.Count -eq 0) {
        $storageControlIds = @(
            "9.1.1","9.1.2","9.1.3",
            "9.2.1","9.2.2","9.2.3",
            "9.3.1.1","9.3.1.2","9.3.1.3","9.3.2.1","9.3.2.2","9.3.2.3","9.3.3.1",
            "9.3.4","9.3.5","9.3.6","9.3.7","9.3.8","9.3.9","9.3.10","9.3.11"
        )
        foreach ($cid in $storageControlIds) {
            if ($storErr) {
                $results.Add((New-ErrorResult $cid "Storage prefetch failed and direct read returned no data: $storErr" $sid $sname))
            } else {
                $results.Add((New-InfoResult $cid "No storage accounts found." $sid $sname))
            }
        }
        return $results.ToArray()
    }

    foreach ($acct in $accounts) {
        $acctName = [string]($acct.PSObject.Properties['name']?.Value)
        $acctId   = [string]($acct.PSObject.Properties['id']?.Value)
        $acctRg   = [string]($acct.PSObject.Properties['resourceGroup']?.Value)

        # ── Group 1: Static checks from Resource Graph ────────────────────────

        # 9.3.4 — Secure transfer required (HTTPS only)
        $httpsOnly = [string]($acct.PSObject.Properties['httpsOnly']?.Value)
        $httpsOk   = $httpsOnly -eq "true" -or $httpsOnly -eq "True"
        $results.Add((New-CISResult `
            -ControlId "9.3.4" `
            -Status $(if ($httpsOk) { $script:PASS } else { $script:FAIL }) `
            -Details $(if ($httpsOk) { "Secure transfer (HTTPS only): Required." } else { "Secure transfer (HTTPS only): Not required — HTTP connections are allowed." }) `
            -Remediation $(if (-not $httpsOk) { "Storage account > $acctName > Configuration > Require secure transfer > Enabled" } else { "" }) `
            -SubscriptionId $sid -SubscriptionName $sname -Resource $acctName))

        # 9.3.8 — No anonymous blob public access
        $blobAnon    = [string]($acct.PSObject.Properties['blobAnon']?.Value)
        $anonDisabled = $blobAnon -eq "false" -or $blobAnon -eq "False"
        $results.Add((New-CISResult `
            -ControlId "9.3.8" `
            -Status $(if ($anonDisabled) { $script:PASS } else { $script:FAIL }) `
            -Details $(if ($anonDisabled) { "Blob public access: Disabled." } else { "Blob public access: Enabled — anonymous access to blob containers is allowed." }) `
            -Remediation $(if (-not $anonDisabled) { "Storage account > $acctName > Configuration > Allow Blob public access > Disabled" } else { "" }) `
            -SubscriptionId $sid -SubscriptionName $sname -Resource $acctName))

        # 9.3.7 — Cross-tenant replication disabled
        $crossTenant    = [string]($acct.PSObject.Properties['crossTenant']?.Value)
        # Null/empty means disabled (Azure default); only explicit "true" means enabled
        $crossTenantOff = $crossTenant -ne "true" -and $crossTenant -ne "True"
        $results.Add((New-CISResult `
            -ControlId "9.3.7" `
            -Status $(if ($crossTenantOff) { $script:PASS } else { $script:FAIL }) `
            -Details $(if ($crossTenantOff) { "Cross-tenant replication: Disabled." } else { "Cross-tenant replication: Enabled — data can be replicated to storage accounts in other tenants." }) `
            -Remediation $(if (-not $crossTenantOff) { "Storage account > $acctName > Object replication > Disable cross-tenant replication" } else { "" }) `
            -SubscriptionId $sid -SubscriptionName $sname -Resource $acctName))

        # 9.3.1.3 — Shared Key access disabled
        $keyAccess    = [string]($acct.PSObject.Properties['keyAccess']?.Value)
        $keyAccessOff = $keyAccess -eq "false" -or $keyAccess -eq "False"
        $results.Add((New-CISResult `
            -ControlId "9.3.1.3" `
            -Status $(if ($keyAccessOff) { $script:PASS } else { $script:FAIL }) `
            -Details $(if ($keyAccessOff) { "Shared key (storage account key) access: Disabled." } else { "Shared key (storage account key) access: Enabled — disable to enforce Entra ID authentication." }) `
            -Remediation $(if (-not $keyAccessOff) { "Storage account > $acctName > Configuration > Allow storage account key access > Disabled" } else { "" }) `
            -SubscriptionId $sid -SubscriptionName $sname -Resource $acctName))

        # 9.3.3.1 — Default to Entra ID (OAuth) authorization
        $oauthDefault   = [string]($acct.PSObject.Properties['oauthDefault']?.Value)
        $oauthDefaultOn = $oauthDefault -eq "true" -or $oauthDefault -eq "True"
        $results.Add((New-CISResult `
            -ControlId "9.3.3.1" `
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
            -ControlId "9.3.2.2" `
            -Status $(if ($pubDisabled) { $script:PASS } else { $script:FAIL }) `
            -Details "publicNetworkAccess = $(if ($pubAccess) { $pubAccess } else { 'null (not explicitly disabled — effective: Enabled)' })" `
            -Remediation $(if (-not $pubDisabled) { "Storage account > $acctName > Networking > Public network access > Disabled" } else { "" }) `
            -SubscriptionId $sid -SubscriptionName $sname -Resource $acctName))

        # 9.3.2.3 — Default network ACL action must be "Deny"
        $denyDefault = $defaultAction -eq "Deny"
        $results.Add((New-CISResult `
            -ControlId "9.3.2.3" `
            -Status $(if ($denyDefault) { $script:PASS } else { $script:FAIL }) `
            -Details "networkAcls.defaultAction = $defaultAction" `
            -Remediation $(if (-not $denyDefault) { "Storage account > $acctName > Networking > Firewall and virtual networks > Default action: Deny" } else { "" }) `
            -SubscriptionId $sid -SubscriptionName $sname -Resource $acctName))

        # 9.3.6 — TLS 1.2+
        $minTls  = [string]($acct.PSObject.Properties['minTls']?.Value)
        $tlsOk   = $minTls -match "TLS1_2|TLS1_3"
        $results.Add((New-CISResult `
            -ControlId "9.3.6" `
            -Status $(if ($tlsOk) { $script:PASS } else { $script:FAIL }) `
            -Details $(if ($tlsOk) { "Minimum TLS version: $minTls." } else { "Minimum TLS version: $minTls — must be TLS 1.2 or higher." }) `
            -Remediation $(if (-not $tlsOk) { "Storage account > $acctName > Configuration > Minimum TLS version > TLS 1.2" } else { "" }) `
            -SubscriptionId $sid -SubscriptionName $sname -Resource $acctName))

        # 9.3.5 — Trusted Azure services bypass
        $bypassOk = $bypass -match "azureservices"
        $results.Add((New-CISResult `
            -ControlId "9.3.5" `
            -Status $(if ($bypassOk) { $script:PASS } else { $script:FAIL }) `
            -Details $(if ($bypassOk) { "networkAcls.bypass includes AzureServices." } else { "networkAcls.bypass: $([string]($acct.PSObject.Properties['bypass']?.Value)) — AzureServices not listed." }) `
            -Remediation $(if (-not $bypassOk) { "Storage account > $acctName > Networking > Exceptions > Allow Azure services on the trusted services list." } else { "" }) `
            -SubscriptionId $sid -SubscriptionName $sname -Resource $acctName))

        # 9.3.11 — Geo-redundant storage (GRS)
        $results.Add((New-CISResult `
            -ControlId "9.3.11" `
            -Status $(if ($isGrs) { $script:PASS } else { $script:FAIL }) `
            -Details "Storage SKU: $acctSku$(if (-not $isGrs) { ' — not geo-redundant' } else { '' })" `
            -Remediation $(if (-not $isGrs) { "Storage account > $acctName > Data Management > Redundancy > Select GRS, GZRS, RA-GRS, or RA-GZRS." } else { "" }) `
            -SubscriptionId $sid -SubscriptionName $sname -Resource $acctName))

        # 9.3.2.1 — Private endpoints
        $privateEps = [int]($acct.PSObject.Properties['privateEps']?.Value)
        $results.Add((New-CISResult `
            -ControlId "9.3.2.1" `
            -Status $(if ($privateEps -gt 0) { $script:PASS } else { $script:FAIL }) `
            -Details $(if ($privateEps -gt 0) { "Private endpoints: $privateEps configured." } else { "Private endpoints: $privateEps — at least one private endpoint is required." }) `
            -Remediation $(if ($privateEps -eq 0) { "Storage account > $acctName > Networking > Private endpoint connections > Add" } else { "" }) `
            -SubscriptionId $sid -SubscriptionName $sname -Resource $acctName))

        # ── Group 2: Blob service properties (dynamic call per account) ───────

        # Skip blob/file checks for Azure Data Lake Storage Gen2 (HNS-enabled accounts
        # do not expose a separate blob service properties API).
        # Use the isHns property from Resource Graph to detect ADLS Gen2 accounts.
        $isHnsProp = [string]($acct.PSObject.Properties['isHns']?.Value)
        $isAdls = $isHnsProp -eq 'true' -or $isHnsProp -eq 'True'

        if (-not $isAdls) {
            try {
                $bp = Invoke-WithRetry -OperationName "blob service properties ($acctName)" -ScriptBlock {
                    Get-AzStorageBlobServiceProperty -ResourceGroupName $acctRg -StorageAccountName $acctName -ErrorAction Stop
                }

                # 9.2.1 — Blob soft delete enabled
                $softDelOn  = [bool]($bp.DeleteRetentionPolicy?.Enabled)
                $retDays    = [int]($bp.DeleteRetentionPolicy?.Days ?? 0)
                $blobSdOk   = $softDelOn -and $retDays -ge 7
                $results.Add((New-CISResult `
                    -ControlId "9.2.1" `
                    -Status $(if ($blobSdOk) { $script:PASS } else { $script:FAIL }) `
                    -Details "Blob soft delete: enabled=$softDelOn, days=$retDays" `
                    -Remediation $(if (-not $blobSdOk) { "Storage account > $acctName > Data management > Data protection > Enable soft delete for blobs (>= 7 days)" } else { "" }) `
                    -SubscriptionId $sid -SubscriptionName $sname -Resource $acctName))

                # 9.2.2 — Container soft delete enabled
                $conDelOn  = [bool]($bp.ContainerDeleteRetentionPolicy?.Enabled)
                $conDays   = [int]($bp.ContainerDeleteRetentionPolicy?.Days ?? 0)
                $conOk     = $conDelOn -and $conDays -ge 7
                $results.Add((New-CISResult `
                    -ControlId "9.2.2" `
                    -Status $(if ($conOk) { $script:PASS } else { $script:FAIL }) `
                    -Details "Container soft delete: enabled=$conDelOn, days=$conDays" `
                    -Remediation $(if (-not $conOk) { "Storage account > $acctName > Data management > Data protection > Enable soft delete for containers (>= 7 days)" } else { "" }) `
                    -SubscriptionId $sid -SubscriptionName $sname -Resource $acctName))

                # 9.2.3 — Blob versioning enabled
                $versionOn = [bool]$bp.IsVersioningEnabled
                $results.Add((New-CISResult `
                    -ControlId "9.2.3" `
                    -Status $(if ($versionOn) { $script:PASS } else { $script:FAIL }) `
                    -Details "Blob versioning: $(if($versionOn){'Enabled'}else{'Disabled'})" `
                    -Remediation $(if (-not $versionOn) { "Storage account > $acctName > Data management > Data protection > Enable blob versioning" } else { "" }) `
                    -SubscriptionId $sid -SubscriptionName $sname -Resource $acctName))

            } catch {
                Add-ClassifiedErrorSet -Results $results -ControlIds @("9.2.1","9.2.2","9.2.3") -Message $_.Exception.Message `
                    -NotApplicableMessage "Blob service not supported for this account type." `
                    -AuthzMessage "Insufficient permissions to read blob service properties." `
                    -FirewallMessage "Storage account firewall or network configuration is blocking access. Verify that the storage account is accessible from the audit machine." `
                    -SubscriptionId $sid -SubscriptionName $sname -Resource $acctName
            }
        } else {
            foreach ($cid in @("9.2.1","9.2.2","9.2.3")) {
                $results.Add((New-InfoResult $cid "ADLS Gen2 — blob service properties API not applicable." $sid $sname $acctName))
            }
        }

        # ── Group 3: File service soft delete ─────────────────────────────────

        # 9.1.1 — File share soft delete
        try {
            $fp = Invoke-WithRetry -OperationName "file service properties ($acctName)" -ScriptBlock {
                Get-AzStorageFileServiceProperty -ResourceGroupName $acctRg -StorageAccountName $acctName -ErrorAction Stop
            }

            $fsDelOn = $fp.ShareDeleteRetentionPolicy?.Enabled
            $fsDays  = [int]($fp.ShareDeleteRetentionPolicy?.Days)
            $fsOk    = $fsDelOn -and $fsDays -ge 7

            $results.Add((New-CISResult `
                -ControlId "9.1.1" `
                -Status $(if ($fsOk) { $script:PASS } else { $script:FAIL }) `
                -Details "File share soft delete: enabled=$fsDelOn, days=$fsDays" `
                -Remediation $(if (-not $fsOk) { "Storage account > $acctName > Data management > Data protection > Enable soft delete for file shares (>= 7 days)" } else { "" }) `
                -SubscriptionId $sid -SubscriptionName $sname -Resource $acctName))

            # 9.1.2 — SMB protocol version >= 3.1.1
            # 9.1.3 — SMB channel encryption AES-256-GCM or higher
            $smb     = $fp.ProtocolSettings?.Smb
            $smbVers = if ($smb) { [string]$smb.Versions } else { "" }
            $smbEnc  = if ($smb) { [string]$smb.ChannelEncryption } else { "" }
            $goodVers = @("SMB3.1.1","SMB3.11")
            $goodEnc  = @("AES-256-GCM","AES256GCM")

            if ($smb) {
                $hasGoodVer = @($smbVers -split '[;, ]' | Where-Object { $goodVers -contains $_.Trim() }).Count -gt 0
                $results.Add((New-CISResult `
                    -ControlId "9.1.2" `
                    -Status $(if ($hasGoodVer) { $script:PASS } else { $script:FAIL }) `
                    -Details "SMB protocol versions: $(if($smbVers){$smbVers}else{'Not configured'})" `
                    -Remediation $(if (-not $hasGoodVer) { "Storage account > $acctName > File shares > SMB settings > Protocol version: SMB 3.1.1" } else { "" }) `
                    -SubscriptionId $sid -SubscriptionName $sname -Resource $acctName))

                $hasGoodEnc = @($smbEnc -split '[;, ]' | Where-Object { $goodEnc -contains $_.Trim() }).Count -gt 0
                $results.Add((New-CISResult `
                    -ControlId "9.1.3" `
                    -Status $(if ($hasGoodEnc) { $script:PASS } else { $script:FAIL }) `
                    -Details "SMB channel encryption: $(if($smbEnc){$smbEnc}else{'Not configured'})" `
                    -Remediation $(if (-not $hasGoodEnc) { "Storage account > $acctName > File shares > SMB settings > Channel encryption: AES-256-GCM" } else { "" }) `
                    -SubscriptionId $sid -SubscriptionName $sname -Resource $acctName))
            } else {
                $results.Add((New-InfoResult "9.1.2" "No SMB protocolSettings found for this account; SMB protocol may not be applicable." $sid $sname $acctName))
                $results.Add((New-InfoResult "9.1.3" "No SMB protocolSettings found for this account; SMB encryption may not be applicable." $sid $sname $acctName))
            }
        } catch {
            Add-ClassifiedErrorSet -Results $results -ControlIds @("9.1.1","9.1.2","9.1.3") -Message $_.Exception.Message `
                -NotApplicableMessage "File service not supported for this account type." `
                -AuthzMessage "Insufficient permissions to read file service properties." `
                -FirewallMessage "Storage account firewall or network configuration is blocking access." `
                -SubscriptionId $sid -SubscriptionName $sname -Resource $acctName
        }

        # ── Group 4: Key rotation ─────────────────────────────────────────────

        # 9.3.1.1 — Key rotation reminder + 9.3.1.2 — Key rotation < 90 days
        try {
            $saAcct = Get-AzStorageAccount -Name $acctName -ResourceGroupName $acctRg -ErrorAction Stop

            # 9.3.1.1 — Key expiration / rotation reminder
            $reminderDays = $saAcct.KeyPolicy?.KeyExpirationPeriodInDays
            $results.Add((New-CISResult `
                -ControlId "9.3.1.1" `
                -Status $(if ($reminderDays) { $script:PASS } else { $script:FAIL }) `
                -Details "Account '$acctName': keyExpirationPeriodInDays = $(if ($null -ne $reminderDays -and $reminderDays -ne '') { $reminderDays } else { '(not configured)' })" `
                -Remediation $(if (-not $reminderDays) { "Storage Account > Access keys > Set rotation reminder" } else { "" }) `
                -SubscriptionId $sid -SubscriptionName $sname -Resource $(if (-not $reminderDays) { $acctName } else { "" })))

            # 9.3.1.2 — Key rotation within 90 days
            $keyTimes = $saAcct.KeyCreationTime
            if ($keyTimes) {
                $now      = [datetime]::UtcNow
                $oldKeys  = [System.Collections.Generic.List[string]]::new()

                foreach ($prop in @("Key1","Key2")) {
                    $keyTime = $keyTimes.PSObject.Properties[$prop]?.Value
                    if ($keyTime) {
                        $created = [datetime]$keyTime
                        $days    = ($now - $created).TotalDays
                        if ($days -gt 90) { $oldKeys.Add("$prop ($([int]$days) days old)") }
                    }
                }

                $pass = $oldKeys.Count -eq 0
                $results.Add((New-CISResult `
                    -ControlId "9.3.1.2" `
                    -Status $(if ($pass) { $script:PASS } else { $script:FAIL }) `
                    -Details $(if ($pass) { "Both access keys rotated within 90 days." } else { "Key(s) not rotated in 90 days: $($oldKeys -join '; ')" }) `
                    -Remediation $(if (-not $pass) { "Storage account > $acctName > Security > Access keys > Rotate key" } else { "" }) `
                    -SubscriptionId $sid -SubscriptionName $sname -Resource $acctName))
            } else {
                $results.Add((New-ErrorResult "9.3.1.2" "Could not retrieve key creation times." $sid $sname $acctName))
            }
        } catch {
            $results.Add((New-ErrorResult "9.3.1.1" $_.Exception.Message $sid $sname $acctName))
            $results.Add((New-ErrorResult "9.3.1.2" $_.Exception.Message $sid $sname $acctName))
        }
    }

    # ── 9.3.9 / 9.3.10 — Resource locks on storage accounts (subscription-wide)
    # 9.3.9: account is covered by a CanNotDelete OR ReadOnly lock (Level 1)
    # 9.3.10: account is covered by a ReadOnly lock specifically (Level 2)
    try {
        # -ErrorAction Stop: a failed lock read must ERROR 9.3.9/9.3.10 in the catch,
        # not FAIL every account with 'no locks found'.
        $locks = @(Get-AzResourceLock -ErrorAction Stop)
        if (-not $locks) { $locks = @() }

        foreach ($acct in $accounts) {
            $acctName = [string]($acct.PSObject.Properties['name']?.Value)
            $acctId   = [string]($acct.PSObject.Properties['id']?.Value)
            $acctRg   = [string]($acct.PSObject.Properties['resourceGroup']?.Value)
            $rgScope  = ($acctId -split '/providers/')[0].ToLower()
            $subScope = "/subscriptions/$sid".ToLower()

            $covering = @()
            $acctScope = $acctId.ToLower()
            foreach ($lk in $locks) {
                $lkId = [string]$lk.LockId
                $lkIdLower = $lkId.ToLower()
                if ($lkIdLower.StartsWith($acctScope + "/providers/microsoft.authorization/locks/") -or
                    $lkIdLower.StartsWith($rgScope + "/providers/microsoft.authorization/locks/") -or
                    $lkIdLower.StartsWith($subScope + "/providers/microsoft.authorization/locks/")) {
                    $covering += [string]$lk.Level
                }
            }
            $coveringLower = @($covering | ForEach-Object { $_.ToLower() })
            $hasDeleteLock = ($coveringLower -contains "cannotdelete" -or $coveringLower -contains "readonly")
            $hasReadOnly   = ($coveringLower -contains "readonly")
            $summary       = if ($covering.Count -gt 0) { "Lock(s) found: $($covering -join ', ')" } else { "No resource locks found at account, RG, or subscription scope." }

            # 9.3.9 — CanNotDelete or ReadOnly lock (protects against accidental deletion)
            $results.Add((New-CISResult `
                -ControlId "9.3.9" `
                -Status $(if ($hasDeleteLock) { $script:PASS } else { $script:FAIL }) `
                -Details "$($acctName): $summary" `
                -Remediation $(if (-not $hasDeleteLock) { "Storage account > $acctName > Locks > Add lock > Lock type: Delete" } else { "" }) `
                -SubscriptionId $sid -SubscriptionName $sname -Resource $acctName))

            # 9.3.10 — ReadOnly lock (full freeze, highest protection)
            $results.Add((New-CISResult `
                -ControlId "9.3.10" `
                -Status $(if ($hasReadOnly) { $script:PASS } else { $script:FAIL }) `
                -Details "$($acctName): $summary" `
                -Remediation $(if (-not $hasReadOnly) { "Storage account > $acctName > Locks > Add lock > Lock type: Read-only" } else { "" }) `
                -SubscriptionId $sid -SubscriptionName $sname -Resource $acctName))
        }
    } catch {
        $results.Add((New-ErrorResult "9.3.9" $_.Exception.Message $sid $sname))
        $results.Add((New-ErrorResult "9.3.10" $_.Exception.Message $sid $sname))
    }

    return $results.ToArray()
}
