# Section 8 — Security Services
# CIS Microsoft Azure Foundations Benchmark v5.0.0

function Invoke-Section8Checks {
    [CmdletBinding()]
    param(
        [string]$SubscriptionId,
        [string]$SubscriptionName,
        [hashtable]$PrefetchData
    )

    $results = [System.Collections.Generic.List[object]]::new()
    $sec     = "8 - Security Services"
    $sid     = $SubscriptionId
    $sname   = $SubscriptionName

    $keyvaults = @(Get-PrefetchData -PrefetchData $PrefetchData -Key "keyvaults" -SubscriptionId $sid)
    $vnets     = @(Get-PrefetchData -PrefetchData $PrefetchData -Key "vnets"     -SubscriptionId $sid)
    $vms       = @(Get-PrefetchData -PrefetchData $PrefetchData -Key "vms"       -SubscriptionId $sid)
    $bastion   = @(Get-PrefetchData -PrefetchData $PrefetchData -Key "bastion"   -SubscriptionId $sid)

    # ── 8.1.x — Microsoft Defender plans ─────────────────────────────────────
    $defenderPlans = @(
        @{ Id="8.1.1.1"; Plan="CloudPosture";                 Title="Ensure Microsoft Defender CSPM Is Set to 'On'" }
        @{ Id="8.1.2.1"; Plan="Api";                          Title="Ensure Microsoft Defender for APIs Is Set to 'On'" }
        @{ Id="8.1.3.1"; Plan="VirtualMachines";              Title="Ensure Microsoft Defender for Servers Is Set to 'On'" }
        @{ Id="8.1.4.1"; Plan="Containers";                   Title="Ensure Microsoft Defender for Containers Is Set to 'On'" }
        @{ Id="8.1.5.1"; Plan="StorageAccounts";              Title="Ensure Microsoft Defender for Storage Is Set to 'On'" }
        @{ Id="8.1.6.1"; Plan="AppServices";                  Title="Ensure Microsoft Defender for App Service Is Set to 'On'" }
        @{ Id="8.1.7.1"; Plan="CosmosDbs";                    Title="Ensure Microsoft Defender for Azure Cosmos DB Is Set to 'On'" }
        @{ Id="8.1.7.2"; Plan="OpenSourceRelationalDatabases";Title="Ensure Microsoft Defender for Open-Source Relational Databases Is Set to 'On'" }
        @{ Id="8.1.7.3"; Plan="SqlServers";                   Title="Ensure Microsoft Defender for Azure SQL Databases Is Set to 'On'" }
        @{ Id="8.1.7.4"; Plan="SqlServerVirtualMachines";     Title="Ensure Microsoft Defender for SQL Servers on Machines Is Set to 'On'" }
        @{ Id="8.1.8.1"; Plan="KeyVaults";                    Title="Ensure Microsoft Defender for Key Vault Is Set to 'On'" }
        @{ Id="8.1.9.1"; Plan="Arm";                          Title="Ensure Microsoft Defender for Resource Manager Is Set to 'On'" }
    )

    foreach ($plan in $defenderPlans) {
        try {
            $r = Invoke-AzCli -Arguments @(
                "security", "pricing", "show", "--name", $plan.Plan
            ) -SubscriptionId $sid -TimeoutSec $script:TIMEOUTS.default

            if (-not $r.Success) {
                $results.Add((New-ErrorResult $plan.Id $plan.Title 2 $sec $r.Error $sid $sname))
                continue
            }

            $tier    = [string]$r.Data.pricingTier
            $enabled = $tier -eq "Standard"
            $results.Add((New-CISResult `
                -ControlId $plan.Id `
                -Title     $plan.Title `
                -Level 2 -Section $sec `
                -Status $(if ($enabled) { $script:PASS } else { $script:FAIL }) `
                -Details $(if ($enabled) { "Microsoft Defender pricing tier: Standard (enabled)." } else { "Microsoft Defender pricing tier: $tier — must be upgraded to Standard." }) `
                -Remediation $(if (-not $enabled) { "Defender for Cloud > Environment Settings > $($plan.Plan) > Enable" } else { "" }) `
                -SubscriptionId $sid -SubscriptionName $sname))
        } catch {
            $results.Add((New-ErrorResult $plan.Id $plan.Title 2 $sec $_.Exception.Message $sid $sname))
        }
    }

    # ── 8.1.3.3 — WDATP / MDE integration ────────────────────────────────────
    try {
        $url = "https://management.azure.com/subscriptions/$sid/providers/Microsoft.Security/settings/WDATP?api-version=2021-06-01"
        $r   = Invoke-AzRest -Uri $url -TimeoutSec $script:TIMEOUTS.default

        if (-not $r.Success) {
            $results.Add((New-ErrorResult "8.1.3.3" "Ensure That Microsoft Defender for Endpoint Integration With Microsoft Defender for Cloud Is Enabled" 1 $sec $r.Error $sid $sname))
        } else {
            $enabled = [string]$r.Data.properties.enabled -eq "True" -or [string]$r.Data.properties.enabled -eq "true"
            $results.Add((New-CISResult `
                -ControlId "8.1.3.3" `
                -Title "Ensure That Microsoft Defender for Endpoint Integration With Microsoft Defender for Cloud Is Enabled" `
                -Level 1 -Section $sec `
                -Status $(if ($enabled) { $script:PASS } else { $script:FAIL }) `
                -Details $(if ($enabled) { "Microsoft Defender for Endpoint integration: Enabled." } else { "Microsoft Defender for Endpoint integration: Disabled." }) `
                -Remediation $(if (-not $enabled) { "Defender for Cloud > Environment Settings > Integrations > Enable MDE integration" } else { "" }) `
                -SubscriptionId $sid -SubscriptionName $sname))
        }
    } catch {
        $results.Add((New-ErrorResult "8.1.3.3" "MDE Integration" 1 $sec $_.Exception.Message $sid $sname))
    }

    # ── 8.1.10 — MDE TVM VM OS update check ──────────────────────────────────
    try {
        $url = "https://management.azure.com/subscriptions/$sid/providers/Microsoft.Security/serverVulnerabilityAssessmentsSettings?api-version=2023-05-01"
        $r   = Invoke-AzRest -Uri $url -TimeoutSec $script:TIMEOUTS.default

        if (-not $r.Success) {
            $results.Add((New-ErrorResult "8.1.10" "Ensure That Microsoft Defender for Cloud Is Set to Assess VMs for OS Updates" 1 $sec $r.Error $sid $sname))
        } else {
            $settingsArr = $r.Data.PSObject.Properties['value']?.Value
            $settings    = if ($settingsArr) { @($settingsArr) } else { @() }
            $enabled  = @($settings | Where-Object {
                $props = $_.PSObject.Properties['properties']?.Value
                $props -and [string]($props.PSObject.Properties['selectedProvider']?.Value) -eq "MdeTvm"
            }).Count -gt 0
            $results.Add((New-CISResult `
                -ControlId "8.1.10" `
                -Title "Ensure That Microsoft Defender for Cloud Is Set to Assess VMs for OS Updates" `
                -Level 1 -Section $sec `
                -Status $(if ($enabled) { $script:PASS } else { $script:FAIL }) `
                -Details $(if ($enabled) { "MDE TVM vulnerability assessment: enabled." } else { "MDE TVM vulnerability assessment: NOT enabled." }) `
                -Remediation $(if (-not $enabled) { "Defender for Cloud > Environment settings > VM vulnerability assessment: Microsoft Defender Vulnerability Management." } else { "" }) `
                -SubscriptionId $sid -SubscriptionName $sname))
        }
    } catch {
        $results.Add((New-ErrorResult "8.1.10" "VM OS Update Assessment" 1 $sec $_.Exception.Message $sid $sname))
    }

    # ── 8.1.12–8.1.15 — Security contact notifications (preview REST API) ──────
    # Uses 2023-12-01-preview directly — it returns all data needed for all 4 checks.
    try {
        $previewUrl  = "https://management.azure.com/subscriptions/$sid/providers/Microsoft.Security/securityContacts?api-version=2023-12-01-preview"
        $r2          = Invoke-AzRest -Uri $previewUrl -TimeoutSec $script:TIMEOUTS.default
        $contactItems = @()
        if ($r2.Success -and $r2.Data) {
            $valProp = $r2.Data.PSObject.Properties['value']
            if ($valProp) { $contactItems = @($valProp.Value) }
        }

        # 8.1.12 — properties.notificationsByRole.roles must contain "Owner"
        $ownersNotified = @($contactItems | Where-Object {
            $props    = $_.PSObject.Properties['properties']?.Value
            if (-not $props) { return $false }
            $nbr      = $props.PSObject.Properties['notificationsByRole']?.Value
            if (-not $nbr) { return $false }
            $roleList = $nbr.PSObject.Properties['roles']?.Value
            if (-not $roleList) { return $false }
            ($roleList | ForEach-Object { [string]$_ }) -contains "Owner"
        }).Count -gt 0

        $results.Add((New-CISResult `
            -ControlId "8.1.12" `
            -Title "Ensure That 'All Users with the Following Roles' Is Set to 'Owner'" `
            -Level 1 -Section $sec `
            -Status $(if ($ownersNotified) { $script:PASS } else { $script:FAIL }) `
            -Details $(if ($ownersNotified) { "Owner role configured for security alert notifications." } else { "Owner role NOT configured for notifications." }) `
            -Remediation $(if (-not $ownersNotified) { "Defender for Cloud > Environment Settings > Email notifications > All users with Owner role." } else { "" }) `
            -SubscriptionId $sid -SubscriptionName $sname))

        # 8.1.13 — properties.emails must be non-empty
        $hasEmail = @($contactItems | Where-Object {
            $props = $_.PSObject.Properties['properties']?.Value
            if (-not $props) { return $false }
            $e = $props.PSObject.Properties['emails']?.Value
            [string]$e -ne ""
        }).Count -gt 0

        $results.Add((New-CISResult `
            -ControlId "8.1.13" `
            -Title "Ensure a Security Contact Email Is Set for Microsoft Defender for Cloud Notifications" `
            -Level 1 -Section $sec `
            -Status $(if ($hasEmail) { $script:PASS } else { $script:FAIL }) `
            -Details $(if ($hasEmail) { "Additional email address(es) configured." } else { "No additional email addresses configured." }) `
            -Remediation $(if (-not $hasEmail) { "Defender for Cloud > Environment Settings > Email notifications > Additional email addresses." } else { "" }) `
            -SubscriptionId $sid -SubscriptionName $sname))

        # 8.1.14 — properties.notificationsByRole.state must be "On"
        $alertOn = @($contactItems | Where-Object {
            $props = $_.PSObject.Properties['properties']?.Value
            $nbr   = if ($props) { $props.PSObject.Properties['notificationsByRole']?.Value } else { $null }
            $state = if ($nbr)   { [string]($nbr.PSObject.Properties['state']?.Value) } else { "" }
            $state -eq "On"
        }).Count -gt 0

        $results.Add((New-CISResult `
            -ControlId "8.1.14" `
            -Title "Ensure That 'Send Notifications About Alerts with Severity High or Above' Is Set to 'On'" `
            -Level 1 -Section $sec `
            -Status $(if ($alertOn) { $script:PASS } else { $script:FAIL }) `
            -Details $(if ($alertOn) { "Alert notification state: On." } else { "Alert notification state is not 'On'." }) `
            -Remediation $(if (-not $alertOn) { "Defender for Cloud > Environment Settings > Email notifications > Notify about alerts with severity: High." } else { "" }) `
            -SubscriptionId $sid -SubscriptionName $sname))

        # 8.1.15 — properties.notificationsSources must have sourceType == "AttackPath"
        $attackOn = $false
        foreach ($ci in $contactItems) {
            $props   = $ci.PSObject.Properties['properties']?.Value
            if (-not $props) { continue }
            $srcProp = $props.PSObject.Properties['notificationsSources']
            if (-not $srcProp) { continue }
            $sources = @($srcProp.Value)
            foreach ($src in $sources) {
                $sourceType = [string]($src.PSObject.Properties['sourceType']?.Value)
                if ($sourceType -eq "AttackPath") { $attackOn = $true; break }
            }
            if ($attackOn) { break }
        }

        $results.Add((New-CISResult `
            -ControlId "8.1.15" `
            -Title "Ensure That Attack Path Notifications Are Configured" `
            -Level 1 -Section $sec `
            -Status $(if ($attackOn) { $script:PASS } else { $script:FAIL }) `
            -Details $(if ($attackOn) { "Attack path notifications configured." } else { "Attack path notifications NOT configured." }) `
            -Remediation $(if (-not $attackOn) { "Defender for Cloud > Environment Settings > Email notifications > Notify about attack paths with risk level: Critical." } else { "" }) `
            -SubscriptionId $sid -SubscriptionName $sname))

    } catch {
        foreach ($cid in @("8.1.12","8.1.13","8.1.14","8.1.15")) {
            $results.Add((New-ErrorResult $cid "Security Contact" 1 $sec $_.Exception.Message $sid $sname))
        }
    }

    # ── 8.3.x — Key Vault checks ──────────────────────────────────────────────
    if ($keyvaults.Count -eq 0) {
        foreach ($cid in @("8.3.1","8.3.2","8.3.3","8.3.4","8.3.5","8.3.6","8.3.7","8.3.8","8.3.9","8.3.11")) {
            $results.Add((New-InfoResult $cid "Key Vault Check" 2 $sec "No Key Vaults found." $sid $sname))
        }
    } else {
        foreach ($kv in $keyvaults) {
            $kvName = [string]$kv.name

            # Static checks from Resource Graph data
            $purge = [string]$kv.purgeProtection -eq "True" -or [string]$kv.purgeProtection -eq "true"
            $rbac  = [string]$kv.rbac            -eq "True" -or [string]$kv.rbac            -eq "true"
            $pub   = [string]$kv.publicAccess
            $eps   = [int]($kv.privateEps)

            # 8.3.1/8.3.2 — Key expiration set (RBAC vs access-policy vault)
            $ctrlKeyExp = if ($rbac) { "8.3.1" } else { "8.3.2" }
            $cachedKeys = $null   # cache for reuse in 8.3.9
            $cachedKeyResult = $null
            try {
                $r = Invoke-AzCli -Arguments @(
                    "keyvault", "key", "list", "--vault-name", $kvName
                ) -TimeoutSec $script:TIMEOUTS.default
                $cachedKeyResult = $r

                if (-not $r.Success) {
                    if (Test-AuthzError $r.Error) {
                        $results.Add((New-ErrorResult $ctrlKeyExp "Ensure That the Expiration Date Is Set on All Keys" 1 $sec "Insufficient permissions to list keys. Grant the 'Key Vault Reader' data-plane role or a Key Vault access policy with Key List permission." $sid $sname $kvName))
                    } elseif (Test-FirewallError $r.Error) {
                        $results.Add((New-ErrorResult $ctrlKeyExp "Ensure That the Expiration Date Is Set on All Keys" 1 $sec "Key Vault firewall is blocking access. Add the audit machine's IP to the vault's firewall allowlist." $sid $sname $kvName))
                    } else {
                        $results.Add((New-ErrorResult $ctrlKeyExp "Ensure That the Expiration Date Is Set on All Keys" 1 $sec $r.Error $sid $sname $kvName))
                    }
                } elseif (-not $r.Data -or ($r.Data | Measure-Object).Count -eq 0) {
                    $results.Add((New-InfoResult $ctrlKeyExp "Ensure That the Expiration Date Is Set on All Keys" 1 $sec "No keys found in vault." $sid $sname $kvName))
                } else {
                    $keys = @($r.Data)
                    $cachedKeys = $keys
                    $noExpiry = @($keys | Where-Object { -not $_.attributes.expires })
                    $pass = $noExpiry.Count -eq 0
                    $results.Add((New-CISResult `
                        -ControlId $ctrlKeyExp -Title "Ensure That the Expiration Date Is Set on All Keys" `
                        -Level 1 -Section $sec `
                        -Status $(if ($pass) { $script:PASS } else { $script:FAIL }) `
                        -Details $(if ($pass) { "All $($keys.Count) key(s) have expiration set." } else { "$($noExpiry.Count) key(s) without expiration: $($noExpiry.name -join ', ')" }) `
                        -Remediation $(if (-not $pass) { "Key Vault > $kvName > Keys > Set expiration date on each key" } else { "" }) `
                        -SubscriptionId $sid -SubscriptionName $sname -Resource $kvName))
                }
            } catch {
                $results.Add((New-ErrorResult $ctrlKeyExp "Key Expiration Check" 1 $sec $_.Exception.Message $sid $sname $kvName))
            }

            # 8.3.3/8.3.4 — Secret expiration set (RBAC vs access-policy vault)
            $ctrlSecExp = if ($rbac) { "8.3.3" } else { "8.3.4" }
            try {
                $r = Invoke-AzCli -Arguments @(
                    "keyvault", "secret", "list", "--vault-name", $kvName
                ) -TimeoutSec $script:TIMEOUTS.default

                if (-not $r.Success) {
                    if (Test-AuthzError $r.Error) {
                        $results.Add((New-ErrorResult $ctrlSecExp "Ensure That the Expiration Date Is Set on All Secrets" 1 $sec "Insufficient permissions to list secrets. Grant the 'Key Vault Reader' data-plane role or a Key Vault access policy with Secret List permission." $sid $sname $kvName))
                    } elseif (Test-FirewallError $r.Error) {
                        $results.Add((New-ErrorResult $ctrlSecExp "Ensure That the Expiration Date Is Set on All Secrets" 1 $sec "Key Vault firewall is blocking access. Add the audit machine's IP to the vault's firewall allowlist." $sid $sname $kvName))
                    } else {
                        $results.Add((New-ErrorResult $ctrlSecExp "Ensure That the Expiration Date Is Set on All Secrets" 1 $sec $r.Error $sid $sname $kvName))
                    }
                } elseif (-not $r.Data -or ($r.Data | Measure-Object).Count -eq 0) {
                    $results.Add((New-InfoResult $ctrlSecExp "Ensure That the Expiration Date Is Set on All Secrets" 1 $sec "No secrets found in vault." $sid $sname $kvName))
                } else {
                    $secrets  = @($r.Data)
                    $noExpiry = @($secrets | Where-Object { -not $_.attributes.expires })
                    $pass     = $noExpiry.Count -eq 0
                    $results.Add((New-CISResult `
                        -ControlId $ctrlSecExp -Title "Ensure That the Expiration Date Is Set on All Secrets" `
                        -Level 1 -Section $sec `
                        -Status $(if ($pass) { $script:PASS } else { $script:FAIL }) `
                        -Details $(if ($pass) { "All $($secrets.Count) secret(s) have expiration set." } else { "$($noExpiry.Count) secret(s) without expiration: $(($noExpiry | ForEach-Object { [string]$_.name } | Where-Object { $_ }) -join ', ')" }) `
                        -Remediation $(if (-not $pass) { "Key Vault > $kvName > Secrets > Set expiration date" } else { "" }) `
                        -SubscriptionId $sid -SubscriptionName $sname -Resource $kvName))
                }
            } catch {
                $results.Add((New-ErrorResult $ctrlSecExp "Secret Expiration Check" 1 $sec $_.Exception.Message $sid $sname $kvName))
            }

            # 8.3.11 — Certificate validity <= 12 months
            try {
                $r = Invoke-AzCli -Arguments @(
                    "keyvault", "certificate", "list", "--vault-name", $kvName
                ) -TimeoutSec $script:TIMEOUTS.default

                if (-not $r.Success) {
                    if (Test-AuthzError $r.Error) {
                        $results.Add((New-ErrorResult "8.3.11" "Ensure That Certificate Validity Period Is Not More Than 12 Months" 1 $sec "Insufficient permissions to list certificates. Grant the 'Key Vault Reader' data-plane role or a Key Vault access policy with Certificate List permission." $sid $sname $kvName))
                    } elseif (Test-FirewallError $r.Error) {
                        $results.Add((New-ErrorResult "8.3.11" "Ensure That Certificate Validity Period Is Not More Than 12 Months" 1 $sec "Key Vault firewall is blocking access. Add the audit machine's IP to the vault's firewall allowlist." $sid $sname $kvName))
                    } else {
                        $results.Add((New-ErrorResult "8.3.11" "Ensure That Certificate Validity Period Is Not More Than 12 Months" 1 $sec $r.Error $sid $sname $kvName))
                    }
                } elseif (-not $r.Data -or ($r.Data | Measure-Object).Count -eq 0) {
                    $results.Add((New-InfoResult "8.3.11" "Ensure That Certificate Validity Period Is Not More Than 12 Months" 1 $sec "No certificates found." $sid $sname $kvName))
                } else {
                    $certs     = @($r.Data)
                    $longCerts = @($certs | Where-Object {
                        $exp = $_.attributes.expires
                        $crt = $_.attributes.created
                        if (-not $exp -or -not $crt) { return $true }
                        $days = ([datetime]$exp - [datetime]$crt).TotalDays
                        $days -gt 366
                    })
                    $pass = $longCerts.Count -eq 0
                    $results.Add((New-CISResult `
                        -ControlId "8.3.11" -Title "Ensure That Certificate Validity Period Is Not More Than 12 Months" `
                        -Level 1 -Section $sec `
                        -Status $(if ($pass) { $script:PASS } else { $script:FAIL }) `
                        -Details $(if ($pass) { "All certificates have valid (<= 12 month) lifetimes." } else { "$($longCerts.Count) certificate(s) with lifetime > 12 months: $(($longCerts | ForEach-Object { [string]$_.name }) -join ', ')" }) `
                        -Remediation $(if (-not $pass) { "Key Vault > $kvName > Certificates > Issuance policy > Validity <= 12 months" } else { "" }) `
                        -SubscriptionId $sid -SubscriptionName $sname -Resource $kvName))
                }
            } catch {
                $results.Add((New-ErrorResult "8.3.11" "Certificate Validity" 1 $sec $_.Exception.Message $sid $sname $kvName))
            }

            # 8.3.6 — RBAC authorization enabled
            $results.Add((New-CISResult `
                -ControlId "8.3.6" -Title "Ensure That Azure Key Vault Uses RBAC for Authorization" `
                -Level 2 -Section $sec `
                -Status $(if ($rbac) { $script:PASS } else { $script:FAIL }) `
                -Details $(if ($rbac) { "RBAC authorization model enabled." } else { "Using legacy Vault Access Policy, not RBAC." }) `
                -Remediation $(if (-not $rbac) { "Key Vault > $kvName > Access configuration > Permission model > Azure RBAC" } else { "" }) `
                -SubscriptionId $sid -SubscriptionName $sname -Resource $kvName))

            # 8.3.5 — Purge protection enabled
            $results.Add((New-CISResult `
                -ControlId "8.3.5" -Title "Ensure That Azure Key Vault Has Purge Protection Enabled" `
                -Level 1 -Section $sec `
                -Status $(if ($purge) { $script:PASS } else { $script:FAIL }) `
                -Details $(if ($purge) { "Purge protection enabled." } else { "Purge protection not enabled." }) `
                -Remediation $(if (-not $purge) { "Key Vault > $kvName > Properties > Enable purge protection" } else { "" }) `
                -SubscriptionId $sid -SubscriptionName $sname -Resource $kvName))

            # 8.3.7 — Public network access disabled
            $pubOk = $pub -eq "Disabled"
            $results.Add((New-CISResult `
                -ControlId "8.3.7" -Title "Ensure That Azure Key Vault Disables Public Network Access" `
                -Level 1 -Section $sec `
                -Status $(if ($pubOk) { $script:PASS } else { $script:FAIL }) `
                -Details $(if ($pubOk) { "Public network access: Disabled." } else { "Public network access: $pub." }) `
                -Remediation $(if (-not $pubOk) { "Key Vault > $kvName > Networking > Allow access from > Disable public access" } else { "" }) `
                -SubscriptionId $sid -SubscriptionName $sname -Resource $kvName))

            # 8.3.8 — Private endpoints configured
            $results.Add((New-CISResult `
                -ControlId "8.3.8" -Title "Ensure That Private Endpoints Are Used for Azure Key Vaults" `
                -Level 2 -Section $sec `
                -Status $(if ($eps -gt 0) { $script:PASS } else { $script:FAIL }) `
                -Details $(if ($eps -gt 0) { "Private endpoint(s) configured: $eps." } else { "No private endpoints configured." }) `
                -Remediation $(if ($eps -eq 0) { "Key Vault > $kvName > Networking > Private endpoint connections > Add" } else { "" }) `
                -SubscriptionId $sid -SubscriptionName $sname -Resource $kvName))

            # 8.3.9 — Automatic key rotation policy set (reuse cached key list from 8.3.1/8.3.2)
            try {
                $r = if ($cachedKeyResult) { $cachedKeyResult } else {
                    Invoke-AzCli -Arguments @(
                        "keyvault", "key", "list", "--vault-name", $kvName
                    ) -TimeoutSec $script:TIMEOUTS.default
                }

                if ($r.Success -and $r.Data -and ($r.Data | Measure-Object).Count -gt 0) {
                    $keys = if ($cachedKeys) { $cachedKeys } else { @($r.Data) }
                    $noRotation = [System.Collections.Generic.List[string]]::new()

                    foreach ($key in $keys) {
                        $keyName = [string]$key.name
                        $rr = Invoke-AzCli -Arguments @(
                            "keyvault", "key", "rotation-policy", "show",
                            "--vault-name", $kvName, "--name", $keyName
                        ) -TimeoutSec $script:TIMEOUTS.default

                        if ($rr.Success -and $rr.Data) {
                            # Compliant if at least one lifetimeAction has type "Rotate" (automatic rotation)
                            $hasRotate = $false
                            foreach ($la in @($rr.Data.lifetimeActions)) {
                                if ([string]($la.PSObject.Properties['action']?.Value.PSObject.Properties['type']?.Value) -eq 'Rotate') {
                                    $hasRotate = $true; break
                                }
                            }
                            if (-not $hasRotate) { $noRotation.Add($keyName) }
                        } else {
                            $noRotation.Add($keyName)
                        }
                    }

                    $pass = $noRotation.Count -eq 0
                    $results.Add((New-CISResult `
                        -ControlId "8.3.9" -Title "Ensure That Automatic Key Rotation Is Enabled for Key Vault Keys" `
                        -Level 2 -Section $sec `
                        -Status $(if ($pass) { $script:PASS } else { $script:FAIL }) `
                        -Details $(if ($pass) { "All keys have automatic rotation configured." } else { "Keys without automatic rotation configured: $($noRotation -join ', ')" }) `
                        -Remediation $(if (-not $pass) { "Key Vault > $kvName > Keys > Rotation policy > Set rotation action" } else { "" }) `
                        -SubscriptionId $sid -SubscriptionName $sname -Resource $kvName))
                } elseif (-not $r.Success) {
                    if (Test-AuthzError $r.Error) {
                        $results.Add((New-ErrorResult "8.3.9" "Ensure That Automatic Key Rotation Is Enabled for Key Vault Keys" 2 $sec "Insufficient permissions to list keys. Grant the 'Key Vault Reader' data-plane role or a Key Vault access policy with Key List permission." $sid $sname $kvName))
                    } elseif (Test-FirewallError $r.Error) {
                        $results.Add((New-ErrorResult "8.3.9" "Ensure That Automatic Key Rotation Is Enabled for Key Vault Keys" 2 $sec "Key Vault firewall is blocking access. Add the audit machine's IP to the vault's firewall allowlist." $sid $sname $kvName))
                    } else {
                        $results.Add((New-ErrorResult "8.3.9" "Ensure That Automatic Key Rotation Is Enabled for Key Vault Keys" 2 $sec $r.Error $sid $sname $kvName))
                    }
                } else {
                    $results.Add((New-InfoResult "8.3.9" "Ensure That Automatic Key Rotation Is Enabled for Key Vault Keys" 2 $sec "No keys found in vault." $sid $sname $kvName))
                }
            } catch {
                $results.Add((New-ErrorResult "8.3.9" "Key Rotation Auto-Rotation" 2 $sec $_.Exception.Message $sid $sname $kvName))
            }
        }
    }

    # ── 8.4.1 — Azure Bastion deployed (if VMs exist) ─────────────────────────
    if ($vms.Count -eq 0) {
        $results.Add((New-InfoResult "8.4.1" "Ensure That Azure Bastion Host Exists" 2 $sec "No VMs found in subscription." $sid $sname))
    } else {
        $hasBastion = $bastion.Count -gt 0
        $results.Add((New-CISResult `
            -ControlId "8.4.1" -Title "Ensure That Azure Bastion Host Exists" -Level 2 -Section $sec `
            -Status $(if ($hasBastion) { $script:PASS } else { $script:FAIL }) `
            -Details $(if ($hasBastion) { "Azure Bastion found: $(($bastion | ForEach-Object { [string]$_.name }) -join ', ')" } else { "No Azure Bastion found. $($vms.Count) VM(s) present." }) `
            -Remediation $(if (-not $hasBastion) { "Create an Azure Bastion host in a dedicated AzureBastionSubnet for secure VM access." } else { "" }) `
            -SubscriptionId $sid -SubscriptionName $sname))
    }

    # ── 8.5 — DDoS Network Protection on VNets ───────────────────────────────
    if ($vnets.Count -eq 0) {
        $results.Add((New-InfoResult "8.5" "Ensure That Azure DDoS Network Protection Is Enabled" 2 $sec "No VNets found." $sid $sname))
    } else {
        foreach ($vnet in $vnets) {
            $hasDdos = [string]$vnet.hasDdos -eq "True" -or [string]$vnet.hasDdos -eq "true"
            $results.Add((New-CISResult `
                -ControlId "8.5" -Title "Ensure That Azure DDoS Network Protection Is Enabled" -Level 2 -Section $sec `
                -Status $(if ($hasDdos) { $script:PASS } else { $script:FAIL }) `
                -Details $(if ($hasDdos) { "DDoS Network Protection enabled." } else { "DDoS Network Protection not enabled." }) `
                -Remediation $(if (-not $hasDdos) { "VNet > $([string]$vnet.name) > DDoS protection > Enable DDoS Network Protection plan" } else { "" }) `
                -SubscriptionId $sid -SubscriptionName $sname -Resource ([string]$vnet.name)))
        }
    }

    return $results.ToArray()
}
