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
        @{ Id="8.1.1.1"; Plan="CloudPosture";                 Title="Ensure Microsoft Defender CSPM is Set to 'On'" }
        @{ Id="8.1.2.1"; Plan="Api";                          Title="Ensure Microsoft Defender for APIs is Set to 'On'" }
        @{ Id="8.1.3.1"; Plan="VirtualMachines";              Title="Ensure that Defender for Servers is Set to 'On'" }
        @{ Id="8.1.4.1"; Plan="Containers";                   Title="Ensure That Microsoft Defender for Containers Is Set To 'On'" }
        @{ Id="8.1.5.1"; Plan="StorageAccounts";              Title="Ensure That Microsoft Defender for Storage Is Set To 'On'" }
        @{ Id="8.1.6.1"; Plan="AppServices";                  Title="Ensure That Microsoft Defender for App Services Is Set To 'On'" }
        @{ Id="8.1.7.1"; Plan="CosmosDbs";                    Title="Ensure That Microsoft Defender for Azure Cosmos DB Is Set To 'On'" }
        @{ Id="8.1.7.2"; Plan="OpenSourceRelationalDatabases";Title="Ensure That Microsoft Defender for Open-Source Relational Databases Is Set To 'On'" }
        @{ Id="8.1.7.3"; Plan="SqlServers";                   Title="Ensure That Microsoft Defender for (Managed Instance) Azure SQL Databases Is Set To 'On'" }
        @{ Id="8.1.7.4"; Plan="SqlServerVirtualMachines";     Title="Ensure That Microsoft Defender for SQL Servers on Machines Is Set To 'On'" }
        @{ Id="8.1.8.1"; Plan="KeyVaults";                    Title="Ensure That Microsoft Defender for Key Vault Is Set To 'On'" }
        @{ Id="8.1.9.1"; Plan="Arm";                          Title="Ensure That Microsoft Defender for Resource Manager Is Set To 'On'" }
    )

    foreach ($plan in $defenderPlans) {
        try {
            $pricing = Get-AzSecurityPricing -Name $plan.Plan -ErrorAction Stop
            $tier    = [string]$pricing.PricingTier
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
        $r   = Invoke-ArmRest -Uri $url

        if (-not $r.Success) {
            $results.Add((New-ErrorResult "8.1.3.3" "Ensure that 'Endpoint protection' Component Status is set to 'On'" 2 $sec $r.Error $sid $sname))
        } else {
            $enabled = [string]$r.Data.properties.enabled -eq "True" -or [string]$r.Data.properties.enabled -eq "true"
            $results.Add((New-CISResult `
                -ControlId "8.1.3.3" `
                -Title "Ensure that 'Endpoint protection' Component Status is set to 'On'" `
                -Level 2 -Section $sec `
                -Status $(if ($enabled) { $script:PASS } else { $script:FAIL }) `
                -Details $(if ($enabled) { "Microsoft Defender for Endpoint integration: Enabled." } else { "Microsoft Defender for Endpoint integration: Disabled." }) `
                -Remediation $(if (-not $enabled) { "Defender for Cloud > Environment Settings > Integrations > Enable MDE integration" } else { "" }) `
                -SubscriptionId $sid -SubscriptionName $sname))
        }
    } catch {
        $results.Add((New-ErrorResult "8.1.3.3" "Ensure that 'Endpoint protection' Component Status is set to 'On'" 2 $sec $_.Exception.Message $sid $sname))
    }

    # ── 8.1.10 — MDE TVM VM OS update check ──────────────────────────────────
    try {
        $url = "https://management.azure.com/subscriptions/$sid/providers/Microsoft.Security/serverVulnerabilityAssessmentsSettings?api-version=2023-05-01"
        $r   = Invoke-ArmRest -Uri $url

        if (-not $r.Success) {
            $results.Add((New-ErrorResult "8.1.10" "Ensure that Microsoft Defender for Cloud is Configured to Check VM Operating Systems for Updates" 1 $sec $r.Error $sid $sname))
        } else {
            $settingsArr = $r.Data.PSObject.Properties['value']?.Value
            $settings    = if ($settingsArr) { @($settingsArr) } else { @() }
            $enabled  = @($settings | Where-Object {
                $props = $_.PSObject.Properties['properties']?.Value
                $props -and [string]($props.PSObject.Properties['selectedProvider']?.Value) -eq "MdeTvm"
            }).Count -gt 0
            $results.Add((New-CISResult `
                -ControlId "8.1.10" `
                -Title "Ensure that Microsoft Defender for Cloud is Configured to Check VM Operating Systems for Updates" `
                -Level 1 -Section $sec `
                -Status $(if ($enabled) { $script:PASS } else { $script:FAIL }) `
                -Details $(if ($enabled) { "MDE TVM vulnerability assessment: enabled." } else { "MDE TVM vulnerability assessment: NOT enabled." }) `
                -Remediation $(if (-not $enabled) { "Defender for Cloud > Environment settings > VM vulnerability assessment: Microsoft Defender Vulnerability Management." } else { "" }) `
                -SubscriptionId $sid -SubscriptionName $sname))
        }
    } catch {
        $results.Add((New-ErrorResult "8.1.10" "Ensure that Microsoft Defender for Cloud is Configured to Check VM Operating Systems for Updates" 1 $sec $_.Exception.Message $sid $sname))
    }

    # ── 8.1.12–8.1.15 — Security contact notifications (preview REST API) ──────
    # Uses 2023-12-01-preview directly — it returns all data needed for all 4 checks.
    try {
        $previewUrl  = "https://management.azure.com/subscriptions/$sid/providers/Microsoft.Security/securityContacts?api-version=2023-12-01-preview"
        $r2          = Invoke-ArmRest -Uri $previewUrl
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
            -Title "Ensure That 'All users with the following roles' is Set to 'Owner'" `
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
            -Title "Ensure 'Additional email addresses' is Configured with a Security Contact Email" `
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
            -Title "Ensure that 'Notify about alerts with the following severity (or higher)' is Enabled" `
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
            -Title "Ensure that 'Notify about attack paths with the following risk level (or higher)' is Enabled" `
            -Level 1 -Section $sec `
            -Status $(if ($attackOn) { $script:PASS } else { $script:FAIL }) `
            -Details $(if ($attackOn) { "Attack path notifications configured." } else { "Attack path notifications NOT configured." }) `
            -Remediation $(if (-not $attackOn) { "Defender for Cloud > Environment Settings > Email notifications > Notify about attack paths with risk level: Critical." } else { "" }) `
            -SubscriptionId $sid -SubscriptionName $sname))

    } catch {
        $scTitleMap = @{
            "8.1.12" = "Ensure That 'All users with the following roles' is Set to 'Owner'"
            "8.1.13" = "Ensure 'Additional email addresses' is Configured with a Security Contact Email"
            "8.1.14" = "Ensure that 'Notify about alerts with the following severity (or higher)' is Enabled"
            "8.1.15" = "Ensure that 'Notify about attack paths with the following risk level (or higher)' is Enabled"
        }
        foreach ($cid in @("8.1.12","8.1.13","8.1.14","8.1.15")) {
            $results.Add((New-ErrorResult $cid $scTitleMap[$cid] 1 $sec $_.Exception.Message $sid $sname))
        }
    }

    # ── 8.3.x — Key Vault checks ──────────────────────────────────────────────
    # Static properties (purge protection, RBAC mode, network access) come from
    # Resource Graph prefetch data. Data-plane checks (key/secret/certificate
    # enumeration) require the Az.KeyVault cmdlets which call the vault's data-plane
    # endpoint directly — this is separate from the ARM control-plane used above.
    #
    # CIS controls are numbered differently depending on whether the vault uses RBAC
    # authorization (8.3.1/8.3.3) vs. legacy vault access policies (8.3.2/8.3.4).
    # The $rbac flag from prefetch data selects the correct control ID at runtime.
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

            $ctrlKeyExp  = if ($rbac) { "8.3.1" } else { "8.3.2" }
            $titleKeyExp = if ($rbac) { "Ensure that the Expiration Date is Set for all Keys in Key Vaults using RBAC" } else { "Ensure that the Expiration Date is set for All Keys in Key Vaults using access policies (legacy)" }
            $cachedKeys = $null
            try {
                # Filter out certificate-backed keys (Managed = $true) — those are managed by the
                # certificate lifecycle and will be excluded by default in Az.KeyVault 7.0 / Az 16.
                $allKeys    = @(Get-AzKeyVaultKey -VaultName $kvName -WarningAction SilentlyContinue -ErrorAction Stop |
                                    Where-Object { -not ($_.PSObject.Properties['Managed'] -and $_.Managed) })
                $cachedKeys = $allKeys

                if ($allKeys.Count -eq 0) {
                    $results.Add((New-InfoResult $ctrlKeyExp $titleKeyExp 1 $sec "No keys found in vault." $sid $sname $kvName))
                } else {
                    $noExpiry = @($allKeys | Where-Object { -not ($_.PSObject.Properties['Attributes'] -and $null -ne $_.Attributes -and $_.Attributes.Expires) })
                    $pass = $noExpiry.Count -eq 0
                    $results.Add((New-CISResult `
                        -ControlId $ctrlKeyExp -Title $titleKeyExp `
                        -Level 1 -Section $sec `
                        -Status $(if ($pass) { $script:PASS } else { $script:FAIL }) `
                        -Details $(if ($pass) { "All $($allKeys.Count) key(s) have expiration set." } else { "$($noExpiry.Count) key(s) without expiration: $(($noExpiry | ForEach-Object { $_.Name }) -join ', ')" }) `
                        -Remediation $(if (-not $pass) { "Key Vault > $kvName > Keys > Set expiration date on each key" } else { "" }) `
                        -SubscriptionId $sid -SubscriptionName $sname -Resource $kvName))
                }
            } catch {
                $errMsg = $_.Exception.Message
                if (Test-AuthzError $errMsg) {
                    $results.Add((New-ErrorResult $ctrlKeyExp $titleKeyExp 1 $sec "Insufficient permissions to list keys. Grant the 'Key Vault Reader' data-plane role or a Key Vault access policy with Key List permission." $sid $sname $kvName))
                } elseif (Test-FirewallError $errMsg) {
                    $results.Add((New-ErrorResult $ctrlKeyExp $titleKeyExp 1 $sec "Key Vault firewall is blocking access. Add the audit machine's IP to the vault's firewall allowlist." $sid $sname $kvName))
                } else {
                    $results.Add((New-ErrorResult $ctrlKeyExp "Key Expiration Check" 1 $sec $errMsg $sid $sname $kvName))
                }
            }

            # 8.3.3/8.3.4 — Secret expiration set (RBAC vs access-policy vault)
            $ctrlSecExp  = if ($rbac) { "8.3.3" } else { "8.3.4" }
            $titleSecExp = if ($rbac) { "Ensure that the Expiration Date is set for All Secrets in Key Vaults using RBAC" } else { "Ensure that the Expiration Date is set for All Secrets in Key Vaults using access policies (legacy)" }
            try {
                # Filter out certificate-backed secrets (Managed = $true) — those are managed by
                # the certificate lifecycle and will be excluded by default in Az.KeyVault 7.0 / Az 16.
                $allSecrets = @(Get-AzKeyVaultSecret -VaultName $kvName -WarningAction SilentlyContinue -ErrorAction Stop |
                                    Where-Object { -not ($_.PSObject.Properties['Managed'] -and $_.Managed) })

                if ($allSecrets.Count -eq 0) {
                    $results.Add((New-InfoResult $ctrlSecExp $titleSecExp 1 $sec "No secrets found in vault." $sid $sname $kvName))
                } else {
                    $noExpiry = @($allSecrets | Where-Object { -not ($_.PSObject.Properties['Attributes'] -and $null -ne $_.Attributes -and $_.Attributes.Expires) })
                    $pass     = $noExpiry.Count -eq 0
                    $results.Add((New-CISResult `
                        -ControlId $ctrlSecExp -Title $titleSecExp `
                        -Level 1 -Section $sec `
                        -Status $(if ($pass) { $script:PASS } else { $script:FAIL }) `
                        -Details $(if ($pass) { "All $($allSecrets.Count) secret(s) have expiration set." } else { "$($noExpiry.Count) secret(s) without expiration: $(($noExpiry | ForEach-Object { $_.Name }) -join ', ')" }) `
                        -Remediation $(if (-not $pass) { "Key Vault > $kvName > Secrets > Set expiration date" } else { "" }) `
                        -SubscriptionId $sid -SubscriptionName $sname -Resource $kvName))
                }
            } catch {
                $errMsg = $_.Exception.Message
                if (Test-AuthzError $errMsg) {
                    $results.Add((New-ErrorResult $ctrlSecExp $titleSecExp 1 $sec "Insufficient permissions to list secrets. Grant the 'Key Vault Reader' data-plane role or a Key Vault access policy with Secret List permission." $sid $sname $kvName))
                } elseif (Test-FirewallError $errMsg) {
                    $results.Add((New-ErrorResult $ctrlSecExp $titleSecExp 1 $sec "Key Vault firewall is blocking access. Add the audit machine's IP to the vault's firewall allowlist." $sid $sname $kvName))
                } else {
                    $results.Add((New-ErrorResult $ctrlSecExp "Secret Expiration Check" 1 $sec $errMsg $sid $sname $kvName))
                }
            }

            # 8.3.11 — Certificate validity <= 12 months
            try {
                $allCerts = @(Get-AzKeyVaultCertificate -VaultName $kvName -ErrorAction Stop)

                if ($allCerts.Count -eq 0) {
                    $results.Add((New-InfoResult "8.3.11" "Ensure Certificate 'Validity Period (in months)' is Less Than or Equal to '12'" 1 $sec "No certificates found." $sid $sname $kvName))
                } else {
                    $longCerts = @($allCerts | Where-Object {
                        $attr = if ($_.PSObject.Properties['Attributes'] -and $null -ne $_.Attributes) { $_.Attributes } else { $null }
                        $exp  = if ($null -ne $attr -and $attr.PSObject.Properties['Expires'])  { $attr.Expires  } else { $null }
                        $crt  = if ($null -ne $attr -and $attr.PSObject.Properties['Created'])  { $attr.Created  } else { $null }
                        if (-not $exp -or -not $crt) { return $true }
                        ($exp - $crt).TotalDays -gt 366
                    })
                    $pass = $longCerts.Count -eq 0
                    $results.Add((New-CISResult `
                        -ControlId "8.3.11" -Title "Ensure Certificate 'Validity Period (in months)' is Less Than or Equal to '12'" `
                        -Level 1 -Section $sec `
                        -Status $(if ($pass) { $script:PASS } else { $script:FAIL }) `
                        -Details $(if ($pass) { "All certificates have valid (<= 12 month) lifetimes." } else { "$($longCerts.Count) certificate(s) with lifetime > 12 months: $(($longCerts | ForEach-Object { $_.Name }) -join ', ')" }) `
                        -Remediation $(if (-not $pass) { "Key Vault > $kvName > Certificates > Issuance policy > Validity <= 12 months" } else { "" }) `
                        -SubscriptionId $sid -SubscriptionName $sname -Resource $kvName))
                }
            } catch {
                $errMsg = $_.Exception.Message
                if (Test-AuthzError $errMsg) {
                    $results.Add((New-ErrorResult "8.3.11" "Ensure Certificate 'Validity Period (in months)' is Less Than or Equal to '12'" 1 $sec "Insufficient permissions to list certificates. Grant the 'Key Vault Reader' data-plane role or a Key Vault access policy with Certificate List permission." $sid $sname $kvName))
                } elseif (Test-FirewallError $errMsg) {
                    $results.Add((New-ErrorResult "8.3.11" "Ensure Certificate 'Validity Period (in months)' is Less Than or Equal to '12'" 1 $sec "Key Vault firewall is blocking access. Add the audit machine's IP to the vault's firewall allowlist." $sid $sname $kvName))
                } else {
                    $results.Add((New-ErrorResult "8.3.11" "Certificate Validity" 1 $sec $errMsg $sid $sname $kvName))
                }
            }

            # 8.3.6 — RBAC authorization enabled
            $results.Add((New-CISResult `
                -ControlId "8.3.6" -Title "Ensure that Role Based Access Control for Azure Key Vault is Enabled" `
                -Level 2 -Section $sec `
                -Status $(if ($rbac) { $script:PASS } else { $script:FAIL }) `
                -Details $(if ($rbac) { "RBAC authorization model enabled." } else { "Using legacy Vault Access Policy, not RBAC." }) `
                -Remediation $(if (-not $rbac) { "Key Vault > $kvName > Access configuration > Permission model > Azure RBAC" } else { "" }) `
                -SubscriptionId $sid -SubscriptionName $sname -Resource $kvName))

            # 8.3.5 — Purge protection enabled
            $results.Add((New-CISResult `
                -ControlId "8.3.5" -Title "Ensure 'Purge protection' is Set to 'Enabled'" `
                -Level 1 -Section $sec `
                -Status $(if ($purge) { $script:PASS } else { $script:FAIL }) `
                -Details $(if ($purge) { "Purge protection enabled." } else { "Purge protection not enabled." }) `
                -Remediation $(if (-not $purge) { "Key Vault > $kvName > Properties > Enable purge protection" } else { "" }) `
                -SubscriptionId $sid -SubscriptionName $sname -Resource $kvName))

            # 8.3.7 — Public network access disabled
            $pubOk = $pub -eq "Disabled"
            $results.Add((New-CISResult `
                -ControlId "8.3.7" -Title "Ensure Public Network Access is Disabled" `
                -Level 1 -Section $sec `
                -Status $(if ($pubOk) { $script:PASS } else { $script:FAIL }) `
                -Details $(if ($pubOk) { "Public network access: Disabled." } else { "Public network access: $pub." }) `
                -Remediation $(if (-not $pubOk) { "Key Vault > $kvName > Networking > Allow access from > Disable public access" } else { "" }) `
                -SubscriptionId $sid -SubscriptionName $sname -Resource $kvName))

            # 8.3.8 — Private endpoints configured
            $results.Add((New-CISResult `
                -ControlId "8.3.8" -Title "Ensure Private Endpoints are Used to Access Azure Key Vault" `
                -Level 2 -Section $sec `
                -Status $(if ($eps -gt 0) { $script:PASS } else { $script:FAIL }) `
                -Details $(if ($eps -gt 0) { "Private endpoint(s) configured: $eps." } else { "No private endpoints configured." }) `
                -Remediation $(if ($eps -eq 0) { "Key Vault > $kvName > Networking > Private endpoint connections > Add" } else { "" }) `
                -SubscriptionId $sid -SubscriptionName $sname -Resource $kvName))

            # 8.3.9 — Automatic key rotation policy set (reuse cached key list from 8.3.1/8.3.2)
            try {
                $keys = if ($cachedKeys) { $cachedKeys } else {
                    @(Get-AzKeyVaultKey -VaultName $kvName -WarningAction SilentlyContinue -ErrorAction Stop |
                        Where-Object { -not ($_.PSObject.Properties['Managed'] -and $_.Managed) })
                }

                if ($keys.Count -gt 0) {
                    $noRotation = [System.Collections.Generic.List[string]]::new()

                    foreach ($key in $keys) {
                        $keyName = [string]$key.Name
                        $policy  = Get-AzKeyVaultKeyRotationPolicy -VaultName $kvName -Name $keyName -ErrorAction SilentlyContinue

                        if ($policy) {
                            $hasRotate = $false
                            foreach ($la in @($policy.LifetimeActions)) {
                                if ($la.Action -eq 'Rotate') { $hasRotate = $true; break }
                            }
                            if (-not $hasRotate) { $noRotation.Add($keyName) }
                        } else {
                            $noRotation.Add($keyName)
                        }
                    }

                    $pass = $noRotation.Count -eq 0
                    $results.Add((New-CISResult `
                        -ControlId "8.3.9" -Title "Ensure Automatic Key Rotation is Enabled within Azure Key Vault" `
                        -Level 2 -Section $sec `
                        -Status $(if ($pass) { $script:PASS } else { $script:FAIL }) `
                        -Details $(if ($pass) { "All keys have automatic rotation configured." } else { "Keys without automatic rotation configured: $($noRotation -join ', ')" }) `
                        -Remediation $(if (-not $pass) { "Key Vault > $kvName > Keys > Rotation policy > Set rotation action" } else { "" }) `
                        -SubscriptionId $sid -SubscriptionName $sname -Resource $kvName))
                } else {
                    $results.Add((New-InfoResult "8.3.9" "Ensure Automatic Key Rotation is Enabled within Azure Key Vault" 2 $sec "No keys found in vault." $sid $sname $kvName))
                }
            } catch {
                $errMsg = $_.Exception.Message
                if (Test-AuthzError $errMsg) {
                    $results.Add((New-ErrorResult "8.3.9" "Ensure Automatic Key Rotation is Enabled within Azure Key Vault" 2 $sec "Insufficient permissions to list keys. Grant the 'Key Vault Reader' data-plane role or a Key Vault access policy with Key List permission." $sid $sname $kvName))
                } elseif (Test-FirewallError $errMsg) {
                    $results.Add((New-ErrorResult "8.3.9" "Ensure Automatic Key Rotation is Enabled within Azure Key Vault" 2 $sec "Key Vault firewall is blocking access. Add the audit machine's IP to the vault's firewall allowlist." $sid $sname $kvName))
                } else {
                    $results.Add((New-ErrorResult "8.3.9" "Key Rotation Auto-Rotation" 2 $sec $errMsg $sid $sname $kvName))
                }
            }
        }
    }

    # ── 8.4.1 — Azure Bastion deployed (if VMs exist) ─────────────────────────
    if ($vms.Count -eq 0) {
        $results.Add((New-InfoResult "8.4.1" "Ensure an Azure Bastion Host Exists" 2 $sec "No VMs found in subscription." $sid $sname))
    } else {
        $hasBastion = $bastion.Count -gt 0
        $results.Add((New-CISResult `
            -ControlId "8.4.1" -Title "Ensure an Azure Bastion Host Exists" -Level 2 -Section $sec `
            -Status $(if ($hasBastion) { $script:PASS } else { $script:FAIL }) `
            -Details $(if ($hasBastion) { "Azure Bastion found: $(($bastion | ForEach-Object { [string]$_.name }) -join ', ')" } else { "No Azure Bastion found. $($vms.Count) VM(s) present." }) `
            -Remediation $(if (-not $hasBastion) { "Create an Azure Bastion host in a dedicated AzureBastionSubnet for secure VM access." } else { "" }) `
            -SubscriptionId $sid -SubscriptionName $sname))
    }

    # ── 8.5 — DDoS Network Protection on VNets ───────────────────────────────
    if ($vnets.Count -eq 0) {
        $results.Add((New-InfoResult "8.5" "Ensure Azure DDoS Network Protection is Enabled on Virtual Networks" 2 $sec "No VNets found." $sid $sname))
    } else {
        foreach ($vnet in $vnets) {
            $hasDdos = [string]$vnet.hasDdos -in @("True", "true", "1")
            $results.Add((New-CISResult `
                -ControlId "8.5" -Title "Ensure Azure DDoS Network Protection is Enabled on Virtual Networks" -Level 2 -Section $sec `
                -Status $(if ($hasDdos) { $script:PASS } else { $script:FAIL }) `
                -Details $(if ($hasDdos) { "DDoS Network Protection enabled." } else { "DDoS Network Protection not enabled." }) `
                -Remediation $(if (-not $hasDdos) { "VNet > $([string]$vnet.name) > DDoS protection > Enable DDoS Network Protection plan" } else { "" }) `
                -SubscriptionId $sid -SubscriptionName $sname -Resource ([string]$vnet.name)))
        }
    }

    return $results.ToArray()
}

function Invoke-Section8TenantChecks {
    <#
    .SYNOPSIS
    Section 8 controls v6 defines as Manual (no reliable automated read) — surfaced
    once so the report mirrors the benchmark's control set.
    #>
    $sec = "8 - Security Services"
    $manual = @(
        @{ Id="8.1.3.2";  Lvl=2; Title="Ensure that 'Vulnerability assessment for machines' Component Status is set to 'On'"; Msg="Manual verification required — Defender for Cloud > Environment settings > Defender for Servers > ensure the 'Vulnerability assessment for machines' component status is 'On'." }
        @{ Id="8.1.3.4";  Lvl=2; Title="Ensure that 'Agentless scanning for machines' Component Status is Set to 'On'"; Msg="Manual verification required — Defender for Cloud > Environment settings > Defender for Servers > ensure the 'Agentless scanning for machines' component status is 'On'." }
        @{ Id="8.1.3.5";  Lvl=2; Title="Ensure that 'File Integrity Monitoring' Component Status is Set to 'On'"; Msg="Manual verification required — Defender for Cloud > Environment settings > Defender for Servers > ensure the 'File Integrity Monitoring' component status is 'On'." }
        @{ Id="8.1.5.2";  Lvl=2; Title="Ensure Advanced Threat Protection Alerts for Storage Accounts Are Monitored"; Msg="Manual verification required — confirm that Microsoft Defender for Storage threat-protection alerts are reviewed and actioned by a responsible team." }
        @{ Id="8.1.11";   Lvl=1; Title="Ensure that non-deprecated Microsoft Cloud Security Benchmark policies are not set to 'Disabled'"; Msg="Manual verification required — Defender for Cloud > Environment settings > Security policy > ensure non-deprecated Microsoft Cloud Security Benchmark policy effects are not set to 'Disabled'." }
        @{ Id="8.1.16";   Lvl=2; Title="Ensure that Microsoft Defender External Attack Surface Monitoring (EASM) is Enabled"; Msg="Manual verification required — confirm a Defender EASM workspace is deployed and monitoring the organisation's external attack surface." }
        @{ Id="8.2.1";    Lvl=2; Title="Ensure That Microsoft Defender for IoT Hub Is Set To 'On'"; Msg="Manual verification required — for each IoT Hub, ensure Microsoft Defender for IoT is enabled." }
        @{ Id="8.3.10";   Lvl=2; Title="Ensure that Azure Key Vault Managed HSM is Used when Required"; Msg="Manual verification required — where FIPS 140-2 Level 3 protection is required, confirm Azure Key Vault Managed HSM is used instead of the standard vault." }
    )

    $results = [System.Collections.Generic.List[object]]::new()
    foreach ($m in $manual) {
        $results.Add((New-ManualResult $m.Id $m.Title $m.Lvl $sec $m.Msg))
    }
    return $results.ToArray()
}
