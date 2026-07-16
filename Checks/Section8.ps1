# Section 8 — Security Services
# CIS Microsoft Azure Foundations Benchmark v6.0.0

function Invoke-Section8Checks {
    [CmdletBinding()]
    param(
        [string]$SubscriptionId,
        [string]$SubscriptionName,
        [hashtable]$PrefetchData
    )

    $results = [System.Collections.Generic.List[object]]::new()
    $sid     = $SubscriptionId
    $sname   = $SubscriptionName

    $keyvaults = @(Get-PrefetchData -PrefetchData $PrefetchData -Key "keyvaults" -SubscriptionId $sid)
    $vnets     = @(Get-PrefetchData -PrefetchData $PrefetchData -Key "vnets"     -SubscriptionId $sid)
    $vms       = @(Get-PrefetchData -PrefetchData $PrefetchData -Key "vms"       -SubscriptionId $sid)
    $bastion   = @(Get-PrefetchData -PrefetchData $PrefetchData -Key "bastion"   -SubscriptionId $sid)

    # Prefetch failure sentinels — dependent checks emit ERROR, never a false INFO/PASS
    $kvErr      = Get-PrefetchError -PrefetchData $PrefetchData -Key "keyvaults"
    $vnetErr    = Get-PrefetchError -PrefetchData $PrefetchData -Key "vnets"
    $vmErr      = Get-PrefetchError -PrefetchData $PrefetchData -Key "vms"
    $bastionErr = Get-PrefetchError -PrefetchData $PrefetchData -Key "bastion"

    # ── 8.1.x — Microsoft Defender plans ─────────────────────────────────────
    $defenderPlans = @(
        @{ Id="8.1.1.1"; Plan="CloudPosture" }
        @{ Id="8.1.2.1"; Plan="Api" }
        @{ Id="8.1.3.1"; Plan="VirtualMachines" }
        @{ Id="8.1.4.1"; Plan="Containers" }
        @{ Id="8.1.5.1"; Plan="StorageAccounts" }
        @{ Id="8.1.6.1"; Plan="AppServices" }
        @{ Id="8.1.7.1"; Plan="CosmosDbs" }
        @{ Id="8.1.7.2"; Plan="OpenSourceRelationalDatabases" }
        @{ Id="8.1.7.3"; Plan="SqlServers" }
        @{ Id="8.1.7.4"; Plan="SqlServerVirtualMachines" }
        @{ Id="8.1.8.1"; Plan="KeyVaults" }
        @{ Id="8.1.9.1"; Plan="Arm" }
    )

    foreach ($plan in $defenderPlans) {
        try {
            $pricing = Get-AzSecurityPricing -Name $plan.Plan -ErrorAction Stop
            $tier    = [string]$pricing.PricingTier
            $enabled = $tier -eq "Standard"
            $results.Add((New-CISResult `
                -ControlId $plan.Id `
                -Status $(if ($enabled) { $script:PASS } else { $script:FAIL }) `
                -Details $(if ($enabled) { "Microsoft Defender pricing tier: Standard (enabled)." } else { "Microsoft Defender pricing tier: $tier — must be upgraded to Standard." }) `
                -Remediation $(if (-not $enabled) { "Defender for Cloud > Environment Settings > $($plan.Plan) > Enable" } else { "" }) `
                -SubscriptionId $sid -SubscriptionName $sname))
        } catch {
            $results.Add((New-ErrorResult $plan.Id $_.Exception.Message $sid $sname))
        }
    }

    # ── 8.1.3.3 — WDATP / MDE integration ────────────────────────────────────
    try {
        $url = "https://management.azure.com/subscriptions/$sid/providers/Microsoft.Security/settings/WDATP?api-version=2021-06-01"
        $r   = Invoke-ArmRest -Uri $url

        if (-not $r.Success) {
            $results.Add((New-ErrorResult "8.1.3.3" $r.Error $sid $sname))
        } else {
            $enabled = [string]$r.Data.properties.enabled -eq "True" -or [string]$r.Data.properties.enabled -eq "true"
            $results.Add((New-CISResult `
                -ControlId "8.1.3.3" `
                -Status $(if ($enabled) { $script:PASS } else { $script:FAIL }) `
                -Details $(if ($enabled) { "Microsoft Defender for Endpoint integration: Enabled." } else { "Microsoft Defender for Endpoint integration: Disabled." }) `
                -Remediation $(if (-not $enabled) { "Defender for Cloud > Environment Settings > Integrations > Enable MDE integration" } else { "" }) `
                -SubscriptionId $sid -SubscriptionName $sname))
        }
    } catch {
        $results.Add((New-ErrorResult "8.1.3.3" $_.Exception.Message $sid $sname))
    }

    # ── 8.1.10 — MDE TVM VM OS update check ──────────────────────────────────
    try {
        $url = "https://management.azure.com/subscriptions/$sid/providers/Microsoft.Security/serverVulnerabilityAssessmentsSettings?api-version=2023-05-01"
        $r   = Invoke-ArmRest -Uri $url

        if (-not $r.Success) {
            $results.Add((New-ErrorResult "8.1.10" $r.Error $sid $sname))
        } else {
            $settingsArr = $r.Data.PSObject.Properties['value']?.Value
            $settings    = if ($settingsArr) { @($settingsArr) } else { @() }
            $enabled  = @($settings | Where-Object {
                $props = $_.PSObject.Properties['properties']?.Value
                $props -and [string]($props.PSObject.Properties['selectedProvider']?.Value) -eq "MdeTvm"
            }).Count -gt 0
            $results.Add((New-CISResult `
                -ControlId "8.1.10" `
                -Status $(if ($enabled) { $script:PASS } else { $script:FAIL }) `
                -Details $(if ($enabled) { "MDE TVM vulnerability assessment: enabled." } else { "MDE TVM vulnerability assessment: NOT enabled." }) `
                -Remediation $(if (-not $enabled) { "Defender for Cloud > Environment settings > VM vulnerability assessment: Microsoft Defender Vulnerability Management." } else { "" }) `
                -SubscriptionId $sid -SubscriptionName $sname))
        }
    } catch {
        $results.Add((New-ErrorResult "8.1.10" $_.Exception.Message $sid $sname))
    }

    # ── 8.1.12–8.1.15 — Security contact notifications (preview REST API) ──────
    # Uses 2023-12-01-preview directly — it returns all data needed for all 4 checks.
    try {
        $previewUrl  = "https://management.azure.com/subscriptions/$sid/providers/Microsoft.Security/securityContacts?api-version=2023-12-01-preview"
        $r2          = Invoke-ArmRest -Uri $previewUrl
        if (-not $r2.Success) { throw ([string]$r2.Error) }
        $contactItems = @()
        if ($r2.Data) {
            $valProp = $r2.Data.PSObject.Properties['value']
            if ($valProp) { $contactItems = @($valProp.Value) }
        }

        # 8.1.12 — notificationsByRole: state must be "On" and roles must contain "Owner"
        $ownersNotified = @($contactItems | Where-Object {
            $props    = $_.PSObject.Properties['properties']?.Value
            if (-not $props) { return $false }
            $nbr      = $props.PSObject.Properties['notificationsByRole']?.Value
            if (-not $nbr) { return $false }
            $state    = [string]($nbr.PSObject.Properties['state']?.Value)
            if ($state -ne "On") { return $false }
            $roleList = $nbr.PSObject.Properties['roles']?.Value
            if (-not $roleList) { return $false }
            ($roleList | ForEach-Object { [string]$_ }) -contains "Owner"
        }).Count -gt 0

        $results.Add((New-CISResult `
            -ControlId "8.1.12" `
            -Status $(if ($ownersNotified) { $script:PASS } else { $script:FAIL }) `
            -Details $(if ($ownersNotified) { "Role notifications On with Owner role configured." } else { "Role notifications are Off or Owner role NOT configured." }) `
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
            -Status $(if ($hasEmail) { $script:PASS } else { $script:FAIL }) `
            -Details $(if ($hasEmail) { "Additional email address(es) configured." } else { "No additional email addresses configured." }) `
            -Remediation $(if (-not $hasEmail) { "Defender for Cloud > Environment Settings > Email notifications > Additional email addresses." } else { "" }) `
            -SubscriptionId $sid -SubscriptionName $sname))

        # 8.1.14 — notificationsSources must contain a sourceType "Alert" entry with a
        # minimalSeverity set (v6 audit: state On + minimalSeverity at an appropriate level).
        # notificationsByRole.state governs role notifications (8.1.12), not alert severity.
        $alertSeverity = $null
        foreach ($ci in $contactItems) {
            $props   = $ci.PSObject.Properties['properties']?.Value
            if (-not $props) { continue }
            $srcProp = $props.PSObject.Properties['notificationsSources']
            if (-not $srcProp) { continue }
            foreach ($src in @($srcProp.Value)) {
                if ([string]($src.PSObject.Properties['sourceType']?.Value) -eq "Alert") {
                    $sev = [string]($src.PSObject.Properties['minimalSeverity']?.Value)
                    if ($sev) { $alertSeverity = $sev; break }
                }
            }
            if ($alertSeverity) { break }
        }
        $alertOn = [bool]$alertSeverity

        $results.Add((New-CISResult `
            -ControlId "8.1.14" `
            -Status $(if ($alertOn) { $script:PASS } else { $script:FAIL }) `
            -Details $(if ($alertOn) { "Alert notifications enabled (minimal severity: $alertSeverity)." } else { "Alert severity notifications are not enabled." }) `
            -Remediation $(if (-not $alertOn) { "Defender for Cloud > Environment Settings > Email notifications > Notify about alerts with severity: High." } else { "" }) `
            -SubscriptionId $sid -SubscriptionName $sname))

        # 8.1.15 — notificationsSources must contain sourceType "AttackPath" with a
        # minimalRiskLevel set (v6 audit: sourceType AttackPath + minimalRiskLevel).
        $attackRisk = $null
        foreach ($ci in $contactItems) {
            $props   = $ci.PSObject.Properties['properties']?.Value
            if (-not $props) { continue }
            $srcProp = $props.PSObject.Properties['notificationsSources']
            if (-not $srcProp) { continue }
            foreach ($src in @($srcProp.Value)) {
                if ([string]($src.PSObject.Properties['sourceType']?.Value) -eq "AttackPath") {
                    $risk = [string]($src.PSObject.Properties['minimalRiskLevel']?.Value)
                    if ($risk) { $attackRisk = $risk; break }
                }
            }
            if ($attackRisk) { break }
        }
        $attackOn = [bool]$attackRisk

        $results.Add((New-CISResult `
            -ControlId "8.1.15" `
            -Status $(if ($attackOn) { $script:PASS } else { $script:FAIL }) `
            -Details $(if ($attackOn) { "Attack path notifications enabled (minimal risk level: $attackRisk)." } else { "Attack path notifications NOT configured." }) `
            -Remediation $(if (-not $attackOn) { "Defender for Cloud > Environment Settings > Email notifications > Notify about attack paths with risk level: Critical." } else { "" }) `
            -SubscriptionId $sid -SubscriptionName $sname))

    } catch {
        foreach ($cid in @("8.1.12","8.1.13","8.1.14","8.1.15")) {
            $results.Add((New-ErrorResult $cid $_.Exception.Message $sid $sname))
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
    # Per-vault 8.3.x block (8.3.10 is manual, emitted in tenant checks)
    $kvControlIds = @("8.3.1","8.3.2","8.3.3","8.3.4","8.3.5","8.3.6","8.3.7","8.3.8","8.3.9","8.3.11")

    if ($kvErr) {
        foreach ($cid in $kvControlIds) {
            $results.Add((New-ErrorResult $cid "Key Vault prefetch failed: $kvErr" $sid $sname))
        }
    } elseif ($keyvaults.Count -eq 0) {
        foreach ($cid in $kvControlIds) {
            $results.Add((New-InfoResult $cid "No Key Vaults found." $sid $sname))
        }
    } else {
        foreach ($kv in $keyvaults) {
            $kvName = [string]$kv.name

            # Static checks from Resource Graph data
            $purge = [string]$kv.purgeProtection -eq "True" -or [string]$kv.purgeProtection -eq "true"
            $rbac  = [string]$kv.rbac            -eq "True" -or [string]$kv.rbac            -eq "true"
            $pub   = [string]$kv.publicAccess
            $eps   = [int]($kv.privateEps)

            $ctrlKeyExp = if ($rbac) { "8.3.1" } else { "8.3.2" }
            $cachedKeys = $null
            try {
                # Filter out certificate-backed keys (Managed = $true) — those are managed by the
                # certificate lifecycle and will be excluded by default in Az.KeyVault 7.0 / Az 16.
                $allKeys    = @(Invoke-WithRetry -OperationName "list keys ($kvName)" -ScriptBlock {
                                    Get-AzKeyVaultKey -VaultName $kvName -WarningAction SilentlyContinue -ErrorAction Stop
                                } | Where-Object { -not ($_.PSObject.Properties['Managed'] -and $_.Managed) })
                $cachedKeys = $allKeys

                if ($allKeys.Count -eq 0) {
                    $results.Add((New-InfoResult $ctrlKeyExp "No keys found in vault." $sid $sname $kvName))
                } else {
                    $noExpiry = @($allKeys | Where-Object { -not ($_.PSObject.Properties['Attributes'] -and $null -ne $_.Attributes -and $_.Attributes.Expires) })
                    $pass = $noExpiry.Count -eq 0
                    $results.Add((New-CISResult `
                        -ControlId $ctrlKeyExp `
                        -Status $(if ($pass) { $script:PASS } else { $script:FAIL }) `
                        -Details $(if ($pass) { "All $($allKeys.Count) key(s) have expiration set." } else { "$($noExpiry.Count) key(s) without expiration: $(($noExpiry | ForEach-Object { $_.Name }) -join ', ')" }) `
                        -Remediation $(if (-not $pass) { "Key Vault > $kvName > Keys > Set expiration date on each key" } else { "" }) `
                        -SubscriptionId $sid -SubscriptionName $sname -Resource $kvName))
                }
            } catch {
                Add-ClassifiedErrorSet -Results $results -ControlIds @($ctrlKeyExp) -Message $_.Exception.Message `
                    -AuthzMessage "Insufficient permissions to list keys. Grant the 'Key Vault Reader' data-plane role or a Key Vault access policy with Key List permission." `
                    -FirewallMessage "Key Vault firewall is blocking access. Add the audit machine's IP to the vault's firewall allowlist." `
                    -SubscriptionId $sid -SubscriptionName $sname -Resource $kvName
            }

            # 8.3.3/8.3.4 — Secret expiration set (RBAC vs access-policy vault)
            $ctrlSecExp = if ($rbac) { "8.3.3" } else { "8.3.4" }
            try {
                # Filter out certificate-backed secrets (Managed = $true) — those are managed by
                # the certificate lifecycle and will be excluded by default in Az.KeyVault 7.0 / Az 16.
                $allSecrets = @(Invoke-WithRetry -OperationName "list secrets ($kvName)" -ScriptBlock {
                                    Get-AzKeyVaultSecret -VaultName $kvName -WarningAction SilentlyContinue -ErrorAction Stop
                                } | Where-Object { -not ($_.PSObject.Properties['Managed'] -and $_.Managed) })

                if ($allSecrets.Count -eq 0) {
                    $results.Add((New-InfoResult $ctrlSecExp "No secrets found in vault." $sid $sname $kvName))
                } else {
                    $noExpiry = @($allSecrets | Where-Object { -not ($_.PSObject.Properties['Attributes'] -and $null -ne $_.Attributes -and $_.Attributes.Expires) })
                    $pass     = $noExpiry.Count -eq 0
                    $results.Add((New-CISResult `
                        -ControlId $ctrlSecExp `
                        -Status $(if ($pass) { $script:PASS } else { $script:FAIL }) `
                        -Details $(if ($pass) { "All $($allSecrets.Count) secret(s) have expiration set." } else { "$($noExpiry.Count) secret(s) without expiration: $(($noExpiry | ForEach-Object { $_.Name }) -join ', ')" }) `
                        -Remediation $(if (-not $pass) { "Key Vault > $kvName > Secrets > Set expiration date" } else { "" }) `
                        -SubscriptionId $sid -SubscriptionName $sname -Resource $kvName))
                }
            } catch {
                Add-ClassifiedErrorSet -Results $results -ControlIds @($ctrlSecExp) -Message $_.Exception.Message `
                    -AuthzMessage "Insufficient permissions to list secrets. Grant the 'Key Vault Reader' data-plane role or a Key Vault access policy with Secret List permission." `
                    -FirewallMessage "Key Vault firewall is blocking access. Add the audit machine's IP to the vault's firewall allowlist." `
                    -SubscriptionId $sid -SubscriptionName $sname -Resource $kvName
            }

            # 8.3.11 — Certificate validity <= 12 months
            try {
                $allCerts = @(Invoke-WithRetry -OperationName "list certificates ($kvName)" -ScriptBlock {
                                  Get-AzKeyVaultCertificate -VaultName $kvName -ErrorAction Stop
                              })

                if ($allCerts.Count -eq 0) {
                    $results.Add((New-InfoResult "8.3.11" "No certificates found." $sid $sname $kvName))
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
                        -ControlId "8.3.11" `
                        -Status $(if ($pass) { $script:PASS } else { $script:FAIL }) `
                        -Details $(if ($pass) { "All certificates have valid (<= 12 month) lifetimes." } else { "$($longCerts.Count) certificate(s) with lifetime > 12 months: $(($longCerts | ForEach-Object { $_.Name }) -join ', ')" }) `
                        -Remediation $(if (-not $pass) { "Key Vault > $kvName > Certificates > Issuance policy > Validity <= 12 months" } else { "" }) `
                        -SubscriptionId $sid -SubscriptionName $sname -Resource $kvName))
                }
            } catch {
                Add-ClassifiedErrorSet -Results $results -ControlIds @("8.3.11") -Message $_.Exception.Message `
                    -AuthzMessage "Insufficient permissions to list certificates. Grant the 'Key Vault Reader' data-plane role or a Key Vault access policy with Certificate List permission." `
                    -FirewallMessage "Key Vault firewall is blocking access. Add the audit machine's IP to the vault's firewall allowlist." `
                    -SubscriptionId $sid -SubscriptionName $sname -Resource $kvName
            }

            # 8.3.6 — RBAC authorization enabled
            $results.Add((New-CISResult `
                -ControlId "8.3.6" `
                -Status $(if ($rbac) { $script:PASS } else { $script:FAIL }) `
                -Details $(if ($rbac) { "RBAC authorization model enabled." } else { "Using legacy Vault Access Policy, not RBAC." }) `
                -Remediation $(if (-not $rbac) { "Key Vault > $kvName > Access configuration > Permission model > Azure RBAC" } else { "" }) `
                -SubscriptionId $sid -SubscriptionName $sname -Resource $kvName))

            # 8.3.5 — Purge protection enabled
            $results.Add((New-CISResult `
                -ControlId "8.3.5" `
                -Status $(if ($purge) { $script:PASS } else { $script:FAIL }) `
                -Details $(if ($purge) { "Purge protection enabled." } else { "Purge protection not enabled." }) `
                -Remediation $(if (-not $purge) { "Key Vault > $kvName > Properties > Enable purge protection" } else { "" }) `
                -SubscriptionId $sid -SubscriptionName $sname -Resource $kvName))

            # 8.3.7 — Public network access disabled
            $pubOk = $pub -eq "Disabled"
            $results.Add((New-CISResult `
                -ControlId "8.3.7" `
                -Status $(if ($pubOk) { $script:PASS } else { $script:FAIL }) `
                -Details $(if ($pubOk) { "Public network access: Disabled." } else { "Public network access: $pub." }) `
                -Remediation $(if (-not $pubOk) { "Key Vault > $kvName > Networking > Allow access from > Disable public access" } else { "" }) `
                -SubscriptionId $sid -SubscriptionName $sname -Resource $kvName))

            # 8.3.8 — Private endpoints configured
            $results.Add((New-CISResult `
                -ControlId "8.3.8" `
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
                        -ControlId "8.3.9" `
                        -Status $(if ($pass) { $script:PASS } else { $script:FAIL }) `
                        -Details $(if ($pass) { "All keys have automatic rotation configured." } else { "Keys without automatic rotation configured: $($noRotation -join ', ')" }) `
                        -Remediation $(if (-not $pass) { "Key Vault > $kvName > Keys > Rotation policy > Set rotation action" } else { "" }) `
                        -SubscriptionId $sid -SubscriptionName $sname -Resource $kvName))
                } else {
                    $results.Add((New-InfoResult "8.3.9" "No keys found in vault." $sid $sname $kvName))
                }
            } catch {
                Add-ClassifiedErrorSet -Results $results -ControlIds @("8.3.9") -Message $_.Exception.Message `
                    -AuthzMessage "Insufficient permissions to list keys. Grant the 'Key Vault Reader' data-plane role or a Key Vault access policy with Key List permission." `
                    -FirewallMessage "Key Vault firewall is blocking access. Add the audit machine's IP to the vault's firewall allowlist." `
                    -SubscriptionId $sid -SubscriptionName $sname -Resource $kvName
            }
        }
    }

    # ── 8.4.1 — Azure Bastion deployed (if VMs exist) ─────────────────────────
    if ($vmErr -or $bastionErr) {
        $bastionMsg = if ($vmErr) { "VM prefetch failed: $vmErr" } else { "Bastion prefetch failed: $bastionErr" }
        $results.Add((New-ErrorResult "8.4.1" $bastionMsg $sid $sname))
    } elseif ($vms.Count -eq 0) {
        $results.Add((New-InfoResult "8.4.1" "No VMs found in subscription." $sid $sname))
    } else {
        $hasBastion = $bastion.Count -gt 0
        $results.Add((New-CISResult `
            -ControlId "8.4.1" `
            -Status $(if ($hasBastion) { $script:PASS } else { $script:FAIL }) `
            -Details $(if ($hasBastion) { "Azure Bastion found: $(($bastion | ForEach-Object { [string]$_.name }) -join ', ')" } else { "No Azure Bastion found. $($vms.Count) VM(s) present." }) `
            -Remediation $(if (-not $hasBastion) { "Create an Azure Bastion host in a dedicated AzureBastionSubnet for secure VM access." } else { "" }) `
            -SubscriptionId $sid -SubscriptionName $sname))
    }

    # ── 8.5 — DDoS Network Protection on VNets ───────────────────────────────
    if ($vnetErr) {
        $results.Add((New-ErrorResult "8.5" "VNet prefetch failed: $vnetErr" $sid $sname))
    } elseif ($vnets.Count -eq 0) {
        $results.Add((New-InfoResult "8.5" "No VNets found." $sid $sname))
    } else {
        foreach ($vnet in $vnets) {
            $hasDdos = [string]$vnet.hasDdos -in @("True", "true", "1")
            $results.Add((New-CISResult `
                -ControlId "8.5" `
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
    $manual = @(
        @{ Id="8.1.3.2"; Msg="Manual verification required — Defender for Cloud > Environment settings > Defender for Servers > ensure the 'Vulnerability assessment for machines' component status is 'On'." }
        @{ Id="8.1.3.4"; Msg="Manual verification required — Defender for Cloud > Environment settings > Defender for Servers > ensure the 'Agentless scanning for machines' component status is 'On'." }
        @{ Id="8.1.3.5"; Msg="Manual verification required — Defender for Cloud > Environment settings > Defender for Servers > ensure the 'File Integrity Monitoring' component status is 'On'." }
        @{ Id="8.1.5.2"; Msg="Manual verification required — confirm that Microsoft Defender for Storage threat-protection alerts are reviewed and actioned by a responsible team." }
        @{ Id="8.1.11";  Msg="Manual verification required — Defender for Cloud > Environment settings > Security policy > ensure non-deprecated Microsoft Cloud Security Benchmark policy effects are not set to 'Disabled'." }
        @{ Id="8.1.16";  Msg="Manual verification required — confirm a Defender EASM workspace is deployed and monitoring the organisation's external attack surface." }
        @{ Id="8.2.1";   Msg="Manual verification required — for each IoT Hub, ensure Microsoft Defender for IoT is enabled." }
        @{ Id="8.3.10";  Msg="Manual verification required — where FIPS 140-2 Level 3 protection is required, confirm Azure Key Vault Managed HSM is used instead of the standard vault." }
    )

    $results = [System.Collections.Generic.List[object]]::new()
    foreach ($m in $manual) {
        $results.Add((New-ManualResult $m.Id $m.Msg))
    }
    return $results.ToArray()
}
