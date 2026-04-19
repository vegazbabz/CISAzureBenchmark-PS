# Section 6 — Monitoring & Management
# CIS Microsoft Azure Foundations Benchmark v5.0.0

function Invoke-Section6Checks {
    [CmdletBinding()]
    param(
        [string]$SubscriptionId,
        [string]$SubscriptionName,
        [hashtable]$PrefetchData
    )

    $results = [System.Collections.Generic.List[object]]::new()
    $sec     = "6 - Management & Governance"
    $sid     = $SubscriptionId
    $sname   = $SubscriptionName

    # ── 6.1.1.1 — Subscription diagnostic settings exist ─────────────────────
    try {
        $subDiagUri = "https://management.azure.com/subscriptions/$sid/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview"
        $r = Invoke-ArmRest -Uri $subDiagUri

        $settings = @()
        if ($r.Success -and $r.Data) {
            # REST endpoint returns {value: [...]}
            $raw = $r.Data
            if ($raw.PSObject.Properties['value']) {
                $settings = @($raw.value)
            } else {
                $settings = @($raw)
            }
        }
        $hasDiag  = $settings.Count -gt 0

        $results.Add((New-CISResult `
            -ControlId "6.1.1.1" `
            -Title "Ensure That a Diagnostic Setting Exists for the Subscription" `
            -Level 1 -Section $sec `
            -Status $(if ($hasDiag) { $script:PASS } else { $script:FAIL }) `
            -Details $(if ($hasDiag) { "Found $($settings.Count) subscription-level diagnostic setting(s)." } else { "No subscription-level diagnostic settings found." }) `
            -Remediation $(if (-not $hasDiag) { "Monitor > Activity Log > Export Activity Logs > Add diagnostic setting" } else { "" }) `
            -SubscriptionId $sid -SubscriptionName $sname))

        # ── 6.1.1.2 — Required log categories captured ─────────────────────
        # Even when a diagnostic setting exists it must capture: Security,
        # Administrative, Alert, and Policy log categories.
        try {
            $requiredCategories = @("security", "administrative", "alert", "policy")
            $foundCategories    = @()

            foreach ($setting in $settings) {
                $logsList = $setting.PSObject.Properties['logs']?.Value
                if ($logsList) {
                    foreach ($log in @($logsList)) {
                        if ([string]$log.enabled -eq "True" -or [string]$log.enabled -eq "true") {
                            $cat = [string]($log.PSObject.Properties['category']?.Value)
                            if ($cat) { $foundCategories += $cat.ToLower() }
                        }
                    }
                }
            }

            $foundCategories = @($foundCategories | Select-Object -Unique)
            $missingCats     = @($requiredCategories | Where-Object { $foundCategories -notcontains $_ })

            if ($settings.Count -eq 0) {
                $results.Add((New-CISResult `
                    -ControlId "6.1.1.2" `
                    -Title "Ensure Diagnostic Setting Captures Required Log Categories" `
                    -Level 1 -Section $sec -Status $script:FAIL `
                    -Details "No subscription diagnostic settings — cannot evaluate categories." `
                    -Remediation "Enable a diagnostic setting and configure all four categories: Security, Administrative, Alert, Policy." `
                    -SubscriptionId $sid -SubscriptionName $sname))
            } elseif ($missingCats.Count -eq 0) {
                $results.Add((New-CISResult `
                    -ControlId "6.1.1.2" `
                    -Title "Ensure Diagnostic Setting Captures Required Log Categories" `
                    -Level 1 -Section $sec -Status $script:PASS `
                    -Details "All required categories enabled: Security, Administrative, Alert, Policy." `
                    -SubscriptionId $sid -SubscriptionName $sname))
            } else {
                $results.Add((New-CISResult `
                    -ControlId "6.1.1.2" `
                    -Title "Ensure Diagnostic Setting Captures Required Log Categories" `
                    -Level 1 -Section $sec -Status $script:FAIL `
                    -Details "Missing required log categories: $($missingCats -join ', '). Found: $($foundCategories -join ', ')." `
                    -Remediation "Monitor > Activity Log > Export Activity Logs > Edit diagnostic setting > Enable: Administrative, Security, Alert, Policy" `
                    -SubscriptionId $sid -SubscriptionName $sname))
            }
        } catch {
            $results.Add((New-ErrorResult "6.1.1.2" "Ensure Diagnostic Setting Captures Required Log Categories" 1 $sec $_.Exception.Message $sid $sname))
        }
    } catch {
        $results.Add((New-ErrorResult "6.1.1.1" "Ensure That a Diagnostic Setting Exists for the Subscription" 1 $sec $_.Exception.Message $sid $sname))
        $results.Add((New-ErrorResult "6.1.1.2" "Ensure Diagnostic Setting Captures Required Log Categories" 1 $sec $_.Exception.Message $sid $sname))
    }

    # ── 6.1.1.3 — Subscription activity log retention >= 365 days ──────────────
    # Classic: Log Profile API. Modern (preferred since ~2022): Subscription Diagnostic Settings.
    # Both paths must be checked — modern Azure subscriptions use diagnostic settings exclusively.
    try {
        $logProfiles = @(Get-AzLogProfile -ErrorAction SilentlyContinue)

        if ($logProfiles.Count -gt 0) {
            # Legacy log profile found — evaluate retention
            $logProfile = $logProfiles | Select-Object -First 1
            $days    = if ($logProfile.RetentionPolicy) { [int]$logProfile.RetentionPolicy.Days } else { 0 }
            $enabled = $logProfile.RetentionPolicy -and $logProfile.RetentionPolicy.Enabled
            $pass    = -not $enabled -or $days -ge 365

            $results.Add((New-CISResult `
                -ControlId "6.1.1.3" `
                -Title "Ensure the Activity Retention Log Is Set to at Least One Year" `
                -Level 1 -Section $sec `
                -Status $(if ($pass) { $script:PASS } else { $script:FAIL }) `
                -Details "Log Profile retention: $days days (policy enabled: $enabled)." `
                -Remediation $(if (-not $pass) { "Monitor > Activity Log > Export > Retention >= 365 days" } else { "" }) `
                -SubscriptionId $sid -SubscriptionName $sname))
        } else {
            # No log profile — check modern subscription-level diagnostic settings.
            # Modern Azure subscriptions route activity logs via diagnostic settings, not log profiles.
            $rDiag = Invoke-ArmRest -Uri "https://management.azure.com/subscriptions/$sid/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview"

            $raw = if ($rDiag.Success -and $rDiag.Data) {
                if ($rDiag.Data.PSObject.Properties['value']) { @($rDiag.Data.value) }
                else { @($rDiag.Data) }
            } else { @() }

            # ARM REST wraps settings fields under .properties — normalize to a flat object
            # so all subsequent access ($_.logs, $_.workspaceId, etc.) is uniform and strict-mode-safe.
            $diagItems = @($raw | ForEach-Object {
                $src = if ($_.PSObject.Properties['properties'] -and $null -ne $_.properties) { $_.properties } else { $_ }
                [PSCustomObject]@{
                    name                        = [string]$_.name
                    logs                        = if ($src.PSObject.Properties['logs'] -and $null -ne $src.logs) { @($src.logs) } else { @() }
                    workspaceId                 = if ($src.PSObject.Properties['workspaceId'])                 { $src.workspaceId }                 else { $null }
                    storageAccountId            = if ($src.PSObject.Properties['storageAccountId'])            { $src.storageAccountId }            else { $null }
                    eventHubAuthorizationRuleId = if ($src.PSObject.Properties['eventHubAuthorizationRuleId']) { $src.eventHubAuthorizationRuleId } else { $null }
                }
            })

            $activeSetting = $diagItems | Where-Object {
                @($_.logs | Where-Object { $_.category -eq 'Administrative' -and [string]$_.enabled -eq 'True' }).Count -gt 0
            } | Select-Object -First 1

            if ($activeSetting) {
                $adminLog = @($activeSetting.logs) | Where-Object {
                    $_.category -eq 'Administrative' -and [string]$_.enabled -eq 'True'
                } | Select-Object -First 1

                if ($activeSetting.workspaceId) {
                    $destDesc = "Log Analytics ($($activeSetting.workspaceId -replace '.*/workspaces/', ''))"
                    $results.Add((New-CISResult `
                        -ControlId "6.1.1.3" `
                        -Title "Ensure the Activity Retention Log Is Set to at Least One Year" `
                        -Level 1 -Section $sec -Status $script:PASS `
                        -Details "Subscription diagnostic setting '$($activeSetting.name)' routes Administrative logs to $destDesc. Verify destination retention >= 365 days." `
                        -Remediation "" `
                        -SubscriptionId $sid -SubscriptionName $sname))
                } elseif ($activeSetting.storageAccountId) {
                    # For storage-account destinations the retentionPolicy on the diagnostic
                    # setting's log entry defines how long data is kept in that account.
                    # retentionPolicy.enabled = false means indefinite (unlimited) — acceptable.
                    # retentionPolicy.enabled = true requires days >= 365 per CIS 6.1.1.3.
                    $retPolicy  = $adminLog.retentionPolicy
                    $retEnabled = $retPolicy -and [bool]$retPolicy.enabled
                    $retDays    = if ($retPolicy) { [int]$retPolicy.days } else { 0 }
                    $retOk      = -not $retEnabled -or $retDays -ge 365
                    $saName     = $activeSetting.storageAccountId -replace '.*/storageAccounts/', ''
                    $retDesc    = if (-not $retEnabled) { "indefinite retention" } else { "$retDays-day retention" }

                    $results.Add((New-CISResult `
                        -ControlId "6.1.1.3" `
                        -Title "Ensure the Activity Retention Log Is Set to at Least One Year" `
                        -Level 1 -Section $sec `
                        -Status $(if ($retOk) { $script:PASS } else { $script:FAIL }) `
                        -Details "Subscription diagnostic setting '$($activeSetting.name)' routes Administrative logs to Storage ($saName) with $retDesc." `
                        -Remediation $(if (-not $retOk) { "Monitor > Diagnostic settings > $($activeSetting.name) > Enable retention >= 365 days on Administrative log category" } else { "" }) `
                        -SubscriptionId $sid -SubscriptionName $sname))
                } elseif ($activeSetting.eventHubAuthorizationRuleId) {
                    $results.Add((New-CISResult `
                        -ControlId "6.1.1.3" `
                        -Title "Ensure the Activity Retention Log Is Set to at Least One Year" `
                        -Level 1 -Section $sec -Status $script:PASS `
                        -Details "Subscription diagnostic setting '$($activeSetting.name)' routes Administrative logs to Event Hub. Verify destination retention >= 365 days." `
                        -Remediation "" `
                        -SubscriptionId $sid -SubscriptionName $sname))
                } else {
                    $results.Add((New-CISResult `
                        -ControlId "6.1.1.3" `
                        -Title "Ensure the Activity Retention Log Is Set to at Least One Year" `
                        -Level 1 -Section $sec -Status $script:PASS `
                        -Details "Subscription diagnostic setting '$($activeSetting.name)' routes Administrative logs to an active destination. Verify destination retention >= 365 days." `
                        -Remediation "" `
                        -SubscriptionId $sid -SubscriptionName $sname))
                }
            } else {
                $results.Add((New-CISResult `
                    -ControlId "6.1.1.3" `
                    -Title "Ensure the Activity Retention Log Is Set to at Least One Year" `
                    -Level 1 -Section $sec -Status $script:FAIL `
                    -Details "No activity log profile or subscription diagnostic setting with Administrative logs enabled found." `
                    -Remediation "Monitor > Activity Log > Diagnostic settings > Add setting > Enable Administrative logs > Send to Log Analytics (retention >= 365 days)" `
                    -SubscriptionId $sid -SubscriptionName $sname))
            }
        }
    } catch {
        $results.Add((New-ErrorResult "6.1.1.3" "Ensure the Activity Retention Log Is Set to at Least One Year" 1 $sec $_.Exception.Message $sid $sname))
    }

    # ── 6.1.1.4 — Key Vault diagnostic logging ───────────────────────────────
    try {
        $kvs = @(Get-PrefetchData -PrefetchData $PrefetchData -Key "keyvaults" -SubscriptionId $sid)

        if ($kvs.Count -eq 0) {
            $results.Add((New-InfoResult "6.1.1.4" "Ensure Diagnostic Logging for Key Vaults Is Enabled" 1 $sec "No Key Vaults found." $sid $sname))
        } else {
            foreach ($kv in $kvs) {
                $kvName  = [string]$kv.name
                $diagList = @(Get-AzDiagnosticSetting -ResourceId ([string]$kv.id) -ErrorAction SilentlyContinue -WarningAction SilentlyContinue)

                # Accept 'audit' or 'allLogs' category group — both satisfy the requirement
                $hasAudit = $false
                foreach ($setting in $diagList) {
                    # @() coercion handles both the current fixed-array and the upcoming List<T>
                    # type change in Az.Monitor 7.0 (Get-AzDiagnosticSetting breaking change)
                    foreach ($log in @($setting.Log)) {
                        if (-not $log.Enabled) { continue }
                        $val = if ($log.CategoryGroup) { $log.CategoryGroup } else { $log.Category }
                        if ($val -imatch "^(audit|allLogs)$") { $hasAudit = $true; break }
                    }
                    if ($hasAudit) { break }
                }

                $results.Add((New-CISResult `
                    -ControlId "6.1.1.4" `
                    -Title "Ensure Diagnostic Logging for Key Vaults Is Enabled" `
                    -Level 1 -Section $sec `
                    -Status $(if ($hasAudit) { $script:PASS } else { $script:FAIL }) `
                    -Details $(if ($hasAudit) { "Vault '$kvName': audit/allLogs diagnostic logging enabled." } else { "Vault '$kvName': no audit logging enabled (requires 'audit' or 'allLogs' category)." }) `
                    -Remediation $(if (-not $hasAudit) { "Key Vault > $kvName > Diagnostic Settings > Add setting > Enable audit or allLogs category" } else { "" }) `
                    -SubscriptionId $sid -SubscriptionName $sname -Resource $kvName))
            }
        }
    } catch {
        $results.Add((New-ErrorResult "6.1.1.4" "Ensure Diagnostic Logging for Key Vaults Is Enabled" 1 $sec $_.Exception.Message $sid $sname))
    }

    # ── 6.1.1.6 — App Service resource logs ──────────────────────────────────
    # Mirrors the Azure built-in policy "App Service apps should have resource
    # logs enabled" — function apps are excluded, only standard web apps checked.
    # Compliant if any diagnostic setting has an enabled log either routed to
    # Log Analytics (no retention requirement) or to storage with >= 365 day
    # retention (or infinite / retention disabled).
    try {
        $apps = @(Get-PrefetchData -PrefetchData $PrefetchData -Key "app_services" -SubscriptionId $sid)
        # Exclude function apps (CIS policy scopes to kind != functionapp)
        $webApps = @($apps | Where-Object { [string]$_.kind -notmatch "functionapp" })

        if ($apps.Count -eq 0) {
            $results.Add((New-InfoResult "6.1.1.6" "Ensure App Service Resource Logs Are Enabled" 2 $sec "No App Services found." $sid $sname))
        } elseif ($webApps.Count -eq 0) {
            $results.Add((New-InfoResult "6.1.1.6" "Ensure App Service Resource Logs Are Enabled" 2 $sec "No standard App Services found ($($apps.Count) function app(s) excluded)." $sid $sname))
        } else {
            foreach ($app in $webApps) {
                $appName  = [string]$app.name
                $appId    = [string]$app.id
                $appKind  = [string]$app.kind
                $diagList = @(Get-AzDiagnosticSetting -ResourceId $appId -ErrorAction SilentlyContinue -WarningAction SilentlyContinue)
                $compliant = $false

                foreach ($setting in $diagList) {
                    if ($compliant) { break }
                    $hasStorage = [bool]$setting.StorageAccountId
                    # @() coercion handles both the current fixed-array and the upcoming List<T>
                    # type change in Az.Monitor 7.0 (Get-AzDiagnosticSetting breaking change)
                    foreach ($log in @($setting.Log)) {
                        if (-not $log.Enabled) { continue }
                        $retEnabled = $log.RetentionPolicyEnabled
                        $retDays    = [int]$log.RetentionPolicyDay

                        # Branch A: retention enforced, infinite (0) or >= 365 days
                        if ($retEnabled -and ($retDays -eq 0 -or $retDays -ge 365)) { $compliant = $true; break }
                        # Branch B: no storage account → Log Analytics, no retention needed
                        if (-not $hasStorage) { $compliant = $true; break }
                        # Branch B variant: retention policy not enforced
                        if (-not $retEnabled) { $compliant = $true; break }
                    }
                }

                if ($compliant) {
                    $results.Add((New-CISResult `
                        -ControlId "6.1.1.6" -Title "Ensure App Service Resource Logs Are Enabled" `
                        -Level 2 -Section $sec -Status $script:PASS `
                        -Details "App '$appName' (kind: $appKind): compliant diagnostic setting found." `
                        -SubscriptionId $sid -SubscriptionName $sname -Resource $appName))
                } elseif ($diagList.Count -gt 0) {
                    $results.Add((New-CISResult `
                        -ControlId "6.1.1.6" -Title "Ensure App Service Resource Logs Are Enabled" `
                        -Level 2 -Section $sec -Status $script:FAIL `
                        -Details "App '$appName': diagnostic settings exist but no log meets the retention requirement (>= 365 days or Log Analytics destination)." `
                        -Remediation "App Service > $appName > Monitoring > Diagnostic settings > Send logs to Log Analytics, or set storage retention >= 365 days." `
                        -SubscriptionId $sid -SubscriptionName $sname -Resource $appName))
                } else {
                    $results.Add((New-CISResult `
                        -ControlId "6.1.1.6" -Title "Ensure App Service Resource Logs Are Enabled" `
                        -Level 2 -Section $sec -Status $script:FAIL `
                        -Details "App '$appName': no diagnostic settings configured." `
                        -Remediation "App Service > $appName > Monitoring > Diagnostic settings > Add diagnostic setting > Enable resource logs to Log Analytics." `
                        -SubscriptionId $sid -SubscriptionName $sname -Resource $appName))
                }
            }
        }
    } catch {
        $results.Add((New-ErrorResult "6.1.1.6" "Ensure App Service Resource Logs Are Enabled" 2 $sec $_.Exception.Message $sid $sname))
    }

    # ── 6.1.2.x — Activity log alerts (CIS v5.0.0 controls 1–11) ────────────
    # IDs and operations aligned with Python implementation / CIS benchmark PDF.
    # 6.1.2.1–10: operationName field matching.
    # 6.1.2.11: category field (ServiceHealth) — different check logic.
    try {
        $alerts = @(Get-AzActivityLogAlert -ErrorAction SilentlyContinue)

        $alertChecks = @(
            @{ Id="6.1.2.1";  Op="microsoft.authorization/policyassignments/write";           Title="Ensure Activity Log Alert: Create Policy Assignment" }
            @{ Id="6.1.2.2";  Op="microsoft.authorization/policyassignments/delete";          Title="Ensure Activity Log Alert: Delete Policy Assignment" }
            @{ Id="6.1.2.3";  Op="microsoft.network/networksecuritygroups/write";             Title="Ensure Activity Log Alert: Create/Update NSG" }
            @{ Id="6.1.2.4";  Op="microsoft.network/networksecuritygroups/delete";            Title="Ensure Activity Log Alert: Delete NSG" }
            @{ Id="6.1.2.5";  Op="microsoft.security/securitysolutions/write";               Title="Ensure Activity Log Alert: Create/Update Security Solution" }
            @{ Id="6.1.2.6";  Op="microsoft.security/securitysolutions/delete";              Title="Ensure Activity Log Alert: Delete Security Solution" }
            @{ Id="6.1.2.7";  Op="microsoft.sql/servers/firewallrules/write";                Title="Ensure Activity Log Alert: Create/Update SQL Server Firewall Rule" }
            @{ Id="6.1.2.8";  Op="microsoft.sql/servers/firewallrules/delete";               Title="Ensure Activity Log Alert: Delete SQL Server Firewall Rule" }
            @{ Id="6.1.2.9";  Op="microsoft.network/publicipaddresses/write";                Title="Ensure Activity Log Alert: Create/Update Public IP Address" }
            @{ Id="6.1.2.10"; Op="microsoft.network/publicipaddresses/delete";               Title="Ensure Activity Log Alert: Delete Public IP Address" }
        )

        foreach ($ac in $alertChecks) {
            $hasAlert = @($alerts | Where-Object {
                $allOf = $_.Condition?.AllOf
                if (-not $allOf) { return $false }
                @($allOf | Where-Object {
                    $_.Field -eq "operationName" -and $_.Equal -ieq $ac.Op
                }).Count -gt 0
            }).Count -gt 0
            $pass = $hasAlert

            $results.Add((New-CISResult `
                -ControlId $ac.Id `
                -Title $ac.Title `
                -Level 1 -Section $sec `
                -Status $(if ($pass) { $script:PASS } else { $script:FAIL }) `
                -Details $(if ($pass) { "Activity log alert configured for operation: $($ac.Op)" } else { "No activity log alert found for: $($ac.Op)" }) `
                -Remediation $(if (-not $pass) { "Monitor > Alerts > + Create > Activity Log > Operation name: $($ac.Op)" } else { "" }) `
                -SubscriptionId $sid -SubscriptionName $sname))
        }

        # 6.1.2.11 — Service Health alert (category = ServiceHealth, not operationName)
        $shAlert = @($alerts | Where-Object {
            $allOf = $_.Condition?.AllOf
            if (-not $allOf) { return $false }
            @($allOf | Where-Object {
                $_.Field -eq "category" -and $_.Equal -ieq "servicehealth"
            }).Count -gt 0
        }).Count -gt 0
        $shPass = $shAlert

        $results.Add((New-CISResult `
            -ControlId "6.1.2.11" `
            -Title "Ensure Activity Log Alert: Service Health Notifications" `
            -Level 1 -Section $sec `
            -Status $(if ($shPass) { $script:PASS } else { $script:FAIL }) `
            -Details $(if ($shPass) { "Service Health activity log alert found." } else { "No Service Health activity log alert found." }) `
            -Remediation $(if (-not $shPass) { "Monitor > Alerts > + Create > Activity Log > Category = Service Health" } else { "" }) `
            -SubscriptionId $sid -SubscriptionName $sname))

    } catch {
        foreach ($ac in @("6.1.2.1","6.1.2.2","6.1.2.3","6.1.2.4","6.1.2.5","6.1.2.6","6.1.2.7","6.1.2.8","6.1.2.9","6.1.2.10","6.1.2.11")) {
            $results.Add((New-ErrorResult $ac "Activity Log Alert Check" 1 $sec $_.Exception.Message $sid $sname))
        }
    }

    # ── 6.1.3.1 — Application Insights configured ────────────────────────────
    try {
        $aiUrl = "https://management.azure.com/subscriptions/$sid/providers/microsoft.insights/components?api-version=2020-02-02"
        $r = Invoke-AzRestPaged -Uri $aiUrl

        $hasAppInsights = $r.Success -and $r.Data -and ($r.Data | Measure-Object).Count -gt 0
        $count = if ($r.Success -and $r.Data) { ($r.Data | Measure-Object).Count } else { 0 }

        $results.Add((New-CISResult `
            -ControlId "6.1.3.1" `
            -Title "Ensure Application Insights Are Configured" `
            -Level 2 -Section $sec `
            -Status $(if ($hasAppInsights) { $script:PASS } else { $script:FAIL }) `
            -Details $(if ($hasAppInsights) { "$count Application Insights component(s) found." } else { "No Application Insights components found." }) `
            -Remediation $(if (-not $hasAppInsights) { "Create Application Insights component via Azure Portal > Monitor > Application Insights > + Create" } else { "" }) `
            -SubscriptionId $sid -SubscriptionName $sname))
    } catch {
        $results.Add((New-ErrorResult "6.1.3.1" "Ensure Application Insights Are Configured" 2 $sec $_.Exception.Message $sid $sname))
    }

    return $results.ToArray()
}
