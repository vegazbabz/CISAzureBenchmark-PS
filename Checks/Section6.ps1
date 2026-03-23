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
    $sec     = "6 - Management and Governance"
    $sid     = $SubscriptionId
    $sname   = $SubscriptionName

    # ── 6.1.1.1 — Subscription diagnostic settings exist ─────────────────────
    try {
        $r = Invoke-AzCli -Arguments @(
            "monitor", "diagnostic-settings", "subscription", "list",
            "--subscription", $sid
        ) -TimeoutSec $script:TIMEOUTS.default

        $settings = @()
        if ($r.Success -and $r.Data) {
            # CLI returns {value: [...]} for subscription diagnostic settings
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

    # ── 6.1.1.3 — Subscription activity log retention >= 365 days (PS bonus) ─
    # Note: This is a PS-specific check (not in CIS Python implementation).
    # Log profiles are the classic mechanism; modern approach uses diagnostic settings.
    try {
        $r = Invoke-AzCli -Arguments @(
            "monitor", "log-profiles", "list",
            "--subscription", $sid
        ) -TimeoutSec $script:TIMEOUTS.default

        if (-not $r.Success -or -not $r.Data -or ($r.Data | Measure-Object).Count -eq 0) {
            $results.Add((New-CISResult `
                -ControlId "6.1.1.3" `
                -Title "Ensure the Activity Retention Log Is Set to at Least One Year" `
                -Level 1 -Section $sec -Status $script:FAIL `
                -Details "No activity log profile found. Retention not configured." `
                -Remediation "Monitor > Activity Log > Export Activity Log > Add diagnostic setting with retention >= 365 days" `
                -SubscriptionId $sid -SubscriptionName $sname))
        } else {
            $logProfile = $r.Data | Select-Object -First 1
            $retPol  = $logProfile.PSObject.Properties['retentionPolicy']?.Value
            $days    = if ($retPol -and $retPol.days) { [int]$retPol.days } else { 0 }
            $enabled = $retPol -and ([string]$retPol.enabled -eq "True")
            $pass    = -not $enabled -or $days -ge 365

            $results.Add((New-CISResult `
                -ControlId "6.1.1.3" `
                -Title "Ensure the Activity Retention Log Is Set to at Least One Year" `
                -Level 1 -Section $sec `
                -Status $(if ($pass) { $script:PASS } else { $script:FAIL }) `
                -Details "Retention: $days days (enabled: $enabled)." `
                -Remediation $(if (-not $pass) { "Monitor > Activity Log > Export > Retention >= 365 days" } else { "" }) `
                -SubscriptionId $sid -SubscriptionName $sname))
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
                $kvName = [string]$kv.name
                $r = Invoke-AzCli -Arguments @(
                    "monitor", "diagnostic-settings", "list",
                    "--resource", [string]$kv.id
                ) -TimeoutSec $script:TIMEOUTS.default

                if (-not $r.Success) {
                    $results.Add((New-ErrorResult "6.1.1.4" "Ensure Diagnostic Logging for Key Vaults Is Enabled" 1 $sec $r.Error $sid $sname $kvName))
                    continue
                }

                $diagList = @()
                if ($r.Data) { $diagList = @($r.Data) }

                # Accept 'audit' or 'allLogs' category group — both satisfy the requirement
                $hasAudit = $false
                foreach ($setting in $diagList) {
                    foreach ($log in @($setting.logs)) {
                        $enabled = [string]$log.enabled -eq "True" -or [string]$log.enabled -eq "true"
                        if (-not $enabled) { continue }
                        $catGrp = [string]$log.PSObject.Properties['categoryGroup']?.Value
                        $cat    = [string]$log.PSObject.Properties['category']?.Value
                        $val    = if ($catGrp) { $catGrp } else { $cat }
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
                $appName = [string]$app.name
                $appId   = [string]$app.id
                $appKind = [string]$app.kind

                $r = Invoke-AzCli -Arguments @(
                    "monitor", "diagnostic-settings", "list",
                    "--resource", $appId
                ) -TimeoutSec $script:TIMEOUTS.default

                if (-not $r.Success) {
                    $results.Add((New-ErrorResult "6.1.1.6" "Ensure App Service Resource Logs Are Enabled" 2 $sec $r.Error $sid $sname $appName))
                    continue
                }

                $diagList  = @()
                if ($r.Data) { $diagList = @($r.Data) }
                $compliant = $false

                foreach ($setting in $diagList) {
                    if ($compliant) { break }
                    $hasStorage = [bool]([string]$setting.PSObject.Properties['storageAccountId']?.Value)

                    foreach ($log in @($setting.logs)) {
                        $logEnabled = [string]$log.enabled -eq "True" -or [string]$log.enabled -eq "true"
                        if (-not $logEnabled) { continue }

                        $retPol     = $log.PSObject.Properties['retentionPolicy']?.Value
                        $retEnabled = $retPol -and ([string]$retPol.enabled -eq "True" -or [string]$retPol.enabled -eq "true")
                        $retDays    = if ($retPol -and $retPol.days) { [int]$retPol.days } else { 0 }

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
        $r = Invoke-AzCli -Arguments @(
            "monitor", "activity-log", "alert", "list",
            "--subscription", $sid
        ) -TimeoutSec $script:TIMEOUTS.activity_log

        $alerts = @()
        if ($r.Success -and $r.Data) { $alerts = @($r.Data) }

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
                $cond  = $_.PSObject.Properties['condition']?.Value
                if (-not $cond) { return $false }
                $allOf = $cond.PSObject.Properties['allOf']?.Value
                if (-not $allOf) { return $false }
                @($allOf | Where-Object {
                    [string]($_.PSObject.Properties['field']?.Value)  -eq "operationName" -and
                    [string]($_.PSObject.Properties['equals']?.Value) -ieq $ac.Op
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
            $cond  = $_.PSObject.Properties['condition']?.Value
            if (-not $cond) { return $false }
            $allOf = $cond.PSObject.Properties['allOf']?.Value
            if (-not $allOf) { return $false }
            @($allOf | Where-Object {
                [string]($_.PSObject.Properties['field']?.Value)  -eq "category" -and
                [string]($_.PSObject.Properties['equals']?.Value) -ieq "servicehealth"
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
        $r = Invoke-AzRestPaged -Uri $aiUrl -TimeoutSec $script:TIMEOUTS.default

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
