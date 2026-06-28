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
            -Title "Ensure that a 'Diagnostic Setting' Exists for Subscription Activity Logs" `
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
                    -Title "Ensure Diagnostic Setting Captures Appropriate Categories" `
                    -Level 1 -Section $sec -Status $script:FAIL `
                    -Details "No subscription diagnostic settings — cannot evaluate categories." `
                    -Remediation "Enable a diagnostic setting and configure all four categories: Security, Administrative, Alert, Policy." `
                    -SubscriptionId $sid -SubscriptionName $sname))
            } elseif ($missingCats.Count -eq 0) {
                $results.Add((New-CISResult `
                    -ControlId "6.1.1.2" `
                    -Title "Ensure Diagnostic Setting Captures Appropriate Categories" `
                    -Level 1 -Section $sec -Status $script:PASS `
                    -Details "All required categories enabled: Security, Administrative, Alert, Policy." `
                    -SubscriptionId $sid -SubscriptionName $sname))
            } else {
                $results.Add((New-CISResult `
                    -ControlId "6.1.1.2" `
                    -Title "Ensure Diagnostic Setting Captures Appropriate Categories" `
                    -Level 1 -Section $sec -Status $script:FAIL `
                    -Details "Missing required log categories: $($missingCats -join ', '). Found: $($foundCategories -join ', ')." `
                    -Remediation "Monitor > Activity Log > Export Activity Logs > Edit diagnostic setting > Enable: Administrative, Security, Alert, Policy" `
                    -SubscriptionId $sid -SubscriptionName $sname))
            }
        } catch {
            $results.Add((New-ErrorResult "6.1.1.2" "Ensure Diagnostic Setting Captures Appropriate Categories" 1 $sec $_.Exception.Message $sid $sname))
        }
    } catch {
        $results.Add((New-ErrorResult "6.1.1.1" "Ensure that a 'Diagnostic Setting' Exists for Subscription Activity Logs" 1 $sec $_.Exception.Message $sid $sname))
        $results.Add((New-ErrorResult "6.1.1.2" "Ensure Diagnostic Setting Captures Appropriate Categories" 1 $sec $_.Exception.Message $sid $sname))
    }

    # ── 6.1.1.4 — Key Vault diagnostic logging ───────────────────────────────
    try {
        $kvs = @(Get-PrefetchData -PrefetchData $PrefetchData -Key "keyvaults" -SubscriptionId $sid)

        if ($kvs.Count -eq 0) {
            $results.Add((New-InfoResult "6.1.1.4" "Ensure that Logging for Azure Key Vault is 'Enabled'" 1 $sec "No Key Vaults found." $sid $sname))
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
                    -Title "Ensure that Logging for Azure Key Vault is 'Enabled'" `
                    -Level 1 -Section $sec `
                    -Status $(if ($hasAudit) { $script:PASS } else { $script:FAIL }) `
                    -Details $(if ($hasAudit) { "Vault '$kvName': audit/allLogs diagnostic logging enabled." } else { "Vault '$kvName': no audit logging enabled (requires 'audit' or 'allLogs' category)." }) `
                    -Remediation $(if (-not $hasAudit) { "Key Vault > $kvName > Diagnostic Settings > Add setting > Enable audit or allLogs category" } else { "" }) `
                    -SubscriptionId $sid -SubscriptionName $sname -Resource $kvName))
            }
        }
    } catch {
        $results.Add((New-ErrorResult "6.1.1.4" "Ensure that Logging for Azure Key Vault is 'Enabled'" 1 $sec $_.Exception.Message $sid $sname))
    }

    # ── 6.1.2.x — Activity log alerts (CIS v5.0.0 controls 1–11) ────────────
    # IDs and operations aligned with Python implementation / CIS benchmark PDF.
    # 6.1.2.1–10: operationName field matching.
    # 6.1.2.11: category field (ServiceHealth) — different check logic.
    try {
        $alerts = @(Get-AzActivityLogAlert -ErrorAction SilentlyContinue)

        $alertChecks = @(
            @{ Id="6.1.2.1";  Op="microsoft.authorization/policyassignments/write";           Title="Ensure that Activity Log Alert Exists for Create Policy Assignment" }
            @{ Id="6.1.2.2";  Op="microsoft.authorization/policyassignments/delete";          Title="Ensure that Activity Log Alert exists for Delete Policy Assignment" }
            @{ Id="6.1.2.3";  Op="microsoft.network/networksecuritygroups/write";             Title="Ensure that Activity Log Alert Exists for Create or Update Network Security Group" }
            @{ Id="6.1.2.4";  Op="microsoft.network/networksecuritygroups/delete";            Title="Ensure that Activity Log Alert Exists for Delete Network Security Group" }
            @{ Id="6.1.2.5";  Op="microsoft.security/securitysolutions/write";               Title="Ensure that Activity Log Alert Exists for Create or Update Security Solution" }
            @{ Id="6.1.2.6";  Op="microsoft.security/securitysolutions/delete";              Title="Ensure that Activity Log Alert Exists for Delete Security Solution" }
            @{ Id="6.1.2.7";  Op="microsoft.sql/servers/firewallrules/write";                Title="Ensure that Activity Log Alert Exists for Create or Update SQL Server Firewall Rule" }
            @{ Id="6.1.2.8";  Op="microsoft.sql/servers/firewallrules/delete";               Title="Ensure that Activity Log Alert Exists for Delete SQL Server Firewall Rule" }
            @{ Id="6.1.2.9";  Op="microsoft.network/publicipaddresses/write";                Title="Ensure that Activity Log Alert Exists for Create or Update Public IP Address rule" }
            @{ Id="6.1.2.10"; Op="microsoft.network/publicipaddresses/delete";               Title="Ensure that Activity Log Alert Exists for Delete Public IP Address rule" }
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
            -Title "Ensure that an Activity Log Alert Exists for Service Health" `
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
            -Title "Ensure Application Insights are Configured" `
            -Level 2 -Section $sec `
            -Status $(if ($hasAppInsights) { $script:PASS } else { $script:FAIL }) `
            -Details $(if ($hasAppInsights) { "$count Application Insights component(s) found." } else { "No Application Insights components found." }) `
            -Remediation $(if (-not $hasAppInsights) { "Create Application Insights component via Azure Portal > Monitor > Application Insights > + Create" } else { "" }) `
            -SubscriptionId $sid -SubscriptionName $sname))
    } catch {
        $results.Add((New-ErrorResult "6.1.3.1" "Ensure Application Insights are Configured" 2 $sec $_.Exception.Message $sid $sname))
    }

    return $results.ToArray()
}

function Invoke-Section6TenantChecks {
    <#
    .SYNOPSIS
    Tenant-level Section 6 controls that v6 defines as Manual (no reliable automated
    read) — surfaced once so the report mirrors the benchmark's control set.
    #>
    $sec = "6 - Management & Governance"
    $manual = @(
        @{ Id="6.1.1.3"; Lvl=2; Title="Ensure the Storage Account Containing the Container with Activity Logs is Encrypted with Customer-managed Key (CMK)"; Msg="Manual verification required — confirm the storage account holding the activity-log container is encrypted with a customer-managed key (CMK) in Azure Key Vault." }
        @{ Id="6.1.1.5"; Lvl=2; Title="Ensure that Network Security Group Flow Logs are Captured and Sent to Log Analytics"; Msg="Manual verification required — Network Watcher > NSG flow logs: ensure flow logs are enabled and traffic analytics sends data to a Log Analytics workspace." }
        @{ Id="6.1.1.6"; Lvl=2; Title="Ensure that Virtual Network Flow Logs are Captured and Sent to Log Analytics"; Msg="Manual verification required — Network Watcher > VNet flow logs: ensure flow logs are enabled and traffic analytics sends data to a Log Analytics workspace." }
        @{ Id="6.1.1.7"; Lvl=2; Title="Ensure that a Microsoft Entra Diagnostic Setting Exists to Send Microsoft Graph Activity Logs to an Appropriate Destination"; Msg="Manual verification required — Microsoft Entra ID > Diagnostic settings: ensure MicrosoftGraphActivityLogs are sent to an appropriate destination." }
        @{ Id="6.1.1.8"; Lvl=2; Title="Ensure that a Microsoft Entra Diagnostic Setting Exists to Send Microsoft Entra Activity Logs to an Appropriate Destination"; Msg="Manual verification required — Microsoft Entra ID > Diagnostic settings: ensure Entra activity logs (AuditLogs, SignInLogs, etc.) are sent to an appropriate destination." }
        @{ Id="6.1.1.9"; Lvl=2; Title="Ensure that Intune Logs are Captured and Sent to Log Analytics"; Msg="Manual verification required — Intune (Microsoft Entra) > Diagnostic settings: ensure Intune audit and operational logs are sent to a Log Analytics workspace." }
        @{ Id="6.1.4";   Lvl=1; Title="Ensure that Azure Monitor Resource Logging is Enabled for All Services that Support it"; Msg="Manual verification required — review Azure Policy compliance (e.g. 'Audit diagnostic setting') to confirm resource logging is enabled across all supported services." }
        @{ Id="6.1.5";   Lvl=2; Title="Ensure Basic, Free, and Consumption SKUs are not used on Production artifacts requiring monitoring and SLA"; Msg="Manual verification required — confirm production artifacts that require monitoring and an SLA are not running on Basic, Free, or Consumption SKUs." }
        @{ Id="6.2";     Lvl=2; Title="Ensure that Resource Locks are set for Mission-Critical Azure Resources"; Msg="Manual verification required — confirm CanNotDelete or ReadOnly resource locks are applied to mission-critical resources." }
    )

    $results = [System.Collections.Generic.List[object]]::new()
    foreach ($m in $manual) {
        $results.Add((New-ManualResult $m.Id $m.Title $m.Lvl $sec $m.Msg))
    }
    return $results.ToArray()
}
