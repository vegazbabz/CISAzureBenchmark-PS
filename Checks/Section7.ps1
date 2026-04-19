# Section 7 — Networking Services
# CIS Microsoft Azure Foundations Benchmark v5.0.0

function Invoke-Section7Checks {
    [CmdletBinding()]
    param(
        [string]$SubscriptionId,
        [string]$SubscriptionName,
        [hashtable]$PrefetchData
    )

    $results = [System.Collections.Generic.List[object]]::new()
    $sec     = "7 - Networking Services"
    $sid     = $SubscriptionId
    $sname   = $SubscriptionName

    $nsgs        = @(Get-PrefetchData -PrefetchData $PrefetchData -Key "nsgs"         -SubscriptionId $sid)
    $appGateways = @(Get-PrefetchData -PrefetchData $PrefetchData -Key "app_gateways" -SubscriptionId $sid)
    $watchers    = @(Get-PrefetchData -PrefetchData $PrefetchData -Key "watchers"     -SubscriptionId $sid)
    $locations   = @(Get-PrefetchData -PrefetchData $PrefetchData -Key "locations"    -SubscriptionId $sid)
    $wafPolicies = @(Get-PrefetchData -PrefetchData $PrefetchData -Key "waf_policies" -SubscriptionId $sid)


    # ── 7.1 — RDP (3389) not open from internet ──────────────────────────────
    try {
        if ($nsgs.Count -eq 0) {
            $results.Add((New-InfoResult "7.1" "Ensure RDP Access From the Internet Is Evaluated and Restricted" 1 $sec "No NSGs found." $sid $sname))
        } else {
            foreach ($nsg in $nsgs) {
                $rules    = @($nsg.rules)
                $badRules = @(Get-NsgBadRules -Rules $rules -Ports @(3389) -Protocols @("TCP","Tcp","*"))
                $pass     = $badRules.Count -eq 0
                $results.Add((New-CISResult `
                    -ControlId "7.1" `
                    -Title "Ensure RDP Access From the Internet Is Evaluated and Restricted" `
                    -Level 1 -Section $sec `
                    -Status $(if ($pass) { $script:PASS } else { $script:FAIL }) `
                    -Details $(if ($pass) { "No rules allow RDP from internet." } else { "Rule(s) allow RDP (3389) from internet: $($badRules -join ', ')" }) `
                    -Remediation $(if (-not $pass) { "NSG > $([string]$nsg.name) > Inbound security rules > Remove/restrict rules exposing port 3389" } else { "" }) `
                    -SubscriptionId $sid -SubscriptionName $sname -Resource ([string]$nsg.name)))
            }
        }
    } catch {
        $results.Add((New-ErrorResult "7.1" "Ensure RDP Access From the Internet Is Evaluated and Restricted" 1 $sec $_.Exception.Message $sid $sname))
    }

    # ── 7.2 — SSH (22) not open from internet ────────────────────────────────
    try {
        if ($nsgs.Count -eq 0) {
            $results.Add((New-InfoResult "7.2" "Ensure SSH Access From the Internet Is Evaluated and Restricted" 1 $sec "No NSGs found." $sid $sname))
        } else {
            foreach ($nsg in $nsgs) {
                $rules    = @($nsg.rules)
                $badRules = @(Get-NsgBadRules -Rules $rules -Ports @(22) -Protocols @("TCP","Tcp","*"))
                $pass     = $badRules.Count -eq 0
                $results.Add((New-CISResult `
                    -ControlId "7.2" `
                    -Title "Ensure SSH Access From the Internet Is Evaluated and Restricted" `
                    -Level 1 -Section $sec `
                    -Status $(if ($pass) { $script:PASS } else { $script:FAIL }) `
                    -Details $(if ($pass) { "No rules allow SSH from internet." } else { "Rule(s) allow SSH (22) from internet: $($badRules -join ', ')" }) `
                    -Remediation $(if (-not $pass) { "NSG > $([string]$nsg.name) > Inbound security rules > Remove/restrict rules exposing port 22" } else { "" }) `
                    -SubscriptionId $sid -SubscriptionName $sname -Resource ([string]$nsg.name)))
            }
        }
    } catch {
        $results.Add((New-ErrorResult "7.2" "Ensure SSH Access From the Internet Is Evaluated and Restricted" 1 $sec $_.Exception.Message $sid $sname))
    }

    # ── 7.3 — UDP not open from internet ─────────────────────────────────────
    try {
        if ($nsgs.Count -eq 0) {
            $results.Add((New-InfoResult "7.3" "Ensure That UDP Access From the Internet Is Evaluated and Restricted" 1 $sec "No NSGs found." $sid $sname))
        } else {
            foreach ($nsg in $nsgs) {
                $rules    = @($nsg.rules)
                $badRules = @(Get-NsgUdpBadRules -Rules $rules)
                $pass     = $badRules.Count -eq 0
                $results.Add((New-CISResult `
                    -ControlId "7.3" `
                    -Title "Ensure That UDP Access From the Internet Is Evaluated and Restricted" `
                    -Level 1 -Section $sec `
                    -Status $(if ($pass) { $script:PASS } else { $script:FAIL }) `
                    -Details $(if ($pass) { "No rules allow UDP from internet." } else { "Rule(s) allow UDP from internet: $($badRules -join ', ')" }) `
                    -Remediation $(if (-not $pass) { "NSG > $([string]$nsg.name) > Inbound security rules > Remove/restrict UDP rules from internet" } else { "" }) `
                    -SubscriptionId $sid -SubscriptionName $sname -Resource ([string]$nsg.name)))
            }
        }
    } catch {
        $results.Add((New-ErrorResult "7.3" "Ensure That UDP Access From the Internet Is Evaluated and Restricted" 1 $sec $_.Exception.Message $sid $sname))
    }

    # ── 7.4 — HTTP/HTTPS exposure evaluation ─────────────────────────────────
    try {
        if ($nsgs.Count -eq 0) {
            $results.Add((New-InfoResult "7.4" "Ensure That HTTP(S) Access From the Internet Is Evaluated and Restricted" 1 $sec "No NSGs found." $sid $sname))
        } else {
            foreach ($nsg in $nsgs) {
                $rules      = @($nsg.rules)
                $httpRules  = @(Get-NsgBadRules -Rules $rules -Ports @(80)  -Protocols @("TCP","Tcp","*"))
                $httpsRules = @(Get-NsgBadRules -Rules $rules -Ports @(443) -Protocols @("TCP","Tcp","*"))
                # Filter nulls before combining to avoid spurious Count inflation
                $exposed    = @(@($httpRules | Where-Object { $_ }) + @($httpsRules | Where-Object { $_ }) | Select-Object -Unique)

                # HTTP/HTTPS open from internet is a FAIL per CIS benchmark
                $status = if ($exposed.Count -gt 0) { $script:FAIL } else { $script:PASS }
                $results.Add((New-CISResult `
                    -ControlId "7.4" `
                    -Title "Ensure That HTTP(S) Access From the Internet Is Evaluated and Restricted" `
                    -Level 1 -Section $sec `
                    -Status $status `
                    -Details $(if ($exposed.Count -gt 0) { "HTTP/HTTPS inbound allowed from internet. Rules: $($exposed -join ', ')" } else { "No rules allow HTTP/HTTPS from internet." }) `
                    -Remediation $(if ($exposed.Count -gt 0) { "NSG > $([string]$nsg.name) > Inbound security rules > Restrict HTTP/HTTPS to known IPs or use an Application Gateway/WAF instead." } else { "" }) `
                    -SubscriptionId $sid -SubscriptionName $sname -Resource ([string]$nsg.name)))
            }
        }
    } catch {
        $results.Add((New-ErrorResult "7.4" "Ensure That HTTP(S) Access From the Internet Is Evaluated and Restricted" 1 $sec $_.Exception.Message $sid $sname))
    }

    # Network Watcher flow-log queries only work against real Azure regions.
    # Resources such as Traffic Manager or Azure DNS report location 'global',
    # and some are tagged 'europe', 'asia', etc.  Strip those pseudo-locations
    # so we don't fire spurious 'network watcher not enabled' errors.
    $pseudoLocations = @('global','europe','asia','northamerica','southamerica','australia','us','uk','france','germany','japan','korea','norway','southafrica','switzerland','uae','brazil','india','canada','china')

    # Pre-compute region lists used by 7.5, 7.6, and 7.8
    $regionList  = @(@($locations | ForEach-Object { [string]$_.location }) | Select-Object -Unique | Where-Object { $pseudoLocations -notcontains $_ })
    $watcherLocs = @(@($watchers | Where-Object { [string]$_.state -eq "Succeeded" } | ForEach-Object { [string]$_.location }) | Select-Object -Unique)

    # Collect all flow logs ONCE — only from watchers that are actually running.
    $allFlowLogs = [System.Collections.Generic.List[object]]::new()
    foreach ($watcher in @($watchers | Where-Object { [string]$_.state -eq "Succeeded" })) {
        $watcherId   = [string]$watcher.id
        $parts       = $watcherId -split '/'
        $watcherRg   = $parts[4]
        $watcherName = $parts[-1]
        $fls = @(Get-AzNetworkWatcherFlowLog -NetworkWatcherName $watcherName -ResourceGroupName $watcherRg -ErrorAction SilentlyContinue)
        foreach ($fl in $fls) { $allFlowLogs.Add($fl) }
    }

    # ── 7.5 — NSG Flow Log retention >= 90 days ────────────────────────
    try {
        if ($allFlowLogs.Count -eq 0) {
            $results.Add((New-CISResult `
                -ControlId "7.5" `
                -Title "Ensure That Network Watcher NSG Flow Log Retention Period Is 'Greater than 90 Days'" `
                -Level 2 -Section $sec -Status $script:FAIL `
                -Details "No NSG flow logs found." `
                -Remediation "Network Watcher > NSG flow logs > Enable with retention >= 90 days" `
                -SubscriptionId $sid -SubscriptionName $sname))
        } else {
            foreach ($fl in $allFlowLogs) {
                $days = [int]$fl.RetentionPolicy.Days
                $en   = $fl.RetentionPolicy.Enabled
                $pass = $en -and $days -ge 90
                $results.Add((New-CISResult `
                    -ControlId "7.5" `
                    -Title "Ensure That Network Watcher NSG Flow Log Retention Period Is 'Greater than 90 Days'" `
                    -Level 2 -Section $sec `
                    -Status $(if ($pass) { $script:PASS } else { $script:FAIL }) `
                    -Details "Retention: $days days (enabled: $en). Flow log: $([string]$fl.Name)" `
                    -Remediation $(if (-not $pass) { "Network Watcher > NSG flow logs > $([string]$fl.Name) > Retention >= 90 days" } else { "" }) `
                    -SubscriptionId $sid -SubscriptionName $sname -Resource ([string]$fl.Name)))
            }
        }
    } catch {
        $results.Add((New-ErrorResult "7.5" "NSG Flow Log Retention" 2 $sec $_.Exception.Message $sid $sname))
    }

    # ── 7.6 — Network Watcher enabled for all regions ────────────────────────
    try {
        $missingRegions = @($regionList | Where-Object { $watcherLocs -notcontains $_ })

        if ($regionList.Count -eq 0) {
            $results.Add((New-InfoResult "7.6" "Ensure That Network Watcher Is 'Enabled'" 1 $sec "No regions with resources found." $sid $sname))
        } elseif ($missingRegions.Count -eq 0) {
            $results.Add((New-CISResult `
                -ControlId "7.6" -Title "Ensure That Network Watcher Is 'Enabled'" -Level 1 -Section $sec `
                -Status $script:PASS -Details "Network Watcher enabled in all $($regionList.Count) region(s)." `
                -SubscriptionId $sid -SubscriptionName $sname))
        } else {
            $results.Add((New-CISResult `
                -ControlId "7.6" -Title "Ensure That Network Watcher Is 'Enabled'" -Level 1 -Section $sec `
                -Status $script:FAIL `
                -Details "Network Watcher missing in: $($missingRegions -join ', ')" `
                -Remediation "Network Watcher > Enable in all regions where resources are deployed." `
                -SubscriptionId $sid -SubscriptionName $sname))
        }
    } catch {
        $results.Add((New-ErrorResult "7.6" "Ensure That Network Watcher Is 'Enabled'" 1 $sec $_.Exception.Message $sid $sname))
    }

    # ── 7.8 — VNet flow log retention >= 90 days ─────────────────────────────
    try {
        $allVnetFlowLogs = @($allFlowLogs | Where-Object {
            [string]$_.TargetResourceId -match '(?i)/virtualnetworks/'
        })

        if ($allVnetFlowLogs.Count -eq 0) {
            $results.Add((New-CISResult `
                -ControlId "7.8" `
                -Title "Ensure That VNet Flow Log Retention Period Is 'Greater than 90 Days'" `
                -Level 2 -Section $sec -Status $script:FAIL `
                -Details "No VNet flow logs configured — flow logging has not been enabled for any VNet in this subscription. See also CIS 6.1.1.7 (VNet flow logs to Log Analytics)." `
                -Remediation "Network Watcher > Flow logs > Create a flow log for each VNet with retention >= 90 days and Traffic Analytics enabled (CIS 6.1.1.7)." `
                -SubscriptionId $sid -SubscriptionName $sname))
        } else {
            foreach ($fl in $allVnetFlowLogs) {
                $days = [int]$fl.RetentionPolicy.Days
                $en   = $fl.RetentionPolicy.Enabled
                $pass = $en -and $days -ge 90
                $results.Add((New-CISResult `
                    -ControlId "7.8" `
                    -Title "Ensure That VNet Flow Log Retention Period Is 'Greater than 90 Days'" `
                    -Level 2 -Section $sec `
                    -Status $(if ($pass) { $script:PASS } else { $script:FAIL }) `
                    -Details "VNet flow log '$([string]$fl.Name)': $days days, enabled = $en" `
                    -Remediation $(if (-not $pass) { "Network Watcher > Flow logs > Set retention >= 90 days" } else { "" }) `
                    -SubscriptionId $sid -SubscriptionName $sname -Resource ([string]$fl.Name)))
            }
        }
    } catch {
        $results.Add((New-ErrorResult "7.8" "VNet Flow Log Retention" 2 $sec $_.Exception.Message $sid $sname))
    }

    # ── 7.11 — Subnets associated with NSGs ──────────────────────────────────
    try {
        $subnets = @(Get-PrefetchData -PrefetchData $PrefetchData -Key "subnets" -SubscriptionId $sid)
        $applicableSubnets = @($subnets | Where-Object {
            [string]$_.vnetName -and [string]$_.subnetName -and
            ($script:EXEMPT_SUBNETS -notcontains [string]$_.subnetName.ToLower())
        })

        if ($subnets.Count -eq 0) {
            $results.Add((New-InfoResult "7.11" "Ensure That Virtual Network Security Groups Are Associated to Subnets" 1 $sec "No subnets found." $sid $sname))
        } elseif ($applicableSubnets.Count -eq 0) {
            $results.Add((New-InfoResult "7.11" "Ensure That Virtual Network Security Groups Are Associated to Subnets" 1 $sec "No applicable subnets found (only platform-managed subnets exist)." $sid $sname))
        } else {
            foreach ($subnet in $applicableSubnets) {
                $vnetName   = [string]$subnet.vnetName
                $subnetName = [string]$subnet.subnetName
                $hasNsg     = [string]$subnet.hasNsg -in @("True", "true", "1")
                $resource   = "$vnetName/$subnetName"
                $results.Add((New-CISResult `
                    -ControlId "7.11" `
                    -Title "Ensure That Virtual Network Security Groups Are Associated to Subnets" `
                    -Level 1 -Section $sec `
                    -Status $(if ($hasNsg) { $script:PASS } else { $script:FAIL }) `
                    -Details $(if ($hasNsg) { "Subnet '$resource': NSG associated." } else { "Subnet '$resource': no NSG associated." }) `
                    -Remediation $(if (-not $hasNsg) { "VNet '$vnetName' > Subnets > '$subnetName' > Network security group: assign an NSG." } else { "" }) `
                    -SubscriptionId $sid -SubscriptionName $sname -Resource $resource))
            }
        }
    } catch {
        $results.Add((New-ErrorResult "7.11" "Ensure That Virtual Network Security Groups Are Associated to Subnets" 1 $sec $_.Exception.Message $sid $sname))
    }

    # ── Application Gateway (WAF) checks 7.10, 7.12–7.15 ────────────────────
    # Wrapped in try/catch: deserialized $appGateways objects (from $using: in
    # parallel runspaces) may have null-valued properties stripped by CLIXML
    # serialization; accessing them under Set-StrictMode throws without this.
    try {
    if ($appGateways.Count -eq 0) {
        foreach ($cid in @("7.10","7.12","7.13","7.14","7.15")) {
            $titleMap = @{
                "7.10" = "Ensure That Azure Web Application Firewall Is Enabled for Azure Application Gateway"
                "7.12" = "Ensure Application Gateway Is Configured with a Minimum TLS Version of 1.2"
                "7.13" = "Ensure Application Gateway Is Configured with HTTP2 Enabled"
                "7.14" = "Ensure That Web Application Firewall Request Body Inspection Is Enabled"
                "7.15" = "Ensure That Web Application Firewall Bot Protection Is Enabled"
            }
            $results.Add((New-InfoResult $cid $titleMap[$cid] 2 $sec "No Application Gateways found." $sid $sname))
        }
    } else {
        foreach ($agw in $appGateways) {
            # Use safe property access: null properties may be absent on deserialized objects
            $agwName  = [string]($agw.PSObject.Properties['name']?.Value)
            $http2    = [string]($agw.PSObject.Properties['enableHttp2']?.Value)
            $wafOn    = [string]($agw.PSObject.Properties['wafEnabled']?.Value)
            $wafBody  = [string]($agw.PSObject.Properties['wafReqBody']?.Value)
            $sslProto = [string]($agw.PSObject.Properties['sslMinProto']?.Value)
            $wafPolId = [string]($agw.PSObject.Properties['wafPolicyId']?.Value)

            # 7.10 — WAF enabled
            $wafEnabled = $wafOn -eq "true" -or $wafOn -eq "True" -or $wafPolId -ne ""
            $results.Add((New-CISResult `
                -ControlId "7.10" `
                -Title "Ensure That Azure Web Application Firewall Is Enabled for Azure Application Gateway" `
                -Level 2 -Section $sec `
                -Status $(if ($wafEnabled) { $script:PASS } else { $script:FAIL }) `
                -Details $(if ($wafEnabled) { "WAF is enabled." } else { "WAF is not enabled on this Application Gateway." }) `
                -Remediation $(if (-not $wafEnabled) { "Application Gateway > $agwName > Web application firewall > Enable WAF" } else { "" }) `
                -SubscriptionId $sid -SubscriptionName $sname -Resource $agwName))

            # 7.12 — TLS 1.2+ (empty/unset ssl policy is non-compliant — must be explicitly configured)
            $tlsOk = $sslProto -match "TLSv1_2|TLSv1_3"
            $results.Add((New-CISResult `
                -ControlId "7.12" `
                -Title "Ensure Application Gateway Is Configured with a Minimum TLS Version of 1.2" `
                -Level 1 -Section $sec `
                -Status $(if ($tlsOk) { $script:PASS } else { $script:FAIL }) `
                -Details "Minimum TLS: $(if($sslProto){"$sslProto"}else{'not set'})" `
                -Remediation $(if (-not $tlsOk) { "Application Gateway > $agwName > Listeners > SSL policy > Set minimum TLS to TLSv1_2" } else { "" }) `
                -SubscriptionId $sid -SubscriptionName $sname -Resource $agwName))

            # 7.13 — HTTP2 (was 7.12)
            $h2Ok = $http2 -eq "true" -or $http2 -eq "True"
            $results.Add((New-CISResult `
                -ControlId "7.13" `
                -Title "Ensure Application Gateway Is Configured with HTTP2 Enabled" `
                -Level 2 -Section $sec `
                -Status $(if ($h2Ok) { $script:PASS } else { $script:FAIL }) `
                -Details "HTTP2 enabled: $http2" `
                -Remediation $(if (-not $h2Ok) { "Application Gateway > $agwName > Configuration > Enable HTTP2" } else { "" }) `
                -SubscriptionId $sid -SubscriptionName $sname -Resource $agwName))

            # 7.14 — WAF request body inspection (was 7.13)
            if ($wafPolId) {
                $matchedPol = $wafPolicies | Where-Object { [string]$_.id -eq $wafPolId }
                if ($matchedPol) {
                    $bodyInspect = [string]($matchedPol.PSObject.Properties['requestBodyInspect']?.Value)
                    $bodyOk = $bodyInspect -eq "true" -or $bodyInspect -eq "True"
                    $results.Add((New-CISResult `
                        -ControlId "7.14" `
                        -Title "Ensure That Web Application Firewall Request Body Inspection Is Enabled" `
                        -Level 2 -Section $sec `
                        -Status $(if ($bodyOk) { $script:PASS } else { $script:FAIL }) `
                        -Details "Request body inspection: $bodyInspect" `
                        -Remediation $(if (-not $bodyOk) { "WAF Policy > Policy Settings > Enable request body inspection" } else { "" }) `
                        -SubscriptionId $sid -SubscriptionName $sname -Resource $agwName))

                    # 7.15 — Bot protection mode in Prevention (was 7.14)
                    $botMode = [string]($matchedPol.PSObject.Properties['botMode']?.Value)
                    $botOk   = $botMode -eq "Prevention"
                    $results.Add((New-CISResult `
                        -ControlId "7.15" `
                        -Title "Ensure That Web Application Firewall Bot Protection Is Enabled" `
                        -Level 2 -Section $sec `
                        -Status $(if ($botOk) { $script:PASS } else { $script:FAIL }) `
                        -Details "Bot protection mode: $(if($botMode){"$botMode"}else{'Not configured'})" `
                        -Remediation $(if (-not $botOk) { "WAF Policy > Bot protection > Set to Prevention" } else { "" }) `
                        -SubscriptionId $sid -SubscriptionName $sname -Resource $agwName))
                } else {
                    $results.Add((New-InfoResult "7.14" "WAF Request Body Inspection" 2 $sec "WAF policy $wafPolId not found in prefetch data." $sid $sname $agwName))
                    $results.Add((New-InfoResult "7.15" "WAF Bot Protection" 2 $sec "WAF policy $wafPolId not found in prefetch data." $sid $sname $agwName))
                }
            } else {
                $wafBodyOk = $wafBody -eq "true" -or $wafBody -eq "True"
                $results.Add((New-CISResult `
                    -ControlId "7.14" -Title "Ensure That Web Application Firewall Request Body Inspection Is Enabled" `
                    -Level 2 -Section $sec `
                    -Status $(if ($wafBodyOk) { $script:PASS } else { $script:FAIL }) `
                    -Details $(if ($wafBody) { "Request body inspection (inline): $wafBody" } else { "WAF is not enabled on this Application Gateway; request body inspection is not configured." }) `
                    -Remediation $(if (-not $wafBodyOk) { "Application Gateway > $agwName > WAF > Request body inspection > Enable" } else { "" }) `
                    -SubscriptionId $sid -SubscriptionName $sname -Resource $agwName))

                # 7.15 without WAF policy — cannot determine bot protection
                $results.Add((New-InfoResult "7.15" "Ensure That Web Application Firewall Bot Protection Is Enabled" 2 $sec "No WAF policy linked; cannot assess bot protection mode." $sid $sname $agwName))
            }
        }
    }
    } catch {
        $results.Add((New-ErrorResult "7.10" "Application Gateway WAF checks (7.10–7.15)" 2 $sec $_.Exception.Message $sid $sname))
    }

    return $results.ToArray()
}
