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
            $results.Add((New-InfoResult "7.1" "Ensure that RDP Access from the Internet is Evaluated and Restricted" 1 $sec "No NSGs found." $sid $sname))
        } else {
            foreach ($nsg in $nsgs) {
                $rules    = @($nsg.rules)
                $badRules = @(Get-NsgBadRules -Rules $rules -Ports @(3389) -Protocols @("TCP","Tcp","*"))
                $pass     = $badRules.Count -eq 0
                $results.Add((New-CISResult `
                    -ControlId "7.1" `
                    -Title "Ensure that RDP Access from the Internet is Evaluated and Restricted" `
                    -Level 1 -Section $sec `
                    -Status $(if ($pass) { $script:PASS } else { $script:FAIL }) `
                    -Details $(if ($pass) { "No rules allow RDP from internet." } else { "Rule(s) allow RDP (3389) from internet: $($badRules -join ', ')" }) `
                    -Remediation $(if (-not $pass) { "NSG > $([string]$nsg.name) > Inbound security rules > Remove/restrict rules exposing port 3389" } else { "" }) `
                    -SubscriptionId $sid -SubscriptionName $sname -Resource ([string]$nsg.name)))
            }
        }
    } catch {
        $results.Add((New-ErrorResult "7.1" "Ensure that RDP Access from the Internet is Evaluated and Restricted" 1 $sec $_.Exception.Message $sid $sname))
    }

    # ── 7.2 — SSH (22) not open from internet ────────────────────────────────
    try {
        if ($nsgs.Count -eq 0) {
            $results.Add((New-InfoResult "7.2" "Ensure that SSH Access from the Internet is Evaluated and Restricted" 1 $sec "No NSGs found." $sid $sname))
        } else {
            foreach ($nsg in $nsgs) {
                $rules    = @($nsg.rules)
                $badRules = @(Get-NsgBadRules -Rules $rules -Ports @(22) -Protocols @("TCP","Tcp","*"))
                $pass     = $badRules.Count -eq 0
                $results.Add((New-CISResult `
                    -ControlId "7.2" `
                    -Title "Ensure that SSH Access from the Internet is Evaluated and Restricted" `
                    -Level 1 -Section $sec `
                    -Status $(if ($pass) { $script:PASS } else { $script:FAIL }) `
                    -Details $(if ($pass) { "No rules allow SSH from internet." } else { "Rule(s) allow SSH (22) from internet: $($badRules -join ', ')" }) `
                    -Remediation $(if (-not $pass) { "NSG > $([string]$nsg.name) > Inbound security rules > Remove/restrict rules exposing port 22" } else { "" }) `
                    -SubscriptionId $sid -SubscriptionName $sname -Resource ([string]$nsg.name)))
            }
        }
    } catch {
        $results.Add((New-ErrorResult "7.2" "Ensure that SSH Access from the Internet is Evaluated and Restricted" 1 $sec $_.Exception.Message $sid $sname))
    }

    # ── 7.3 — UDP not open from internet ─────────────────────────────────────
    try {
        if ($nsgs.Count -eq 0) {
            $results.Add((New-InfoResult "7.3" "Ensure that UDP Port Access from the Internet is Evaluated and Restricted" 1 $sec "No NSGs found." $sid $sname))
        } else {
            foreach ($nsg in $nsgs) {
                $rules    = @($nsg.rules)
                $badRules = @(Get-NsgUdpBadRules -Rules $rules)
                $pass     = $badRules.Count -eq 0
                $results.Add((New-CISResult `
                    -ControlId "7.3" `
                    -Title "Ensure that UDP Port Access from the Internet is Evaluated and Restricted" `
                    -Level 1 -Section $sec `
                    -Status $(if ($pass) { $script:PASS } else { $script:FAIL }) `
                    -Details $(if ($pass) { "No rules allow UDP from internet." } else { "Rule(s) allow UDP from internet: $($badRules -join ', ')" }) `
                    -Remediation $(if (-not $pass) { "NSG > $([string]$nsg.name) > Inbound security rules > Remove/restrict UDP rules from internet" } else { "" }) `
                    -SubscriptionId $sid -SubscriptionName $sname -Resource ([string]$nsg.name)))
            }
        }
    } catch {
        $results.Add((New-ErrorResult "7.3" "Ensure that UDP Port Access from the Internet is Evaluated and Restricted" 1 $sec $_.Exception.Message $sid $sname))
    }

    # ── 7.4 — HTTP/HTTPS exposure evaluation ─────────────────────────────────
    try {
        if ($nsgs.Count -eq 0) {
            $results.Add((New-InfoResult "7.4" "Ensure that HTTP(S) Access from the Internet is Evaluated and Restricted" 1 $sec "No NSGs found." $sid $sname))
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
                    -Title "Ensure that HTTP(S) Access from the Internet is Evaluated and Restricted" `
                    -Level 1 -Section $sec `
                    -Status $status `
                    -Details $(if ($exposed.Count -gt 0) { "HTTP/HTTPS inbound allowed from internet. Rules: $($exposed -join ', ')" } else { "No rules allow HTTP/HTTPS from internet." }) `
                    -Remediation $(if ($exposed.Count -gt 0) { "NSG > $([string]$nsg.name) > Inbound security rules > Restrict HTTP/HTTPS to known IPs or use an Application Gateway/WAF instead." } else { "" }) `
                    -SubscriptionId $sid -SubscriptionName $sname -Resource ([string]$nsg.name)))
            }
        }
    } catch {
        $results.Add((New-ErrorResult "7.4" "Ensure that HTTP(S) Access from the Internet is Evaluated and Restricted" 1 $sec $_.Exception.Message $sid $sname))
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
                -Title "Ensure that Network Security Group Flow Log Retention Days is Set to Greater than or equal to 90" `
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
                    -Title "Ensure that Network Security Group Flow Log Retention Days is Set to Greater than or equal to 90" `
                    -Level 2 -Section $sec `
                    -Status $(if ($pass) { $script:PASS } else { $script:FAIL }) `
                    -Details "Retention: $days days (enabled: $en). Flow log: $([string]$fl.Name)" `
                    -Remediation $(if (-not $pass) { "Network Watcher > NSG flow logs > $([string]$fl.Name) > Retention >= 90 days" } else { "" }) `
                    -SubscriptionId $sid -SubscriptionName $sname -Resource ([string]$fl.Name)))
            }
        }
    } catch {
        $results.Add((New-ErrorResult "7.5" "Ensure that Network Security Group Flow Log Retention Days is Set to Greater than or equal to 90" 2 $sec $_.Exception.Message $sid $sname))
    }

    # ── 7.6 — Network Watcher enabled for all regions ────────────────────────
    try {
        $missingRegions = @($regionList | Where-Object { $watcherLocs -notcontains $_ })

        if ($regionList.Count -eq 0) {
            $results.Add((New-InfoResult "7.6" "Ensure that Network Watcher is 'Enabled' for Azure Regions That are in Use" 2 $sec "No regions with resources found." $sid $sname))
        } elseif ($missingRegions.Count -eq 0) {
            $results.Add((New-CISResult `
                -ControlId "7.6" -Title "Ensure that Network Watcher is 'Enabled' for Azure Regions That are in Use" -Level 2 -Section $sec `
                -Status $script:PASS -Details "Network Watcher enabled in all $($regionList.Count) region(s)." `
                -SubscriptionId $sid -SubscriptionName $sname))
        } else {
            $results.Add((New-CISResult `
                -ControlId "7.6" -Title "Ensure that Network Watcher is 'Enabled' for Azure Regions That are in Use" -Level 2 -Section $sec `
                -Status $script:FAIL `
                -Details "Network Watcher missing in: $($missingRegions -join ', ')" `
                -Remediation "Network Watcher > Enable in all regions where resources are deployed." `
                -SubscriptionId $sid -SubscriptionName $sname))
        }
    } catch {
        $results.Add((New-ErrorResult "7.6" "Ensure that Network Watcher is 'Enabled' for Azure Regions That are in Use" 2 $sec $_.Exception.Message $sid $sname))
    }

    # ── 7.8 — VNet flow log retention >= 90 days ─────────────────────────────
    try {
        $allVnetFlowLogs = @($allFlowLogs | Where-Object {
            [string]$_.TargetResourceId -match '(?i)/virtualnetworks/'
        })

        if ($allVnetFlowLogs.Count -eq 0) {
            $results.Add((New-CISResult `
                -ControlId "7.8" `
                -Title "Ensure that Virtual Network Flow Log Retention Days is Set to Greater than or Equal to 90" `
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
                    -Title "Ensure that Virtual Network Flow Log Retention Days is Set to Greater than or Equal to 90" `
                    -Level 2 -Section $sec `
                    -Status $(if ($pass) { $script:PASS } else { $script:FAIL }) `
                    -Details "VNet flow log '$([string]$fl.Name)': $days days, enabled = $en" `
                    -Remediation $(if (-not $pass) { "Network Watcher > Flow logs > Set retention >= 90 days" } else { "" }) `
                    -SubscriptionId $sid -SubscriptionName $sname -Resource ([string]$fl.Name)))
            }
        }
    } catch {
        $results.Add((New-ErrorResult "7.8" "Ensure that Virtual Network Flow Log Retention Days is Set to Greater than or Equal to 90" 2 $sec $_.Exception.Message $sid $sname))
    }

    # ── 7.11 — Subnets associated with NSGs ──────────────────────────────────
    try {
        $subnets = @(Get-PrefetchData -PrefetchData $PrefetchData -Key "subnets" -SubscriptionId $sid)
        $applicableSubnets = @($subnets | Where-Object {
            [string]$_.vnetName -and [string]$_.subnetName -and
            ($script:EXEMPT_SUBNETS -notcontains [string]$_.subnetName.ToLower())
        })

        if ($subnets.Count -eq 0) {
            $results.Add((New-InfoResult "7.11" "Ensure Subnets Are Associated with Network Security Groups" 1 $sec "No subnets found." $sid $sname))
        } elseif ($applicableSubnets.Count -eq 0) {
            $results.Add((New-InfoResult "7.11" "Ensure Subnets Are Associated with Network Security Groups" 1 $sec "No applicable subnets found (only platform-managed subnets exist)." $sid $sname))
        } else {
            foreach ($subnet in $applicableSubnets) {
                $vnetName   = [string]$subnet.vnetName
                $subnetName = [string]$subnet.subnetName
                $hasNsg     = [string]$subnet.hasNsg -in @("True", "true", "1")
                $resource   = "$vnetName/$subnetName"
                $results.Add((New-CISResult `
                    -ControlId "7.11" `
                    -Title "Ensure Subnets Are Associated with Network Security Groups" `
                    -Level 1 -Section $sec `
                    -Status $(if ($hasNsg) { $script:PASS } else { $script:FAIL }) `
                    -Details $(if ($hasNsg) { "Subnet '$resource': NSG associated." } else { "Subnet '$resource': no NSG associated." }) `
                    -Remediation $(if (-not $hasNsg) { "VNet '$vnetName' > Subnets > '$subnetName' > Network security group: assign an NSG." } else { "" }) `
                    -SubscriptionId $sid -SubscriptionName $sname -Resource $resource))
            }
        }
    } catch {
        $results.Add((New-ErrorResult "7.11" "Ensure Subnets Are Associated with Network Security Groups" 1 $sec $_.Exception.Message $sid $sname))
    }

    # ── Application Gateway (WAF) checks 7.10, 7.12–7.15 ────────────────────
    # Wrapped in try/catch: deserialized $appGateways objects (from $using: in
    # parallel runspaces) may have null-valued properties stripped by CLIXML
    # serialization; accessing them under Set-StrictMode throws without this.
    try {
    if ($appGateways.Count -eq 0) {
        foreach ($cid in @("7.10","7.12","7.13","7.14","7.15")) {
            $titleMap = @{
                "7.10" = "Ensure Azure Web Application Firewall (WAF) is Enabled on Azure Application Gateway"
                "7.12" = "Ensure the SSL Policy's 'Min protocol version' is Set to 'TLSv1_2' or Higher on Azure Application Gateway"
                "7.13" = "Ensure 'HTTP2' is Set to 'Enabled' on Azure Application Gateway"
                "7.14" = "Ensure Request Body Inspection is Enabled in Azure Web Application Firewall policy on Azure Application Gateway"
                "7.15" = "Ensure Bot Protection is Enabled in Azure Web Application Firewall Policy on Azure Application Gateway"
            }
            $levelMap = @{ "7.10" = 2; "7.12" = 1; "7.13" = 1; "7.14" = 2; "7.15" = 2 }
            $results.Add((New-InfoResult $cid $titleMap[$cid] $levelMap[$cid] $sec "No Application Gateways found." $sid $sname))
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
                -Title "Ensure Azure Web Application Firewall (WAF) is Enabled on Azure Application Gateway" `
                -Level 2 -Section $sec `
                -Status $(if ($wafEnabled) { $script:PASS } else { $script:FAIL }) `
                -Details $(if ($wafEnabled) { "WAF is enabled." } else { "WAF is not enabled on this Application Gateway." }) `
                -Remediation $(if (-not $wafEnabled) { "Application Gateway > $agwName > Web application firewall > Enable WAF" } else { "" }) `
                -SubscriptionId $sid -SubscriptionName $sname -Resource $agwName))

            # 7.12 — TLS 1.2+ (empty/unset ssl policy is non-compliant — must be explicitly configured)
            $tlsOk = $sslProto -match "TLSv1_2|TLSv1_3"
            $results.Add((New-CISResult `
                -ControlId "7.12" `
                -Title "Ensure the SSL Policy's 'Min protocol version' is Set to 'TLSv1_2' or Higher on Azure Application Gateway" `
                -Level 1 -Section $sec `
                -Status $(if ($tlsOk) { $script:PASS } else { $script:FAIL }) `
                -Details "Minimum TLS: $(if($sslProto){"$sslProto"}else{'not set'})" `
                -Remediation $(if (-not $tlsOk) { "Application Gateway > $agwName > Listeners > SSL policy > Set minimum TLS to TLSv1_2" } else { "" }) `
                -SubscriptionId $sid -SubscriptionName $sname -Resource $agwName))

            # 7.13 — HTTP2 (was 7.12)
            $h2Ok = $http2 -eq "true" -or $http2 -eq "True"
            $results.Add((New-CISResult `
                -ControlId "7.13" `
                -Title "Ensure 'HTTP2' is Set to 'Enabled' on Azure Application Gateway" `
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
                        -Title "Ensure Request Body Inspection is Enabled in Azure Web Application Firewall policy on Azure Application Gateway" `
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
                        -Title "Ensure Bot Protection is Enabled in Azure Web Application Firewall Policy on Azure Application Gateway" `
                        -Level 2 -Section $sec `
                        -Status $(if ($botOk) { $script:PASS } else { $script:FAIL }) `
                        -Details "Bot protection mode: $(if($botMode){"$botMode"}else{'Not configured'})" `
                        -Remediation $(if (-not $botOk) { "WAF Policy > Bot protection > Set to Prevention" } else { "" }) `
                        -SubscriptionId $sid -SubscriptionName $sname -Resource $agwName))
                } else {
                    $results.Add((New-InfoResult "7.14" "Ensure Request Body Inspection is Enabled in Azure Web Application Firewall policy on Azure Application Gateway" 2 $sec "WAF policy $wafPolId not found in prefetch data." $sid $sname $agwName))
                    $results.Add((New-InfoResult "7.15" "Ensure Bot Protection is Enabled in Azure Web Application Firewall Policy on Azure Application Gateway" 2 $sec "WAF policy $wafPolId not found in prefetch data." $sid $sname $agwName))
                }
            } else {
                $wafBodyOk = $wafBody -eq "true" -or $wafBody -eq "True"
                $results.Add((New-CISResult `
                    -ControlId "7.14" -Title "Ensure Request Body Inspection is Enabled in Azure Web Application Firewall policy on Azure Application Gateway" `
                    -Level 2 -Section $sec `
                    -Status $(if ($wafBodyOk) { $script:PASS } else { $script:FAIL }) `
                    -Details $(if ($wafBody) { "Request body inspection (inline): $wafBody" } else { "WAF is not enabled on this Application Gateway; request body inspection is not configured." }) `
                    -Remediation $(if (-not $wafBodyOk) { "Application Gateway > $agwName > WAF > Request body inspection > Enable" } else { "" }) `
                    -SubscriptionId $sid -SubscriptionName $sname -Resource $agwName))

                # 7.15 without WAF policy — cannot determine bot protection
                $results.Add((New-InfoResult "7.15" "Ensure Bot Protection is Enabled in Azure Web Application Firewall Policy on Azure Application Gateway" 2 $sec "No WAF policy linked; cannot assess bot protection mode." $sid $sname $agwName))
            }
        }
    }
    } catch {
        $agwErrMsg = $_.Exception.Message
        $agwTitleMap = @{
            "7.10" = @{ Title = "Ensure Azure Web Application Firewall (WAF) is Enabled on Azure Application Gateway"; Level = 2 }
            "7.12" = @{ Title = "Ensure the SSL Policy's 'Min protocol version' is Set to 'TLSv1_2' or Higher on Azure Application Gateway"; Level = 1 }
            "7.13" = @{ Title = "Ensure 'HTTP2' is Set to 'Enabled' on Azure Application Gateway"; Level = 1 }
            "7.14" = @{ Title = "Ensure Request Body Inspection is Enabled in Azure Web Application Firewall policy on Azure Application Gateway"; Level = 2 }
            "7.15" = @{ Title = "Ensure Bot Protection is Enabled in Azure Web Application Firewall Policy on Azure Application Gateway"; Level = 2 }
        }
        foreach ($cid in @("7.10","7.12","7.13","7.14","7.15")) {
            $results.Add((New-ErrorResult $cid $agwTitleMap[$cid].Title $agwTitleMap[$cid].Level $sec $agwErrMsg $sid $sname))
        }
    }

    return $results.ToArray()
}

function Invoke-Section7TenantChecks {
    <#
    .SYNOPSIS
    Section 7 controls v6 defines without a reliable automated read — surfaced once
    as MANUAL so the report mirrors the benchmark's control set. (7.9 is 'Automated'
    in v6 but only documents a portal audit for the VPN Gateway P2S setting, so it is
    surfaced for manual review rather than asserted PASS/FAIL.)
    #>
    $sec = "7 - Networking Services"
    $manual = @(
        @{ Id="7.7";  Lvl=1; Title="Ensure that Public IP Addresses are Evaluated on a Periodic Basis"; Msg="Manual verification required — periodically review all Public IP addresses (Azure Portal > Public IP addresses) and remove or justify each exposed endpoint." }
        @{ Id="7.9";  Lvl=2; Title="Ensure 'Authentication type' is Set to 'Azure Active Directory' only for Azure VPN Gateway Point-to-Site Configuration"; Msg="Manual verification required — for each VPN Gateway with a Point-to-Site configuration, ensure the Authentication type is set to 'Azure Active Directory' only." }
        @{ Id="7.16"; Lvl=2; Title="Ensure Azure Network Security Perimeter is Used to Secure Azure Platform-as-a-service Resources"; Msg="Manual verification required — confirm Azure Network Security Perimeter is configured to secure supported PaaS resources." }
    )

    $results = [System.Collections.Generic.List[object]]::new()
    foreach ($m in $manual) {
        $results.Add((New-ManualResult $m.Id $m.Title $m.Lvl $sec $m.Msg))
    }
    return $results.ToArray()
}
