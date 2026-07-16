#Requires -Version 7.0
<#
.SYNOPSIS
    Section 7 — Networking Services checks.
    Split from the former Tests\Checks.Tests.ps1 monolith; shared fixtures and the
    hermetic default mocks live in Tests\TestHelpers.ps1.
#>

param()

BeforeAll {
    . (Join-Path $PSScriptRoot "TestHelpers.ps1")
}

# =============================================================================
# SECTION 7 — NETWORKING
# =============================================================================

Describe "Invoke-Section7Checks — no NSGs returns INFO" {
    It "returns INFO for 7.1 and 7.2 when NSG list is empty" {
        $pd = Merge-PD @(
            (New-PD "nsgs"         @())
            (New-PD "app_gateways" @())
            (New-PD "watchers"     @())
            (New-PD "locations"    @())
            (New-PD "waf_policies" @())
            (New-PD "subnets"      @())
            (New-PD "vnets"        @())
        )

        $results = @(Invoke-Section7Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "7.1" }).Status | Should -Be "INFO"
        ($results | Where-Object { $_.ControlId -eq "7.2" }).Status | Should -Be "INFO"
    }
}

Describe "Invoke-Section7Checks — 7.1 RDP" {
    It "returns PASS for NSG with no RDP rule" {
        $nsg = [PSCustomObject]@{
            name = "safe-nsg"
            rules = @(New-Rule -Name "allow-443" -Protocol "TCP" -Src "*" -DestPort "443")
        }
        $pd = Merge-PD @(
            (New-PD "nsgs"         @($nsg))
            (New-PD "app_gateways" @())
            (New-PD "watchers"     @())
            (New-PD "locations"    @())
            (New-PD "waf_policies" @())
            (New-PD "subnets"      @())
            (New-PD "vnets"        @())
        )

        $results = @(Invoke-Section7Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "7.1" }).Status | Should -Be "PASS"
    }

    It "returns FAIL for NSG allowing RDP from internet" {
        $nsg = [PSCustomObject]@{
            name  = "bad-nsg"
            rules = @(New-Rule -Name "allow-rdp" -Protocol "TCP" -Src "*" -DestPort "3389")
        }
        $pd = Merge-PD @(
            (New-PD "nsgs"         @($nsg))
            (New-PD "app_gateways" @())
            (New-PD "watchers"     @())
            (New-PD "locations"    @())
            (New-PD "waf_policies" @())
            (New-PD "subnets"      @())
            (New-PD "vnets"        @())
        )

        $results = @(Invoke-Section7Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "7.1" }).Status | Should -Be "FAIL"
    }
}

Describe "Invoke-Section7Checks — 7.2 SSH" {
    It "returns FAIL for NSG allowing SSH from internet" {
        $nsg = [PSCustomObject]@{
            name  = "ssh-exposed"
            rules = @(New-Rule -Name "allow-ssh" -Protocol "TCP" -Src "0.0.0.0/0" -DestPort "22")
        }
        $pd = Merge-PD @(
            (New-PD "nsgs"         @($nsg))
            (New-PD "app_gateways" @())
            (New-PD "watchers"     @())
            (New-PD "locations"    @())
            (New-PD "waf_policies" @())
            (New-PD "subnets"      @())
            (New-PD "vnets"        @())
        )

        $results = @(Invoke-Section7Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "7.2" }).Status | Should -Be "FAIL"
    }
}

# =============================================================================
# SECTION 7 — NETWORKING (additional coverage)
# =============================================================================

Describe "Invoke-Section7Checks — 7.3 UDP" {
    It "returns FAIL when UDP allowed from internet" {
        $nsg = [PSCustomObject]@{
            name = "udp-nsg"
            rules = @([PSCustomObject]@{
                name = "bad-udp"; access = "Allow"; direction = "Inbound"
                protocol = "UDP"; sourceAddressPrefix = "*"
                destinationPortRange = "*"; destinationPortRanges = @()
            })
        }
        $pd = Merge-PD @(
            (New-PD "nsgs" @($nsg)), (New-PD "app_gateways" @()), (New-PD "watchers" @()),
            (New-PD "locations" @()), (New-PD "waf_policies" @()), (New-PD "subnets" @()), (New-PD "vnets" @())
        )
        $results = @(Invoke-Section7Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "7.3" }).Status | Should -Be "FAIL"
    }

    It "returns PASS when no UDP from internet" {
        $nsg = [PSCustomObject]@{
            name = "tcp-only-nsg"
            rules = @(New-Rule -Name "allow-443" -Protocol "TCP" -Src "*" -DestPort "443")
        }
        $pd = Merge-PD @(
            (New-PD "nsgs" @($nsg)), (New-PD "app_gateways" @()), (New-PD "watchers" @()),
            (New-PD "locations" @()), (New-PD "waf_policies" @()), (New-PD "subnets" @()), (New-PD "vnets" @())
        )
        $results = @(Invoke-Section7Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "7.3" }).Status | Should -Be "PASS"
    }
}

Describe "Invoke-Section7Checks — 7.4 HTTP/HTTPS" {
    It "returns FAIL when HTTP port 80 exposed" {
        $nsg = [PSCustomObject]@{
            name = "http-nsg"
            rules = @(New-Rule -Name "allow-http" -Protocol "TCP" -Src "*" -DestPort "80")
        }
        $pd = Merge-PD @(
            (New-PD "nsgs" @($nsg)), (New-PD "app_gateways" @()), (New-PD "watchers" @()),
            (New-PD "locations" @()), (New-PD "waf_policies" @()), (New-PD "subnets" @()), (New-PD "vnets" @())
        )
        $results = @(Invoke-Section7Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "7.4" }).Status | Should -Be "FAIL"
    }

    It "returns PASS when no HTTP/HTTPS exposed" {
        $nsg = [PSCustomObject]@{
            name = "safe-nsg"
            rules = @(New-Rule -Name "allow-ssh" -Protocol "TCP" -Src "10.0.0.0/8" -DestPort "22")
        }
        $pd = Merge-PD @(
            (New-PD "nsgs" @($nsg)), (New-PD "app_gateways" @()), (New-PD "watchers" @()),
            (New-PD "locations" @()), (New-PD "waf_policies" @()), (New-PD "subnets" @()), (New-PD "vnets" @())
        )
        $results = @(Invoke-Section7Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "7.4" }).Status | Should -Be "PASS"
    }
}

Describe "Invoke-Section7Checks — 7.5 NSG Flow Log Retention" {
    It "returns PASS when flow log retention >= 90 days" {
        $pd = Merge-PD @(
            (New-PD "nsgs" @()), (New-PD "app_gateways" @()),
            (New-PD "watchers" @([PSCustomObject]@{ location = "eastus"; state = "Succeeded"; id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/NetworkWatcherRG/providers/Microsoft.Network/networkWatchers/NetworkWatcher_eastus" })),
            (New-PD "locations" @([PSCustomObject]@{ location = "eastus" })),
            (New-PD "waf_policies" @()), (New-PD "subnets" @()), (New-PD "vnets" @())
        )
        Mock Get-AzNetworkWatcherFlowLog {
            [PSCustomObject]@{
                Name = "fl1"; TargetResourceId = "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Network/networkSecurityGroups/nsg1"
                RetentionPolicy = [PSCustomObject]@{ Enabled = $true; Days = 90 }
            }
        }
        $results = @(Invoke-Section7Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "7.5" }).Status | Should -Be "PASS"
    }

    It "returns FAIL when no flow logs found" {
        $pd = Merge-PD @(
            (New-PD "nsgs" @()), (New-PD "app_gateways" @()), (New-PD "watchers" @()),
            (New-PD "locations" @([PSCustomObject]@{ location = "eastus" })),
            (New-PD "waf_policies" @()), (New-PD "subnets" @()), (New-PD "vnets" @())
        )
        $results = @(Invoke-Section7Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "7.5" }).Status | Should -Be "FAIL"
    }

    It "returns FAIL when flow log retention is disabled even with 0 days (regression)" {
        # Previously the logic was '-not $en -or $days -ge 90' which would PASS a disabled log.
        # Correct behaviour: disabled retention must FAIL regardless of days.
        $pd = Merge-PD @(
            (New-PD "nsgs" @()), (New-PD "app_gateways" @()),
            (New-PD "watchers" @([PSCustomObject]@{ location = "eastus"; state = "Succeeded"; id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/NetworkWatcherRG/providers/Microsoft.Network/networkWatchers/NetworkWatcher_eastus" })),
            (New-PD "locations" @([PSCustomObject]@{ location = "eastus" })),
            (New-PD "waf_policies" @()), (New-PD "subnets" @()), (New-PD "vnets" @())
        )
        Mock Get-AzNetworkWatcherFlowLog {
            [PSCustomObject]@{
                Name = "fl-disabled"; TargetResourceId = "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Network/networkSecurityGroups/nsg1"
                RetentionPolicy = [PSCustomObject]@{ Enabled = $false; Days = 0 }
            }
        }
        $results = @(Invoke-Section7Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "7.5" }).Status | Should -Be "FAIL"
    }
}

Describe "Invoke-Section7Checks — 7.6 Network Watcher" {
    It "returns PASS when watchers cover all regions" {
        $pd = Merge-PD @(
            (New-PD "nsgs" @()), (New-PD "app_gateways" @()),
            (New-PD "watchers" @([PSCustomObject]@{ location = "eastus"; state = "Succeeded"; id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/NetworkWatcherRG/providers/Microsoft.Network/networkWatchers/NetworkWatcher_eastus" })),
            (New-PD "locations" @([PSCustomObject]@{ location = "eastus" })),
            (New-PD "waf_policies" @()), (New-PD "subnets" @()), (New-PD "vnets" @())
        )
        Mock Get-AzNetworkWatcherFlowLog { @() }
        $results = @(Invoke-Section7Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "7.6" }).Status | Should -Be "PASS"
    }

    It "returns FAIL when watcher missing in a region" {
        $pd = Merge-PD @(
            (New-PD "nsgs" @()), (New-PD "app_gateways" @()),
            (New-PD "watchers" @([PSCustomObject]@{ location = "eastus"; state = "Succeeded"; id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/NetworkWatcherRG/providers/Microsoft.Network/networkWatchers/NetworkWatcher_eastus" })),
            (New-PD "locations" @([PSCustomObject]@{ location = "eastus" }, [PSCustomObject]@{ location = "westus" })),
            (New-PD "waf_policies" @()), (New-PD "subnets" @()), (New-PD "vnets" @())
        )
        Mock Get-AzNetworkWatcherFlowLog { @() }
        $results = @(Invoke-Section7Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "7.6" }).Status | Should -Be "FAIL"
    }
}

Describe "Invoke-Section7Checks — 7.8 VNet Flow Logs" {
    It "returns PASS when VNet flow log with >= 90 day retention" {
        $pd = Merge-PD @(
            (New-PD "nsgs" @()), (New-PD "app_gateways" @()),
            (New-PD "watchers" @([PSCustomObject]@{ location = "eastus"; state = "Succeeded"; id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/NetworkWatcherRG/providers/Microsoft.Network/networkWatchers/NetworkWatcher_eastus" })),
            (New-PD "locations" @([PSCustomObject]@{ location = "eastus" })),
            (New-PD "waf_policies" @()), (New-PD "subnets" @()), (New-PD "vnets" @())
        )
        Mock Get-AzNetworkWatcherFlowLog {
            [PSCustomObject]@{
                Name = "vfl1"; TargetResourceId = "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Network/virtualNetworks/vnet1"
                RetentionPolicy = [PSCustomObject]@{ Enabled = $true; Days = 90 }
            }
        }
        $results = @(Invoke-Section7Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "7.8" }).Status | Should -Be "PASS"
    }

    It "returns FAIL when no VNet flow logs" {
        $pd = Merge-PD @(
            (New-PD "nsgs" @()), (New-PD "app_gateways" @()), (New-PD "watchers" @()),
            (New-PD "locations" @([PSCustomObject]@{ location = "eastus" })),
            (New-PD "waf_policies" @()), (New-PD "subnets" @()), (New-PD "vnets" @())
        )
        $results = @(Invoke-Section7Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "7.8" }).Status | Should -Be "FAIL"
    }
}

Describe "Invoke-Section7Checks — 7.11 Subnet-NSG Association" {
    It "returns PASS when all subnets have NSGs" {
        $subnets = @(
            [PSCustomObject]@{ vnetName = "vnet1"; subnetName = "web"; hasNsg = "true" }
            [PSCustomObject]@{ vnetName = "vnet1"; subnetName = "app"; hasNsg = "true" }
        )
        $pd = Merge-PD @(
            (New-PD "nsgs" @()), (New-PD "app_gateways" @()), (New-PD "watchers" @()),
            (New-PD "locations" @()), (New-PD "waf_policies" @()),
            (New-PD "subnets" $subnets), (New-PD "vnets" @())
        )
        $results = @(Invoke-Section7Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        $s711 = @($results | Where-Object { $_.ControlId -eq "7.11" })
        $s711 | ForEach-Object { $_.Status | Should -Be "PASS" }
    }

    It "returns FAIL when a subnet has no NSG" {
        $subnets = @(
            [PSCustomObject]@{ vnetName = "vnet1"; subnetName = "web"; hasNsg = "true" }
            [PSCustomObject]@{ vnetName = "vnet1"; subnetName = "db";  hasNsg = "false" }
        )
        $pd = Merge-PD @(
            (New-PD "nsgs" @()), (New-PD "app_gateways" @()), (New-PD "watchers" @()),
            (New-PD "locations" @()), (New-PD "waf_policies" @()),
            (New-PD "subnets" $subnets), (New-PD "vnets" @())
        )
        $results = @(Invoke-Section7Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        $s711 = @($results | Where-Object { $_.ControlId -eq "7.11" })
        ($s711 | Where-Object { $_.Status -eq "FAIL" }).Count | Should -BeGreaterThan 0
    }

    It "skips exempt subnets like GatewaySubnet" {
        $subnets = @(
            [PSCustomObject]@{ vnetName = "vnet1"; subnetName = "GatewaySubnet"; hasNsg = "false" }
        )
        $pd = Merge-PD @(
            (New-PD "nsgs" @()), (New-PD "app_gateways" @()), (New-PD "watchers" @()),
            (New-PD "locations" @()), (New-PD "waf_policies" @()),
            (New-PD "subnets" $subnets), (New-PD "vnets" @())
        )
        $results = @(Invoke-Section7Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        $s711 = @($results | Where-Object { $_.ControlId -eq "7.11" })
        $s711 | ForEach-Object { $_.Status | Should -Be "INFO" }
    }
}

Describe "Invoke-Section7Checks — 7.10 WAF Enabled" {
    It "returns PASS when WAF is enabled on AppGW" {
        $agw = [PSCustomObject]@{
            name = "agw1"; enableHttp2 = "true"; wafEnabled = "true"
            wafMode = "Prevention"; wafReqBody = "true"; sslMinProto = "TLSv1_2"; wafPolicyId = ""
        }
        $pd = Merge-PD @(
            (New-PD "nsgs" @()), (New-PD "app_gateways" @($agw)), (New-PD "watchers" @()),
            (New-PD "locations" @()), (New-PD "waf_policies" @()), (New-PD "subnets" @()), (New-PD "vnets" @())
        )
        $results = @(Invoke-Section7Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "7.10" }).Status | Should -Be "PASS"
    }

    It "returns FAIL when WAF is off and no policy" {
        $agw = [PSCustomObject]@{
            name = "agw2"; enableHttp2 = "false"; wafEnabled = "false"
            wafMode = ""; wafReqBody = "false"; sslMinProto = "TLSv1_0"; wafPolicyId = ""
        }
        $pd = Merge-PD @(
            (New-PD "nsgs" @()), (New-PD "app_gateways" @($agw)), (New-PD "watchers" @()),
            (New-PD "locations" @()), (New-PD "waf_policies" @()), (New-PD "subnets" @()), (New-PD "vnets" @())
        )
        $results = @(Invoke-Section7Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "7.10" }).Status | Should -Be "FAIL"
    }

    It "returns INFO when no App Gateways" {
        $pd = Merge-PD @(
            (New-PD "nsgs" @()), (New-PD "app_gateways" @()), (New-PD "watchers" @()),
            (New-PD "locations" @()), (New-PD "waf_policies" @()), (New-PD "subnets" @()), (New-PD "vnets" @())
        )
        $results = @(Invoke-Section7Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "7.10" }).Status | Should -Be "INFO"
    }
}

Describe "Invoke-Section7Checks — 7.12 TLS 1.2+" {
    It "returns PASS when sslMinProto is TLSv1_2" {
        $agw = [PSCustomObject]@{
            name = "agw1"; enableHttp2 = "true"; wafEnabled = "true"
            wafMode = "Prevention"; wafReqBody = "true"; sslMinProto = "TLSv1_2"; wafPolicyId = ""
        }
        $pd = Merge-PD @(
            (New-PD "nsgs" @()), (New-PD "app_gateways" @($agw)), (New-PD "watchers" @()),
            (New-PD "locations" @()), (New-PD "waf_policies" @()), (New-PD "subnets" @()), (New-PD "vnets" @())
        )
        $results = @(Invoke-Section7Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "7.12" }).Status | Should -Be "PASS"
    }

    It "returns FAIL when sslMinProto is TLSv1_0" {
        $agw = [PSCustomObject]@{
            name = "agw2"; enableHttp2 = "false"; wafEnabled = "false"
            wafMode = ""; wafReqBody = "false"; sslMinProto = "TLSv1_0"; wafPolicyId = ""
        }
        $pd = Merge-PD @(
            (New-PD "nsgs" @()), (New-PD "app_gateways" @($agw)), (New-PD "watchers" @()),
            (New-PD "locations" @()), (New-PD "waf_policies" @()), (New-PD "subnets" @()), (New-PD "vnets" @())
        )
        $results = @(Invoke-Section7Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "7.12" }).Status | Should -Be "FAIL"
    }
}

Describe "Invoke-Section7Checks — 7.13 HTTP2" {
    It "returns PASS when HTTP2 enabled" {
        $agw = [PSCustomObject]@{
            name = "agw1"; enableHttp2 = "true"; wafEnabled = "true"
            wafMode = "Prevention"; wafReqBody = "true"; sslMinProto = "TLSv1_2"; wafPolicyId = ""
        }
        $pd = Merge-PD @(
            (New-PD "nsgs" @()), (New-PD "app_gateways" @($agw)), (New-PD "watchers" @()),
            (New-PD "locations" @()), (New-PD "waf_policies" @()), (New-PD "subnets" @()), (New-PD "vnets" @())
        )
        $results = @(Invoke-Section7Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "7.13" }).Status | Should -Be "PASS"
    }

    It "returns FAIL when HTTP2 disabled" {
        $agw = [PSCustomObject]@{
            name = "agw2"; enableHttp2 = "false"; wafEnabled = "false"
            wafMode = ""; wafReqBody = "false"; sslMinProto = "TLSv1_0"; wafPolicyId = ""
        }
        $pd = Merge-PD @(
            (New-PD "nsgs" @()), (New-PD "app_gateways" @($agw)), (New-PD "watchers" @()),
            (New-PD "locations" @()), (New-PD "waf_policies" @()), (New-PD "subnets" @()), (New-PD "vnets" @())
        )
        $results = @(Invoke-Section7Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "7.13" }).Status | Should -Be "FAIL"
    }
}

Describe "Invoke-Section7Checks — 7.14 WAF Body Inspection" {
    It "returns PASS when inline wafReqBody is true" {
        $agw = [PSCustomObject]@{
            name = "agw1"; enableHttp2 = "true"; wafEnabled = "true"
            wafMode = "Prevention"; wafReqBody = "true"; sslMinProto = "TLSv1_2"; wafPolicyId = ""
        }
        $pd = Merge-PD @(
            (New-PD "nsgs" @()), (New-PD "app_gateways" @($agw)), (New-PD "watchers" @()),
            (New-PD "locations" @()), (New-PD "waf_policies" @()), (New-PD "subnets" @()), (New-PD "vnets" @())
        )
        $results = @(Invoke-Section7Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "7.14" }).Status | Should -Be "PASS"
    }

    It "returns PASS when WAF policy has body inspection" {
        $agw = [PSCustomObject]@{
            name = "agw1"; enableHttp2 = "true"; wafEnabled = "false"
            wafMode = ""; wafReqBody = "false"; sslMinProto = "TLSv1_2"
            wafPolicyId = "/sub/x/wafpolicies/pol1"
        }
        $pol = [PSCustomObject]@{ id = "/sub/x/wafpolicies/pol1"; name = "pol1"; requestBodyInspect = "true"; botMode = "Prevention" }
        $pd = Merge-PD @(
            (New-PD "nsgs" @()), (New-PD "app_gateways" @($agw)), (New-PD "watchers" @()),
            (New-PD "locations" @()), (New-PD "waf_policies" @($pol)), (New-PD "subnets" @()), (New-PD "vnets" @())
        )
        $results = @(Invoke-Section7Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "7.14" }).Status | Should -Be "PASS"
    }
}

Describe "Invoke-Section7Checks — 7.15 Bot Protection" {
    It "returns PASS when WAF policy botMode is Prevention" {
        $agw = [PSCustomObject]@{
            name = "agw1"; enableHttp2 = "true"; wafEnabled = "false"
            wafMode = ""; wafReqBody = "false"; sslMinProto = "TLSv1_2"
            wafPolicyId = "/sub/x/wafpolicies/pol1"
        }
        $pol = [PSCustomObject]@{ id = "/sub/x/wafpolicies/pol1"; name = "pol1"; requestBodyInspect = "true"; botMode = "Prevention" }
        $pd = Merge-PD @(
            (New-PD "nsgs" @()), (New-PD "app_gateways" @($agw)), (New-PD "watchers" @()),
            (New-PD "locations" @()), (New-PD "waf_policies" @($pol)), (New-PD "subnets" @()), (New-PD "vnets" @())
        )
        $results = @(Invoke-Section7Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "7.15" }).Status | Should -Be "PASS"
    }

    It "returns FAIL when botMode is Detection" {
        $agw = [PSCustomObject]@{
            name = "agw1"; enableHttp2 = "true"; wafEnabled = "false"
            wafMode = ""; wafReqBody = "false"; sslMinProto = "TLSv1_2"
            wafPolicyId = "/sub/x/wafpolicies/pol1"
        }
        $pol = [PSCustomObject]@{ id = "/sub/x/wafpolicies/pol1"; name = "pol1"; requestBodyInspect = "true"; botMode = "Detection" }
        $pd = Merge-PD @(
            (New-PD "nsgs" @()), (New-PD "app_gateways" @($agw)), (New-PD "watchers" @()),
            (New-PD "locations" @()), (New-PD "waf_policies" @($pol)), (New-PD "subnets" @()), (New-PD "vnets" @())
        )
        $results = @(Invoke-Section7Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "7.15" }).Status | Should -Be "FAIL"
    }

    It "returns INFO when no WAF policy linked" {
        $agw = [PSCustomObject]@{
            name = "agw1"; enableHttp2 = "true"; wafEnabled = "true"
            wafMode = "Prevention"; wafReqBody = "true"; sslMinProto = "TLSv1_2"; wafPolicyId = ""
        }
        $pd = Merge-PD @(
            (New-PD "nsgs" @()), (New-PD "app_gateways" @($agw)), (New-PD "watchers" @()),
            (New-PD "locations" @()), (New-PD "waf_policies" @()), (New-PD "subnets" @()), (New-PD "vnets" @())
        )
        $results = @(Invoke-Section7Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "7.15" }).Status | Should -Be "INFO"
    }
}

Describe "Invoke-Section7TenantChecks — v6 manual controls" {
    It "emits the 3 v6 manual networking controls, all MANUAL" {
        $results = @(Invoke-Section7TenantChecks)
        ($results | Measure-Object).Count | Should -Be 3
        @($results | Where-Object { $_.Status -ne 'MANUAL' }).Count | Should -Be 0
        $ids = ($results.ControlId | Sort-Object) -join ','
        $ids | Should -Be (@('7.16','7.7','7.9') -join ',')
    }
}
