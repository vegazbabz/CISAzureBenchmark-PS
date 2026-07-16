#Requires -Version 7.0
<#
.SYNOPSIS
    Section 2 — Azure Databricks checks.
    Split from the former Tests\Checks.Tests.ps1 monolith; shared fixtures and the
    hermetic default mocks live in Tests\TestHelpers.ps1.
#>

param()

BeforeAll {
    . (Join-Path $PSScriptRoot "TestHelpers.ps1")
}

# =============================================================================
# SECTION 2 — DATABRICKS
# =============================================================================

Describe "Invoke-Section2Checks — no workspaces" {
    It "returns INFO for all six controls when no Databricks workspaces found" {
        $pd = New-PD -Key "databricks" -Records @()
        # Need subnets key too to avoid null dereference
        $pd["subnets"] = @{}
        $results = @(Invoke-Section2Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        $results | Should -HaveCount 6
        $results | ForEach-Object { $_.Status | Should -Be "INFO" }
    }
}

Describe "Invoke-Section2Checks — 2.1.1 customer-managed VNet" {
    It "returns PASS when workspace has a custom VNet (vnetId present)" {
        $ws = [PSCustomObject]@{ id = "/sub/x/ws/ws1"; name = "ws1"; vnetId = "/subscriptions/x/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/my-vnet"; noPublicIp = "true"; publicAccess = "Disabled"; privateEps = 1 }
        $pd = Merge-PD @((New-PD "databricks" @($ws)), (New-PD "subnets" @()))
        $results = @(Invoke-Section2Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "2.1.1" }).Status | Should -Be "PASS"
    }
    It "returns FAIL when workspace uses the managed VNet (no vnetId)" {
        $ws = [PSCustomObject]@{ id = "/sub/x/ws/ws2"; name = "ws2"; vnetId = ""; noPublicIp = "true"; publicAccess = "Disabled"; privateEps = 0 }
        $pd = Merge-PD @((New-PD "databricks" @($ws)), (New-PD "subnets" @()))
        $results = @(Invoke-Section2Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "2.1.1" }).Status | Should -Be "FAIL"
    }
}

Describe "Invoke-Section2TenantChecks — v6 manual controls" {
    It "emits the 6 v6 manual Databricks controls, all MANUAL" {
        $results = @(Invoke-Section2TenantChecks)
        ($results | Measure-Object).Count | Should -Be 6
        @($results | Where-Object { $_.Status -ne 'MANUAL' }).Count | Should -Be 0
        $ids = ((Invoke-Section2TenantChecks).ControlId | Sort-Object) -join ','
        $ids | Should -Be (@('2.1.12','2.1.3','2.1.4','2.1.5','2.1.6','2.1.8') -join ',')
    }
}

Describe "Invoke-Section2Checks — 2.1.2 NSGs" {
    It "returns PASS when all Databricks subnets have NSGs" {
        $vnetPath = "/subscriptions/x/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/my-vnet"
        $ws = [PSCustomObject]@{
            id = "/sub/x/ws/ws1"; name = "ws1"; resourceGroup = "rg"
            vnetId = $vnetPath; noPublicIp = "true"; publicAccess = "Disabled"; privateEps = 1
        }
        $subnets = @(
            [PSCustomObject]@{ vnetName = "my-vnet"; subnetName = "databricks-public";  hasNsg = "true" }
            [PSCustomObject]@{ vnetName = "my-vnet"; subnetName = "databricks-private"; hasNsg = "true" }
        )
        $pd = Merge-PD @(
            (New-PD "databricks" @($ws)),
            (New-PD "subnets"    $subnets)
        )


        $results = @(Invoke-Section2Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        $nsgResult = $results | Where-Object { $_.ControlId -eq "2.1.2" }
        $nsgResult.Status | Should -Be "PASS"
    }

    It "returns FAIL when a Databricks subnet has no NSG" {
        $vnetPath = "/subscriptions/x/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/my-vnet"
        $ws = [PSCustomObject]@{
            id = "/sub/x/ws/ws1"; name = "ws1"; resourceGroup = "rg"
            vnetId = $vnetPath; noPublicIp = "true"; publicAccess = "Disabled"; privateEps = 0
        }
        $subnets = @(
            [PSCustomObject]@{ vnetName = "my-vnet"; subnetName = "databricks-public";  hasNsg = "false" }
            [PSCustomObject]@{ vnetName = "my-vnet"; subnetName = "databricks-private"; hasNsg = "true" }
        )
        $pd = Merge-PD @(
            (New-PD "databricks" @($ws)),
            (New-PD "subnets"    $subnets)
        )


        $results = @(Invoke-Section2Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        $nsgResult = $results | Where-Object { $_.ControlId -eq "2.1.2" }
        $nsgResult.Status | Should -Be "FAIL"
    }
}

Describe "Invoke-Section2Checks — 2.1.9 No Public IP" {
    It "returns PASS when noPublicIp is true" {
        $ws = [PSCustomObject]@{
            id = "/sub/x/ws/ws1"; name = "ws1"; resourceGroup = "rg"
            vnetId = ""; noPublicIp = "true"; publicAccess = "Enabled"; privateEps = 0
        }
        $pd = Merge-PD @((New-PD "databricks" @($ws)), (New-PD "subnets" @()))
        $results = @(Invoke-Section2Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "2.1.9" }).Status | Should -Be "PASS"
    }

    It "returns FAIL when noPublicIp is false" {
        $ws = [PSCustomObject]@{
            id = "/sub/x/ws/ws1"; name = "ws1"; resourceGroup = "rg"
            vnetId = ""; noPublicIp = "false"; publicAccess = "Enabled"; privateEps = 0
        }
        $pd = Merge-PD @((New-PD "databricks" @($ws)), (New-PD "subnets" @()))
        $results = @(Invoke-Section2Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "2.1.9" }).Status | Should -Be "FAIL"
    }
}

Describe "Invoke-Section2Checks — 2.1.10 Public Network Access" {
    It "returns PASS when publicAccess is Disabled" {
        $ws = [PSCustomObject]@{
            id = "/x"; name = "ws1"; resourceGroup = "rg"
            vnetId = ""; noPublicIp = "true"; publicAccess = "Disabled"; privateEps = 1
        }
        $pd = Merge-PD @((New-PD "databricks" @($ws)), (New-PD "subnets" @()))
        $results = @(Invoke-Section2Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "2.1.10" }).Status | Should -Be "PASS"
    }

    It "returns FAIL when publicAccess is Enabled" {
        $ws = [PSCustomObject]@{
            id = "/x"; name = "ws1"; resourceGroup = "rg"
            vnetId = ""; noPublicIp = "true"; publicAccess = "Enabled"; privateEps = 0
        }
        $pd = Merge-PD @((New-PD "databricks" @($ws)), (New-PD "subnets" @()))
        $results = @(Invoke-Section2Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "2.1.10" }).Status | Should -Be "FAIL"
    }
}

# =============================================================================
# SECTION 2 — DATABRICKS (additional coverage)
# =============================================================================

Describe "Invoke-Section2Checks — 2.1.7 Diagnostic Logging" {
    BeforeAll {
        $script:ws2 = [PSCustomObject]@{
            id = "/sub/x/ws/ws1"; name = "ws1"; resourceGroup = "rg"
            vnetId = ""; noPublicIp = "true"; publicAccess = "Disabled"; privateEps = 1
        }
    }

    It "returns PASS when diagnostic settings exist" {
        $pd = Merge-PD @((New-PD "databricks" @($ws2)), (New-PD "subnets" @()))
        Mock Get-AzDiagnosticSetting { [PSCustomObject]@{ name = "diag1" } }
        $results = @(Invoke-Section2Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "2.1.7" }).Status | Should -Be "PASS"
    }

    It "returns FAIL when no diagnostic settings" {
        $pd = Merge-PD @((New-PD "databricks" @($ws2)), (New-PD "subnets" @()))
        Mock Get-AzDiagnosticSetting { @() }
        $results = @(Invoke-Section2Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "2.1.7" }).Status | Should -Be "FAIL"
    }
}

Describe "Invoke-Section2Checks — 2.1.11 Private Endpoints" {
    It "returns PASS when private endpoints configured" {
        $ws = [PSCustomObject]@{
            id = "/sub/x/ws/ws1"; name = "ws1"; resourceGroup = "rg"
            vnetId = ""; noPublicIp = "true"; publicAccess = "Disabled"; privateEps = 2
        }
        $pd = Merge-PD @((New-PD "databricks" @($ws)), (New-PD "subnets" @()))
        $results = @(Invoke-Section2Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "2.1.11" }).Status | Should -Be "PASS"
    }

    It "returns FAIL when no private endpoints" {
        $ws = [PSCustomObject]@{
            id = "/sub/x/ws/ws1"; name = "ws1"; resourceGroup = "rg"
            vnetId = ""; noPublicIp = "true"; publicAccess = "Disabled"; privateEps = 0
        }
        $pd = Merge-PD @((New-PD "databricks" @($ws)), (New-PD "subnets" @()))
        $results = @(Invoke-Section2Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "2.1.11" }).Status | Should -Be "FAIL"
    }
}
