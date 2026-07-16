#Requires -Version 7.0
<#
.SYNOPSIS
    Section 6 — Management & Governance checks.
    Split from the former Tests\Checks.Tests.ps1 monolith; shared fixtures and the
    hermetic default mocks live in Tests\TestHelpers.ps1.
#>

param()

BeforeAll {
    . (Join-Path $PSScriptRoot "TestHelpers.ps1")
}

# =============================================================================
# SECTION 6 — MONITORING & MANAGEMENT
# =============================================================================

Describe "Invoke-Section6Checks — 6.1.1.1 Diagnostic Setting Exists" {
    BeforeAll {
        function New-S6PD { Merge-PD @((New-PD "keyvaults" @()), (New-PD "app_services" @())) }
    }

    It "returns PASS when subscription diagnostic settings exist" {
        Mock Invoke-ArmRest {
            [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @([PSCustomObject]@{
                name = "ds1"
                logs = @([PSCustomObject]@{ enabled = "True"; category = "Security" },
                         [PSCustomObject]@{ enabled = "True"; category = "Administrative" },
                         [PSCustomObject]@{ enabled = "True"; category = "Alert" },
                         [PSCustomObject]@{ enabled = "True"; category = "Policy" })
            }) } }
        }
        Mock Get-AzLogProfile { @() }
        Mock Invoke-AzRestPaged { [PSCustomObject]@{ Success = $true; Data = @() } }

        $results = @(Invoke-Section6Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData (New-S6PD))
        ($results | Where-Object { $_.ControlId -eq "6.1.1.1" }).Status | Should -Be "PASS"
    }

    It "returns FAIL when no diagnostic settings" {
        Mock Invoke-ArmRest {
            [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @() } }
        }
        Mock Get-AzLogProfile { @() }
        Mock Invoke-AzRestPaged { [PSCustomObject]@{ Success = $true; Data = @() } }

        $results = @(Invoke-Section6Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData (New-S6PD))
        ($results | Where-Object { $_.ControlId -eq "6.1.1.1" }).Status | Should -Be "FAIL"
    }
}

Describe "Invoke-Section6Checks — 6.1.1.2 Required Log Categories" {
    BeforeAll {
        function New-S6PD { Merge-PD @((New-PD "keyvaults" @()), (New-PD "app_services" @())) }
    }

    It "returns PASS when all four categories enabled" {
        Mock Invoke-ArmRest {
            [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @([PSCustomObject]@{
                name = "ds1"
                logs = @(
                    [PSCustomObject]@{ enabled = "True"; category = "Security" }
                    [PSCustomObject]@{ enabled = "True"; category = "Administrative" }
                    [PSCustomObject]@{ enabled = "True"; category = "Alert" }
                    [PSCustomObject]@{ enabled = "True"; category = "Policy" }
                )
            }) } }
        }
        Mock Get-AzLogProfile { @() }
        Mock Invoke-AzRestPaged { [PSCustomObject]@{ Success = $true; Data = @() } }

        $results = @(Invoke-Section6Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData (New-S6PD))
        ($results | Where-Object { $_.ControlId -eq "6.1.1.2" }).Status | Should -Be "PASS"
    }

    It "returns FAIL when missing required categories" {
        Mock Invoke-ArmRest {
            [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @([PSCustomObject]@{
                name = "ds1"
                logs = @(
                    [PSCustomObject]@{ enabled = "True"; category = "Security" }
                )
            }) } }
        }
        Mock Get-AzLogProfile { @() }
        Mock Invoke-AzRestPaged { [PSCustomObject]@{ Success = $true; Data = @() } }

        $results = @(Invoke-Section6Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData (New-S6PD))
        ($results | Where-Object { $_.ControlId -eq "6.1.1.2" }).Status | Should -Be "FAIL"
    }
}

Describe "Invoke-Section6Checks — 6.1.1.4 Key Vault Diagnostic Logging" {
    It "returns PASS when KV has audit logging" {
        $kv = [PSCustomObject]@{ id = "/sub/x/kv/kv1"; name = "kv1" }
        $pd = Merge-PD @((New-PD "keyvaults" @($kv)), (New-PD "app_services" @()))

        Mock Get-AzDiagnosticSetting {
            [PSCustomObject]@{
                Log = @([PSCustomObject]@{ Enabled = $true; CategoryGroup = "audit"; Category = $null })
            }
        }
        Mock Get-AzLogProfile { @() }
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @() } } }
        Mock Invoke-AzRestPaged { [PSCustomObject]@{ Success = $true; Data = @() } }

        $results = @(Invoke-Section6Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "6.1.1.4" }).Status | Should -Be "PASS"
    }

    It "returns FAIL when KV has no audit logging" {
        $kv = [PSCustomObject]@{ id = "/sub/x/kv/kv1"; name = "kv1" }
        $pd = Merge-PD @((New-PD "keyvaults" @($kv)), (New-PD "app_services" @()))

        Mock Invoke-AzRestPaged { [PSCustomObject]@{ Success = $true; Data = @() } }

        $results = @(Invoke-Section6Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "6.1.1.4" }).Status | Should -Be "FAIL"
    }

    It "returns INFO when no Key Vaults" {
        $pd = Merge-PD @((New-PD "keyvaults" @()), (New-PD "app_services" @()))

        Mock Invoke-AzRestPaged { [PSCustomObject]@{ Success = $true; Data = @() } }

        $results = @(Invoke-Section6Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "6.1.1.4" }).Status | Should -Be "INFO"
    }
}

Describe "Invoke-Section6Checks — 6.1.2.x Activity Log Alerts" {
    BeforeAll {
        function New-S6PD { Merge-PD @((New-PD "keyvaults" @()), (New-PD "app_services" @())) }

        function New-AlertRule {
            param([string]$Field, [string]$Equals)
            [PSCustomObject]@{
                condition = [PSCustomObject]@{
                    allOf = @([PSCustomObject]@{ field = $Field; equals = $Equals })
                }
            }
        }
    }

    It "returns PASS for 6.1.2.1 when policy assignment alert exists" {
        Mock Get-AzActivityLogAlert {
            [PSCustomObject]@{
                Condition = [PSCustomObject]@{
                    AllOf = @([PSCustomObject]@{ Field = "operationName"; Equal = "microsoft.authorization/policyassignments/write" })
                }
            }
        }
        Mock Get-AzLogProfile { @() }
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @() } } }
        Mock Invoke-AzRestPaged { [PSCustomObject]@{ Success = $true; Data = @() } }

        $results = @(Invoke-Section6Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData (New-S6PD))
        ($results | Where-Object { $_.ControlId -eq "6.1.2.1" }).Status | Should -Be "PASS"
    }

    It "returns FAIL for 6.1.2.1 when no matching alert" {
        Mock Get-AzActivityLogAlert { @() }
        Mock Get-AzLogProfile { @() }
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @() } } }
        Mock Invoke-AzRestPaged { [PSCustomObject]@{ Success = $true; Data = @() } }

        $results = @(Invoke-Section6Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData (New-S6PD))
        ($results | Where-Object { $_.ControlId -eq "6.1.2.1" }).Status | Should -Be "FAIL"
    }

    It "returns PASS for all 6.1.2.x when all alerts configured" {
        Mock Get-AzActivityLogAlert {
            @(
                [PSCustomObject]@{ Condition = [PSCustomObject]@{ AllOf = @([PSCustomObject]@{ Field = "operationName"; Equal = "microsoft.authorization/policyassignments/write" }) } }
                [PSCustomObject]@{ Condition = [PSCustomObject]@{ AllOf = @([PSCustomObject]@{ Field = "operationName"; Equal = "microsoft.authorization/policyassignments/delete" }) } }
                [PSCustomObject]@{ Condition = [PSCustomObject]@{ AllOf = @([PSCustomObject]@{ Field = "operationName"; Equal = "microsoft.network/networksecuritygroups/write" }) } }
                [PSCustomObject]@{ Condition = [PSCustomObject]@{ AllOf = @([PSCustomObject]@{ Field = "operationName"; Equal = "microsoft.network/networksecuritygroups/delete" }) } }
                [PSCustomObject]@{ Condition = [PSCustomObject]@{ AllOf = @([PSCustomObject]@{ Field = "operationName"; Equal = "microsoft.security/securitysolutions/write" }) } }
                [PSCustomObject]@{ Condition = [PSCustomObject]@{ AllOf = @([PSCustomObject]@{ Field = "operationName"; Equal = "microsoft.security/securitysolutions/delete" }) } }
                [PSCustomObject]@{ Condition = [PSCustomObject]@{ AllOf = @([PSCustomObject]@{ Field = "operationName"; Equal = "microsoft.sql/servers/firewallrules/write" }) } }
                [PSCustomObject]@{ Condition = [PSCustomObject]@{ AllOf = @([PSCustomObject]@{ Field = "operationName"; Equal = "microsoft.sql/servers/firewallrules/delete" }) } }
                [PSCustomObject]@{ Condition = [PSCustomObject]@{ AllOf = @([PSCustomObject]@{ Field = "operationName"; Equal = "microsoft.network/publicipaddresses/write" }) } }
                [PSCustomObject]@{ Condition = [PSCustomObject]@{ AllOf = @([PSCustomObject]@{ Field = "operationName"; Equal = "microsoft.network/publicipaddresses/delete" }) } }
                [PSCustomObject]@{ Condition = [PSCustomObject]@{ AllOf = @([PSCustomObject]@{ Field = "category"; Equal = "servicehealth" }) } }
            )
        }
        Mock Get-AzLogProfile { @() }
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @() } } }
        Mock Invoke-AzRestPaged { [PSCustomObject]@{ Success = $true; Data = @() } }

        $results = @(Invoke-Section6Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData (New-S6PD))
        foreach ($cid in @("6.1.2.1","6.1.2.2","6.1.2.3","6.1.2.4","6.1.2.5","6.1.2.6","6.1.2.7","6.1.2.8","6.1.2.9","6.1.2.10","6.1.2.11")) {
            ($results | Where-Object { $_.ControlId -eq $cid }).Status | Should -Be "PASS" -Because "control $cid"
        }
    }

    It "returns FAIL for 6.1.2.11 when no ServiceHealth alert" {
        Mock Get-AzActivityLogAlert {
            @([PSCustomObject]@{ Condition = [PSCustomObject]@{ AllOf = @([PSCustomObject]@{ Field = "operationName"; Equal = "microsoft.authorization/policyassignments/write" }) } })
        }
        Mock Get-AzLogProfile { @() }
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @() } } }
        Mock Invoke-AzRestPaged { [PSCustomObject]@{ Success = $true; Data = @() } }

        $results = @(Invoke-Section6Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData (New-S6PD))
        ($results | Where-Object { $_.ControlId -eq "6.1.2.11" }).Status | Should -Be "FAIL"
    }
}

Describe "Invoke-Section6Checks — 6.1.3.1 Application Insights" {
    BeforeAll {
        function New-S6PD { Merge-PD @((New-PD "keyvaults" @()), (New-PD "app_services" @())) }
    }

    It "returns PASS when App Insights components exist" {
        Mock Invoke-AzRestPaged { [PSCustomObject]@{ Success = $true; Data = @([PSCustomObject]@{ name = "ai1" }) } }

        $results = @(Invoke-Section6Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData (New-S6PD))
        ($results | Where-Object { $_.ControlId -eq "6.1.3.1" }).Status | Should -Be "PASS"
    }

    It "returns FAIL when no App Insights components" {
        Mock Invoke-AzRestPaged { [PSCustomObject]@{ Success = $true; Data = @() } }

        $results = @(Invoke-Section6Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData (New-S6PD))
        ($results | Where-Object { $_.ControlId -eq "6.1.3.1" }).Status | Should -Be "FAIL"
    }
}

Describe "Invoke-Section6TenantChecks — v6 manual controls" {
    It "emits exactly the 9 v6 manual controls, all MANUAL" {
        $results = @(Invoke-Section6TenantChecks)
        ($results | Measure-Object).Count | Should -Be 9
        @($results | Where-Object { $_.Status -ne 'MANUAL' }).Count | Should -Be 0
    }

    It "covers the expected v6 control IDs" {
        $ids = (Invoke-Section6TenantChecks).ControlId | Sort-Object
        $expected = @('6.1.1.3','6.1.1.5','6.1.1.6','6.1.1.7','6.1.1.8','6.1.1.9','6.1.4','6.1.5','6.2') | Sort-Object
        ($ids -join ',') | Should -Be ($expected -join ',')
    }
}

Describe "Invoke-Section6Checks — disabled alert rules and read failures" {
    BeforeAll {
        function New-S6PD2 { Merge-PD @((New-PD "keyvaults" @())) }
    }

    It "6.1.2.1 FAIL when the only matching alert rule is disabled" {
        Mock Get-AzActivityLogAlert {
            [PSCustomObject]@{
                Enabled   = $false
                Condition = [PSCustomObject]@{ AllOf = @([PSCustomObject]@{ Field = "operationName"; Equal = "microsoft.authorization/policyassignments/write" }) }
            }
        }
        Mock Get-AzLogProfile { @() }
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @() } } }
        Mock Invoke-AzRestPaged { [PSCustomObject]@{ Success = $true; Data = @() } }
        $r = @(Invoke-Section6Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData (New-S6PD2))
        ($r | Where-Object { $_.ControlId -eq "6.1.2.1" }).Status | Should -Be "FAIL"
    }

    It "6.1.2.1 PASS when the matching alert rule is enabled" {
        Mock Get-AzActivityLogAlert {
            [PSCustomObject]@{
                Enabled   = $true
                Condition = [PSCustomObject]@{ AllOf = @([PSCustomObject]@{ Field = "operationName"; Equal = "microsoft.authorization/policyassignments/write" }) }
            }
        }
        Mock Get-AzLogProfile { @() }
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @() } } }
        Mock Invoke-AzRestPaged { [PSCustomObject]@{ Success = $true; Data = @() } }
        $r = @(Invoke-Section6Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData (New-S6PD2))
        ($r | Where-Object { $_.ControlId -eq "6.1.2.1" }).Status | Should -Be "PASS"
    }

    It "6.1.2.x ERROR (not FAIL) when the alert list cannot be read" {
        Mock Get-AzActivityLogAlert { throw "insufficient privileges" }
        Mock Get-AzLogProfile { @() }
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @() } } }
        Mock Invoke-AzRestPaged { [PSCustomObject]@{ Success = $true; Data = @() } }
        $r = @(Invoke-Section6Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData (New-S6PD2))
        ($r | Where-Object { $_.ControlId -eq "6.1.2.1" }).Status | Should -Be "ERROR"
        ($r | Where-Object { $_.ControlId -eq "6.1.2.11" }).Status | Should -Be "ERROR"
    }

    It "6.1.1.1 ERROR (not FAIL) when the diagnostic settings read fails" {
        Mock Get-AzActivityLogAlert { @() }
        Mock Get-AzLogProfile { @() }
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $false; Data = $null; Error = "429 throttled" } }
        Mock Invoke-AzRestPaged { [PSCustomObject]@{ Success = $true; Data = @() } }
        $r = @(Invoke-Section6Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData (New-S6PD2))
        ($r | Where-Object { $_.ControlId -eq "6.1.1.1" }).Status | Should -Be "ERROR"
    }

    It "6.1.3.1 ERROR (not FAIL) when the Application Insights read fails" {
        Mock Get-AzActivityLogAlert { @() }
        Mock Get-AzLogProfile { @() }
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @() } } }
        Mock Invoke-AzRestPaged { [PSCustomObject]@{ Success = $false; Data = $null; Error = "403 forbidden" } }
        $r = @(Invoke-Section6Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData (New-S6PD2))
        ($r | Where-Object { $_.ControlId -eq "6.1.3.1" }).Status | Should -Be "ERROR"
    }
}
