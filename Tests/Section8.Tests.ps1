#Requires -Version 7.0
<#
.SYNOPSIS
    Section 8 — Security Services checks.
    Split from the former Tests\Checks.Tests.ps1 monolith; shared fixtures and the
    hermetic default mocks live in Tests\TestHelpers.ps1.
#>

param()

BeforeAll {
    . (Join-Path $PSScriptRoot "TestHelpers.ps1")
}

# =============================================================================
# SECTION 8 — SECURITY SERVICES
# =============================================================================

Describe "Invoke-Section8Checks — 8.4.1 Bastion" {
    It "returns PASS when a Bastion host exists" {
        $bastion = [PSCustomObject]@{ name = "bastion1"; sku = [PSCustomObject]@{ name = "Standard" } }
        $pd = Merge-PD @(
            (New-PD "bastion" @($bastion))
            (New-PD "vms"     @([PSCustomObject]@{ name = "vm1" }))
            (New-PD "vnets"   @())
            (New-PD "keyvaults" @())
        )
        Mock Get-AzSecurityPricing { [PSCustomObject]@{ PricingTier = "Standard" } }
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @() } } }

        $results = @(Invoke-Section8Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "8.4.1" }).Status | Should -Be "PASS"
    }

    It "returns INFO when no VMs and no Bastion" {
        $pd = Merge-PD @(
            (New-PD "bastion"   @())
            (New-PD "vms"       @())
            (New-PD "vnets"     @())
            (New-PD "keyvaults" @())
        )
        Mock Get-AzSecurityPricing { [PSCustomObject]@{ PricingTier = "Standard" } }
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @() } } }

        $results = @(Invoke-Section8Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "8.4.1" }).Status | Should -Be "INFO"
    }

    It "returns FAIL when VMs exist but no Bastion" {
        $pd = Merge-PD @(
            (New-PD "bastion"   @())
            (New-PD "vms"       @([PSCustomObject]@{ name = "vm1" }))
            (New-PD "vnets"     @())
            (New-PD "keyvaults" @())
        )
        Mock Get-AzSecurityPricing { [PSCustomObject]@{ PricingTier = "Standard" } }
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @() } } }

        $results = @(Invoke-Section8Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "8.4.1" }).Status | Should -Be "FAIL"
    }
}

Describe "Invoke-Section8Checks — 8.3 Key Vault purge protection" {
    It "returns PASS for Key Vault with purge protection enabled" {
        $vault = [PSCustomObject]@{
            id = "/sub/x/kv/kv1"; name = "kv1"
            purgeProtection = $true; rbac = $true
            publicAccess = "Disabled"; privateEps = 1
        }
        $pd = Merge-PD @(
            (New-PD "keyvaults" @($vault))
            (New-PD "bastion"   @())
            (New-PD "vms"       @())
            (New-PD "vnets"     @())
        )
        Mock Get-AzSecurityPricing  { [PSCustomObject]@{ PricingTier = "Standard" } }
        Mock Get-AzKeyVaultKey       { @() }
        Mock Get-AzKeyVaultSecret    { @() }
        Mock Get-AzKeyVaultCertificate { @() }
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @() } } }

        $results = @(Invoke-Section8Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "8.3.5" }).Status | Should -Be "PASS"
    }

    It "returns FAIL for Key Vault with purge protection disabled" {
        $vault = [PSCustomObject]@{
            id = "/sub/x/kv/kv2"; name = "kv2"
            purgeProtection = $false; rbac = $true
            publicAccess = "Enabled"; privateEps = 0
        }
        $pd = Merge-PD @(
            (New-PD "keyvaults" @($vault))
            (New-PD "bastion"   @())
            (New-PD "vms"       @())
            (New-PD "vnets"     @())
        )
        Mock Get-AzSecurityPricing  { [PSCustomObject]@{ PricingTier = "Standard" } }
        Mock Get-AzKeyVaultKey       { @() }
        Mock Get-AzKeyVaultSecret    { @() }
        Mock Get-AzKeyVaultCertificate { @() }
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @() } } }

        $results = @(Invoke-Section8Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "8.3.5" }).Status | Should -Be "FAIL"
    }
}

Describe "Invoke-Section8TenantChecks — v6 manual controls" {
    It "emits the 8 v6 manual security controls, all MANUAL" {
        $results = @(Invoke-Section8TenantChecks)
        ($results | Measure-Object).Count | Should -Be 8
        @($results | Where-Object { $_.Status -ne 'MANUAL' }).Count | Should -Be 0
    }
    It "covers the expected v6 control IDs" {
        $ids = ((Invoke-Section8TenantChecks).ControlId | Sort-Object) -join ','
        $expected = (@('8.1.3.2','8.1.3.4','8.1.3.5','8.1.5.2','8.1.11','8.1.16','8.2.1','8.3.10') | Sort-Object) -join ','
        $ids | Should -Be $expected
    }
}

# =============================================================================
# SECTION 8 — SECURITY SERVICES (additional coverage)
# =============================================================================

Describe "Invoke-Section8Checks — 8.1.x Defender Plans" {
    BeforeAll {
        function New-S8PD {
            Merge-PD @(
                (New-PD "keyvaults" @()), (New-PD "bastion" @()),
                (New-PD "vms" @()), (New-PD "vnets" @())
            )
        }
    }

    It "returns PASS for Defender plan when tier is Standard" {
        Mock Get-AzSecurityPricing { [PSCustomObject]@{ PricingTier = "Standard" } }
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ properties = [PSCustomObject]@{ enabled = "true" }; value = @() } } }

        $results = @(Invoke-Section8Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData (New-S8PD))
        ($results | Where-Object { $_.ControlId -eq "8.1.1.1" }).Status | Should -Be "PASS"
    }

    It "returns FAIL for Defender plan when tier is Free" {
        Mock Get-AzSecurityPricing { [PSCustomObject]@{ PricingTier = "Free" } }
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ properties = [PSCustomObject]@{ enabled = "false" }; value = @() } } }

        $results = @(Invoke-Section8Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData (New-S8PD))
        ($results | Where-Object { $_.ControlId -eq "8.1.1.1" }).Status | Should -Be "FAIL"
    }
}

Describe "Invoke-Section8Checks — 8.1.3.3 WDATP Integration" {
    BeforeAll {
        function New-S8PD {
            Merge-PD @(
                (New-PD "keyvaults" @()), (New-PD "bastion" @()),
                (New-PD "vms" @()), (New-PD "vnets" @())
            )
        }
    }

    It "returns PASS when WDATP enabled" {
        Mock Get-AzSecurityPricing { [PSCustomObject]@{ PricingTier = "Standard" } }
        Mock Invoke-ArmRest {
            param($Uri)
            if ($Uri -match "WDATP") {
                return [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ properties = [PSCustomObject]@{ enabled = "true" } } }
            }
            return [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @() } }
        }

        $results = @(Invoke-Section8Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData (New-S8PD))
        ($results | Where-Object { $_.ControlId -eq "8.1.3.3" }).Status | Should -Be "PASS"
    }

    It "returns FAIL when WDATP disabled" {
        Mock Get-AzSecurityPricing { [PSCustomObject]@{ PricingTier = "Standard" } }
        Mock Invoke-ArmRest {
            param($Uri)
            if ($Uri -match "WDATP") {
                return [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ properties = [PSCustomObject]@{ enabled = "false" } } }
            }
            return [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @() } }
        }

        $results = @(Invoke-Section8Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData (New-S8PD))
        ($results | Where-Object { $_.ControlId -eq "8.1.3.3" }).Status | Should -Be "FAIL"
    }
}

Describe "Invoke-Section8Checks — 8.1.10 MDE TVM" {
    BeforeAll {
        function New-S8PD {
            Merge-PD @(
                (New-PD "keyvaults" @()), (New-PD "bastion" @()),
                (New-PD "vms" @()), (New-PD "vnets" @())
            )
        }
    }

    It "returns PASS when MdeTvm is selected provider" {
        Mock Get-AzSecurityPricing { [PSCustomObject]@{ PricingTier = "Standard" } }
        Mock Invoke-ArmRest {
            param($Uri)
            if ($Uri -match "WDATP") { return [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ properties = [PSCustomObject]@{ enabled = "true" } } } }
            if ($Uri -match "serverVulnerabilityAssessmentsSettings") {
                return [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{
                    value = @([PSCustomObject]@{ properties = [PSCustomObject]@{ selectedProvider = "MdeTvm" } })
                } }
            }
            return [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @() } }
        }

        $results = @(Invoke-Section8Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData (New-S8PD))
        ($results | Where-Object { $_.ControlId -eq "8.1.10" }).Status | Should -Be "PASS"
    }

    It "returns FAIL when MdeTvm not configured" {
        Mock Get-AzSecurityPricing { [PSCustomObject]@{ PricingTier = "Standard" } }
        Mock Invoke-ArmRest {
            param($Uri)
            if ($Uri -match "WDATP") { return [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ properties = [PSCustomObject]@{ enabled = "true" } } } }
            if ($Uri -match "serverVulnerabilityAssessmentsSettings") {
                return [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @() } }
            }
            return [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @() } }
        }

        $results = @(Invoke-Section8Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData (New-S8PD))
        ($results | Where-Object { $_.ControlId -eq "8.1.10" }).Status | Should -Be "FAIL"
    }
}

Describe "Invoke-Section8Checks — 8.1.12 Owner Notification" {
    BeforeAll {
        function New-S8PD {
            Merge-PD @(
                (New-PD "keyvaults" @()), (New-PD "bastion" @()),
                (New-PD "vms" @()), (New-PD "vnets" @())
            )
        }
    }

    It "returns PASS when Owner in notificationsByRole" {
        Mock Get-AzSecurityPricing { [PSCustomObject]@{ PricingTier = "Standard" } }
        Mock Invoke-ArmRest {
            param($Uri)
            if ($Uri -match "WDATP") { return [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ properties = [PSCustomObject]@{ enabled = "true" } } } }
            if ($Uri -match "securityContacts") {
                return [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{
                    value = @([PSCustomObject]@{
                        properties = [PSCustomObject]@{
                            notificationsByRole = [PSCustomObject]@{ state = "On"; roles = @("Owner") }
                            notificationsSource = @([PSCustomObject]@{ sourceType = "AttackPath" })
                        }
                    })
                } }
            }
            return [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @() } }
        }

        $results = @(Invoke-Section8Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData (New-S8PD))
        ($results | Where-Object { $_.ControlId -eq "8.1.12" }).Status | Should -Be "PASS"
    }

    It "returns FAIL when contact has no Owner role" {
        Mock Get-AzSecurityPricing { [PSCustomObject]@{ PricingTier = "Standard" } }
        Mock Invoke-ArmRest {
            param($Uri)
            if ($Uri -match "WDATP") { return [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ properties = [PSCustomObject]@{ enabled = "true" } } } }
            if ($Uri -match "securityContacts") { return [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @() } } }
            return [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @() } }
        }

        $results = @(Invoke-Section8Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData (New-S8PD))
        ($results | Where-Object { $_.ControlId -eq "8.1.12" }).Status | Should -Be "FAIL"
    }
}

Describe "Invoke-Section8Checks — 8.3.x Key Vault checks" {
    BeforeAll {
        function New-KV {
            param([bool]$Purge = $true, [bool]$Rbac = $true, [string]$Pub = "Disabled", [int]$Eps = 1)
            [PSCustomObject]@{
                id = "/sub/x/kv/kv1"; name = "kv1"; resourceGroup = "rg"
                purgeProtection = $Purge; rbac = $Rbac; publicAccess = $Pub; privateEps = $Eps
            }
        }
    }

    It "8.3.6 — PASS when RBAC enabled" {
        $pd = Merge-PD @((New-PD "keyvaults" @(New-KV -Rbac $true)), (New-PD "bastion" @()), (New-PD "vms" @()), (New-PD "vnets" @()))
        Mock Get-AzSecurityPricing    { [PSCustomObject]@{ PricingTier = "Standard" } }
        Mock Get-AzKeyVaultKey        { @() }
        Mock Get-AzKeyVaultSecret     { @() }
        Mock Get-AzKeyVaultCertificate { @() }
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @() } } }
        $results = @(Invoke-Section8Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "8.3.6" }).Status | Should -Be "PASS"
    }

    It "8.3.6 — FAIL when RBAC not enabled" {
        $pd = Merge-PD @((New-PD "keyvaults" @(New-KV -Rbac $false)), (New-PD "bastion" @()), (New-PD "vms" @()), (New-PD "vnets" @()))
        Mock Get-AzSecurityPricing    { [PSCustomObject]@{ PricingTier = "Standard" } }
        Mock Get-AzKeyVaultKey        { @() }
        Mock Get-AzKeyVaultSecret     { @() }
        Mock Get-AzKeyVaultCertificate { @() }
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @() } } }
        $results = @(Invoke-Section8Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "8.3.6" }).Status | Should -Be "FAIL"
    }

    It "8.3.7 — PASS when public access Disabled" {
        $pd = Merge-PD @((New-PD "keyvaults" @(New-KV -Pub "Disabled")), (New-PD "bastion" @()), (New-PD "vms" @()), (New-PD "vnets" @()))
        Mock Get-AzSecurityPricing    { [PSCustomObject]@{ PricingTier = "Standard" } }
        Mock Get-AzKeyVaultKey        { @() }
        Mock Get-AzKeyVaultSecret     { @() }
        Mock Get-AzKeyVaultCertificate { @() }
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @() } } }
        $results = @(Invoke-Section8Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "8.3.7" }).Status | Should -Be "PASS"
    }

    It "8.3.7 — FAIL when public access Enabled" {
        $pd = Merge-PD @((New-PD "keyvaults" @(New-KV -Pub "Enabled")), (New-PD "bastion" @()), (New-PD "vms" @()), (New-PD "vnets" @()))
        Mock Get-AzSecurityPricing    { [PSCustomObject]@{ PricingTier = "Standard" } }
        Mock Get-AzKeyVaultKey        { @() }
        Mock Get-AzKeyVaultSecret     { @() }
        Mock Get-AzKeyVaultCertificate { @() }
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @() } } }
        $results = @(Invoke-Section8Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "8.3.7" }).Status | Should -Be "FAIL"
    }

    It "8.3.8 — PASS when private endpoints configured" {
        $pd = Merge-PD @((New-PD "keyvaults" @(New-KV -Eps 2)), (New-PD "bastion" @()), (New-PD "vms" @()), (New-PD "vnets" @()))
        Mock Get-AzSecurityPricing    { [PSCustomObject]@{ PricingTier = "Standard" } }
        Mock Get-AzKeyVaultKey        { @() }
        Mock Get-AzKeyVaultSecret     { @() }
        Mock Get-AzKeyVaultCertificate { @() }
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @() } } }
        $results = @(Invoke-Section8Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "8.3.8" }).Status | Should -Be "PASS"
    }

    It "8.3.8 — FAIL when no private endpoints" {
        $pd = Merge-PD @((New-PD "keyvaults" @(New-KV -Eps 0)), (New-PD "bastion" @()), (New-PD "vms" @()), (New-PD "vnets" @()))
        Mock Get-AzSecurityPricing    { [PSCustomObject]@{ PricingTier = "Standard" } }
        Mock Get-AzKeyVaultKey        { @() }
        Mock Get-AzKeyVaultSecret     { @() }
        Mock Get-AzKeyVaultCertificate { @() }
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @() } } }
        $results = @(Invoke-Section8Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "8.3.8" }).Status | Should -Be "FAIL"
    }

    It "8.3.1 — PASS when all keys have expiration (RBAC vault)" {
        $kv = New-KV -Rbac $true
        $pd = Merge-PD @((New-PD "keyvaults" @($kv)), (New-PD "bastion" @()), (New-PD "vms" @()), (New-PD "vnets" @()))
        Mock Get-AzSecurityPricing { [PSCustomObject]@{ PricingTier = "Free" } }
        Mock Get-AzKeyVaultKey {
            @([PSCustomObject]@{ Name = "k1"; Attributes = [PSCustomObject]@{ Expires = [datetime]"2025-12-31" } })
        }
        Mock Get-AzKeyVaultSecret     { @() }
        Mock Get-AzKeyVaultCertificate { @() }
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @() } } }
        $results = @(Invoke-Section8Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "8.3.1" }).Status | Should -Be "PASS"
    }

    It "8.3.1 — retries a throttled key listing instead of reporting ERROR" {
        $kv = New-KV -Rbac $true
        $pd = Merge-PD @((New-PD "keyvaults" @($kv)), (New-PD "bastion" @()), (New-PD "vms" @()), (New-PD "vnets" @()))
        Mock Get-AzSecurityPricing { [PSCustomObject]@{ PricingTier = "Free" } }
        Mock Start-Sleep {}
        $script:kvKeyCalls = 0
        Mock Get-AzKeyVaultKey {
            $script:kvKeyCalls++
            if ($script:kvKeyCalls -eq 1) { throw "Response status code does not indicate success: 429 (Too Many Requests)" }
            @([PSCustomObject]@{ Name = "k1"; Attributes = [PSCustomObject]@{ Expires = [datetime]"2025-12-31" } })
        }
        Mock Get-AzKeyVaultSecret     { @() }
        Mock Get-AzKeyVaultCertificate { @() }
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @() } } }
        $results = @(Invoke-Section8Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "8.3.1" }).Status | Should -Be "PASS"
        $script:kvKeyCalls | Should -Be 2
    }

    It "8.3.1 — FAIL when key has no expiration (RBAC vault)" {
        $kv = New-KV -Rbac $true
        $pd = Merge-PD @((New-PD "keyvaults" @($kv)), (New-PD "bastion" @()), (New-PD "vms" @()), (New-PD "vnets" @()))
        Mock Get-AzSecurityPricing { [PSCustomObject]@{ PricingTier = "Free" } }
        Mock Get-AzKeyVaultKey {
            @([PSCustomObject]@{ Name = "k-no-exp"; Attributes = [PSCustomObject]@{ Expires = $null } })
        }
        Mock Get-AzKeyVaultSecret     { @() }
        Mock Get-AzKeyVaultCertificate { @() }
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @() } } }
        $results = @(Invoke-Section8Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "8.3.1" }).Status | Should -Be "FAIL"
    }

    It "8.3.3 — PASS when all secrets have expiration (RBAC vault)" {
        $kv = New-KV -Rbac $true
        $pd = Merge-PD @((New-PD "keyvaults" @($kv)), (New-PD "bastion" @()), (New-PD "vms" @()), (New-PD "vnets" @()))
        Mock Get-AzSecurityPricing { [PSCustomObject]@{ PricingTier = "Free" } }
        Mock Get-AzKeyVaultKey        { @() }
        Mock Get-AzKeyVaultSecret {
            @([PSCustomObject]@{ Name = "s1"; Attributes = [PSCustomObject]@{ Expires = [datetime]"2025-12-31" } })
        }
        Mock Get-AzKeyVaultCertificate { @() }
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @() } } }
        $results = @(Invoke-Section8Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "8.3.3" }).Status | Should -Be "PASS"
    }

    It "8.3.3 — FAIL when secret has no expiration (RBAC vault)" {
        $kv = New-KV -Rbac $true
        $pd = Merge-PD @((New-PD "keyvaults" @($kv)), (New-PD "bastion" @()), (New-PD "vms" @()), (New-PD "vnets" @()))
        Mock Get-AzSecurityPricing { [PSCustomObject]@{ PricingTier = "Free" } }
        Mock Get-AzKeyVaultKey        { @() }
        Mock Get-AzKeyVaultSecret {
            @([PSCustomObject]@{ Name = "s-no-exp"; Attributes = [PSCustomObject]@{ Expires = $null } })
        }
        Mock Get-AzKeyVaultCertificate { @() }
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @() } } }
        $results = @(Invoke-Section8Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "8.3.3" }).Status | Should -Be "FAIL"
    }

    It "8.3.11 — PASS when cert validity <= 12 months" {
        $kv = New-KV -Rbac $true
        $pd = Merge-PD @((New-PD "keyvaults" @($kv)), (New-PD "bastion" @()), (New-PD "vms" @()), (New-PD "vnets" @()))
        $now = [datetime]::UtcNow
        Mock Get-AzSecurityPricing { [PSCustomObject]@{ PricingTier = "Free" } }
        Mock Get-AzKeyVaultKey        { @() }
        Mock Get-AzKeyVaultSecret     { @() }
        Mock Get-AzKeyVaultCertificate {
            @([PSCustomObject]@{ Name = "c1"; Attributes = [PSCustomObject]@{
                Created = $now.AddMonths(-6)
                Expires = $now.AddMonths(6)
            } })
        }
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @() } } }
        $results = @(Invoke-Section8Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "8.3.11" }).Status | Should -Be "PASS"
    }

    It "8.3.11 — FAIL when cert validity > 12 months" {
        $kv = New-KV -Rbac $true
        $pd = Merge-PD @((New-PD "keyvaults" @($kv)), (New-PD "bastion" @()), (New-PD "vms" @()), (New-PD "vnets" @()))
        Mock Get-AzSecurityPricing { [PSCustomObject]@{ PricingTier = "Free" } }
        Mock Get-AzKeyVaultKey        { @() }
        Mock Get-AzKeyVaultSecret     { @() }
        Mock Get-AzKeyVaultCertificate {
            @([PSCustomObject]@{ Name = "c-long"; Attributes = [PSCustomObject]@{
                Created = [datetime]"2024-01-01"
                Expires = [datetime]"2026-01-01"
            } })
        }
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @() } } }
        $results = @(Invoke-Section8Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "8.3.11" }).Status | Should -Be "FAIL"
    }
}

Describe "Invoke-Section8Checks — 8.5 DDoS Protection" {
    It "returns PASS when VNet has DDoS protection" {
        $vnet = [PSCustomObject]@{ name = "vnet1"; hasDdos = "true" }
        $pd = Merge-PD @(
            (New-PD "keyvaults" @()), (New-PD "bastion" @()),
            (New-PD "vms" @()), (New-PD "vnets" @($vnet))
        )
        Mock Get-AzSecurityPricing { [PSCustomObject]@{ PricingTier = "Standard" } }
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @() } } }

        $results = @(Invoke-Section8Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "8.5" }).Status | Should -Be "PASS"
    }

    It "returns FAIL when VNet lacks DDoS protection" {
        $vnet = [PSCustomObject]@{ name = "vnet1"; hasDdos = "false" }
        $pd = Merge-PD @(
            (New-PD "keyvaults" @()), (New-PD "bastion" @()),
            (New-PD "vms" @()), (New-PD "vnets" @($vnet))
        )
        Mock Get-AzSecurityPricing { [PSCustomObject]@{ PricingTier = "Standard" } }
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @() } } }

        $results = @(Invoke-Section8Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "8.5" }).Status | Should -Be "FAIL"
    }

    It "returns INFO when no VNets" {
        $pd = Merge-PD @(
            (New-PD "keyvaults" @()), (New-PD "bastion" @()),
            (New-PD "vms" @()), (New-PD "vnets" @())
        )
        Mock Get-AzSecurityPricing { [PSCustomObject]@{ PricingTier = "Standard" } }
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @() } } }

        $results = @(Invoke-Section8Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "8.5" }).Status | Should -Be "INFO"
    }
}


# ══════════════════════════════════════════════════════════════════════════════
# v6 check-logic fixes — security contact notifications, alert Enabled, read failures
# ══════════════════════════════════════════════════════════════════════════════

Describe "Invoke-Section8Checks — 8.1.13/8.1.14/8.1.15 security contact notifications" {
    BeforeAll {
        function New-S8PD2 {
            Merge-PD @(
                (New-PD "keyvaults" @()), (New-PD "bastion" @()),
                (New-PD "vms" @()), (New-PD "vnets" @())
            )
        }
        function New-ContactMock {
            param([object]$Properties)
            Mock Get-AzSecurityPricing { [PSCustomObject]@{ PricingTier = "Standard" } }
            $script:__contactProps = $Properties
            Mock Invoke-ArmRest {
                param($Uri)
                if ($Uri -match "WDATP") { return [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ properties = [PSCustomObject]@{ enabled = "true" } } } }
                if ($Uri -match "securityContacts") {
                    return [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @([PSCustomObject]@{ properties = $script:__contactProps }) } }
                }
                return [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @() } }
            }
        }
    }

    It "8.1.13 PASS when an additional email is configured" {
        New-ContactMock ([PSCustomObject]@{ emails = "secops@contoso.com" })
        $r = @(Invoke-Section8Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData (New-S8PD2))
        ($r | Where-Object { $_.ControlId -eq "8.1.13" }).Status | Should -Be "PASS"
    }

    It "8.1.14 PASS when notificationsSources has Alert with minimalSeverity" {
        New-ContactMock ([PSCustomObject]@{ notificationsSources = @([PSCustomObject]@{ sourceType = "Alert"; minimalSeverity = "High" }) })
        $r = @(Invoke-Section8Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData (New-S8PD2))
        ($r | Where-Object { $_.ControlId -eq "8.1.14" }).Status | Should -Be "PASS"
    }

    It "8.1.14 FAIL when only role notifications are On (no Alert source)" {
        New-ContactMock ([PSCustomObject]@{ notificationsByRole = [PSCustomObject]@{ state = "On"; roles = @("Owner") } })
        $r = @(Invoke-Section8Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData (New-S8PD2))
        ($r | Where-Object { $_.ControlId -eq "8.1.14" }).Status | Should -Be "FAIL"
    }

    It "8.1.15 PASS when AttackPath source has minimalRiskLevel" {
        New-ContactMock ([PSCustomObject]@{ notificationsSources = @([PSCustomObject]@{ sourceType = "AttackPath"; minimalRiskLevel = "High" }) })
        $r = @(Invoke-Section8Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData (New-S8PD2))
        ($r | Where-Object { $_.ControlId -eq "8.1.15" }).Status | Should -Be "PASS"
    }

    It "8.1.15 FAIL when AttackPath source has no minimalRiskLevel" {
        New-ContactMock ([PSCustomObject]@{ notificationsSources = @([PSCustomObject]@{ sourceType = "AttackPath" }) })
        $r = @(Invoke-Section8Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData (New-S8PD2))
        ($r | Where-Object { $_.ControlId -eq "8.1.15" }).Status | Should -Be "FAIL"
    }

    It "8.1.12 FAIL when Owner configured but role notifications are Off" {
        New-ContactMock ([PSCustomObject]@{ notificationsByRole = [PSCustomObject]@{ state = "Off"; roles = @("Owner") } })
        $r = @(Invoke-Section8Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData (New-S8PD2))
        ($r | Where-Object { $_.ControlId -eq "8.1.12" }).Status | Should -Be "FAIL"
    }

    It "8.1.12-8.1.15 ERROR when the securityContacts read fails" {
        Mock Get-AzSecurityPricing { [PSCustomObject]@{ PricingTier = "Standard" } }
        Mock Invoke-ArmRest {
            param($Uri)
            if ($Uri -match "WDATP") { return [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ properties = [PSCustomObject]@{ enabled = "true" } } } }
            if ($Uri -match "securityContacts") { return [PSCustomObject]@{ Success = $false; Data = $null; Error = "403 forbidden" } }
            return [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @() } }
        }
        $r = @(Invoke-Section8Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData (New-S8PD2))
        foreach ($cid in @("8.1.12","8.1.13","8.1.14","8.1.15")) {
            ($r | Where-Object { $_.ControlId -eq $cid }).Status | Should -Be "ERROR" -Because "control $cid"
        }
    }
}
