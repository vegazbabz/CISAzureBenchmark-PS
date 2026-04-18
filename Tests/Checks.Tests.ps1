#Requires -Version 7.0
<#
.SYNOPSIS
    Pester unit tests for CIS Azure Benchmark PS check functions.
    Covers Sections 2, 5, 6, 7, 8, and 9 by mocking az CLI and Graph API calls.

.NOTES
    Run with:
        Invoke-Pester .\Tests\Checks.Tests.ps1 -Output Detailed
    Or via the repo helper:
        .\Tests\Run-Tests.ps1
#>

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '', Justification = 'Test scaffolding')]
param()

BeforeAll {
    # Dot-source all module files so check functions are available in test scope
    $moduleRoot = Split-Path $PSScriptRoot -Parent
    foreach ($f in @(
        "Private\Config.ps1",
        "Private\Models.ps1",
        "Private\AzureClient.ps1",
        "Private\Helpers.ps1",
        "Private\CheckHelpers.ps1",
        "Private\Identity.ps1",
        "Private\Checkpoint.ps1",
        "Private\History.ps1",
        "Private\Report.ps1",
        "Checks\Section2.ps1",
        "Checks\Section3.ps1",
        "Checks\Section5.ps1",
        "Checks\Section6.ps1",
        "Checks\Section7.ps1",
        "Checks\Section8.ps1",
        "Checks\Section9.ps1"
    )) {
        . (Join-Path $moduleRoot $f)
    }

    # Silence logger during tests
    $script:DEBUG_MODE   = $false
    $script:VERBOSE_MODE = $false
    $script:LOG_FILE     = $null

    # Test subscription constants
    $script:T_SID   = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    $script:T_SNAME = "Test Subscription"

    # Helper: build a minimal prefetch hashtable for Get-PrefetchData lookups
    function New-PD {
        param([string]$Key, [object[]]$Records)
        @{ $Key = @{ $script:T_SID.ToLower() = $Records } }
    }

    # Helper: combine multiple prefetch keys into one hashtable
    function Merge-PD {
        param([hashtable[]]$Tables)
        $out = @{}
        foreach ($t in $Tables) { foreach ($k in $t.Keys) { $out[$k] = $t[$k] } }
        $out
    }

    # Helper: build an NSG rule object (Resource Graph flat shape)
    function New-Rule {
        param(
            [string]$Name      = "rule1",
            [string]$Access    = "Allow",
            [string]$Direction = "Inbound",
            [string]$Protocol  = "TCP",
            [string]$Src       = "*",
            [string]$DestPort  = "22"
        )
        [PSCustomObject]@{
            name                    = $Name
            access                  = $Access
            direction               = $Direction
            protocol                = $Protocol
            sourceAddressPrefix     = $Src
            destinationPortRange    = $DestPort
            destinationPortRanges   = @()
        }
    }
}

# =============================================================================
# HELPERS — Test-PortInRange, Get-NsgBadRules, Get-NsgUdpBadRules
# =============================================================================

Describe "Test-PortInRange" {
    It "matches wildcard" {
        Test-PortInRange -PortSpec "*" -Port 22 | Should -BeTrue
    }
    It "matches exact port" {
        Test-PortInRange -PortSpec "22" -Port 22 | Should -BeTrue
    }
    It "does not match different port" {
        Test-PortInRange -PortSpec "22" -Port 3389 | Should -BeFalse
    }
    It "matches port within range" {
        Test-PortInRange -PortSpec "1024-65535" -Port 8080 | Should -BeTrue
    }
    It "does not match port below range" {
        Test-PortInRange -PortSpec "1024-65535" -Port 80 | Should -BeFalse
    }
}

Describe "Get-NsgBadRules" {
    It "returns empty for empty rules array" {
        $result = Get-NsgBadRules -Rules @() -Ports @(22)
        $result | Should -HaveCount 0
    }

    It "flags Allow Inbound TCP * rule for port 22" {
        $rule = New-Rule -Name "bad-ssh" -Access "Allow" -Direction "Inbound" -Protocol "TCP" -Src "*" -DestPort "22"
        $result = Get-NsgBadRules -Rules @($rule) -Ports @(22)
        $result | Should -Contain "bad-ssh"
    }

    It "ignores Deny rules" {
        $rule = New-Rule -Name "deny-ssh" -Access "Deny" -Direction "Inbound" -Protocol "TCP" -Src "*" -DestPort "22"
        $result = Get-NsgBadRules -Rules @($rule) -Ports @(22)
        $result | Should -HaveCount 0
    }

    It "ignores Outbound rules" {
        $rule = New-Rule -Name "out-ssh" -Access "Allow" -Direction "Outbound" -Protocol "TCP" -Src "*" -DestPort "22"
        $result = Get-NsgBadRules -Rules @($rule) -Ports @(22)
        $result | Should -HaveCount 0
    }

    It "ignores private source address" {
        $rule = New-Rule -Name "priv-ssh" -Access "Allow" -Direction "Inbound" -Protocol "TCP" -Src "10.0.0.0/8" -DestPort "22"
        $result = Get-NsgBadRules -Rules @($rule) -Ports @(22)
        $result | Should -HaveCount 0
    }

    It "flags wildcard protocol rule" {
        $rule = New-Rule -Name "any-rdp" -Access "Allow" -Direction "Inbound" -Protocol "*" -Src "Internet" -DestPort "3389"
        $result = Get-NsgBadRules -Rules @($rule) -Ports @(3389)
        $result | Should -Contain "any-rdp"
    }

    It "does not flag when port does not match" {
        $rule = New-Rule -Name "allow-80" -Access "Allow" -Direction "Inbound" -Protocol "TCP" -Src "*" -DestPort "80"
        $result = Get-NsgBadRules -Rules @($rule) -Ports @(22)
        $result | Should -HaveCount 0
    }

    It "flags rule when internet source is in sourceAddressPrefixes array (regression)" {
        # Internet source expressed as an array (sourceAddressPrefixes) must still be flagged
        $rule = [PSCustomObject]@{
            name = "array-ssh"; access = "Allow"; direction = "Inbound"
            protocol = "TCP"; sourceAddressPrefix = ""; destinationPortRange = "22"
            sourceAddressPrefixes = @("10.0.0.0/8", "*")
            destinationPortRanges = @()
        }
        $result = Get-NsgBadRules -Rules @($rule) -Ports @(22)
        $result | Should -Contain "array-ssh"
    }

    It "does not flag rule when all sourceAddressPrefixes entries are private" {
        $rule = [PSCustomObject]@{
            name = "priv-array-ssh"; access = "Allow"; direction = "Inbound"
            protocol = "TCP"; sourceAddressPrefix = ""; destinationPortRange = "22"
            sourceAddressPrefixes = @("10.0.0.0/8", "192.168.0.0/16")
            destinationPortRanges = @()
        }
        $result = Get-NsgBadRules -Rules @($rule) -Ports @(22)
        $result | Should -HaveCount 0
    }
}

Describe "Get-NsgUdpBadRules" {
    It "flags UDP Allow Inbound from internet" {
        $rule = [PSCustomObject]@{
            name = "bad-udp"; access = "Allow"; direction = "Inbound"
            protocol = "UDP"; sourceAddressPrefix = "*"
            destinationPortRange = "*"; destinationPortRanges = @()
        }
        $result = Get-NsgUdpBadRules -Rules @($rule)
        $result | Should -Contain "bad-udp"
    }

    It "does not flag TCP rules" {
        $rule = New-Rule -Name "tcp-rule" -Protocol "TCP" -Src "*" -DestPort "*"
        $result = Get-NsgUdpBadRules -Rules @($rule)
        $result | Should -HaveCount 0
    }

    It "flags wildcard protocol from internet" {
        $rule = [PSCustomObject]@{
            name = "any-proto"; access = "Allow"; direction = "Inbound"
            protocol = "*"; sourceAddressPrefix = "0.0.0.0/0"
            destinationPortRange = "1900"; destinationPortRanges = @()
        }
        $result = Get-NsgUdpBadRules -Rules @($rule)
        $result | Should -Contain "any-proto"
    }

    It "flags UDP rule when internet source is in sourceAddressPrefixes array (regression)" {
        $rule = [PSCustomObject]@{
            name = "array-udp"; access = "Allow"; direction = "Inbound"
            protocol = "UDP"; sourceAddressPrefix = ""
            sourceAddressPrefixes = @("10.0.0.0/8", "Internet")
            destinationPortRange = "*"; destinationPortRanges = @()
        }
        $result = Get-NsgUdpBadRules -Rules @($rule)
        $result | Should -Contain "array-udp"
    }
}

Describe "Get-ControlSortKey" {
    It "pads single-segment control IDs" {
        Get-ControlSortKey "7" | Should -Be "007"
    }
    It "pads two-segment IDs" {
        Get-ControlSortKey "9.3" | Should -Be "009.003"
    }
    It "pads three-segment IDs" {
        Get-ControlSortKey "9.3.10" | Should -Be "009.003.010"
    }
    It "sorts correctly: 9.3.2 before 9.3.10" {
        $sorted = @("9.3.10", "9.3.2") | Sort-Object { Get-ControlSortKey $_ }
        $sorted[0] | Should -Be "9.3.2"
    }
}

# =============================================================================
# NEW-CISRESULT / MODELS
# =============================================================================

Describe "New-CISResult" {
    It "creates a result with required fields" {
        $r = New-CISResult -ControlId "1.1" -Title "Test" -Level 1 -Section "1-Test" -Status "PASS"
        $r.ControlId | Should -Be "1.1"
        $r.Status    | Should -Be "PASS"
        $r.Level     | Should -Be 1
    }

    It "defaults optional fields to empty string" {
        $r = New-CISResult -ControlId "1.1" -Title "T" -Level 1 -Section "S" -Status "PASS"
        $r.Details          | Should -Be ""
        $r.Remediation      | Should -Be ""
        $r.SubscriptionId   | Should -Be ""
        $r.SubscriptionName | Should -Be ""
        $r.Resource         | Should -Be ""
    }
}

Describe "New-ErrorResult" {
    It "creates an ERROR status result" {
        $r = New-ErrorResult "1.1" "Title" 1 "Section" "Some error message"
        $r.Status | Should -Be "ERROR"
    }

    It "truncates long messages to ~220 chars" {
        $long = "A" * 300
        $r = New-ErrorResult "1.1" "T" 1 "S" $long
        $r.Details.Length | Should -BeLessOrEqual 225
    }
}

Describe "New-InfoResult" {
    It "creates an INFO status result" {
        $r = New-InfoResult "7.1" "Title" 1 "Section" "No NSGs found."
        $r.Status  | Should -Be "INFO"
        $r.Details | Should -Be "No NSGs found."
    }
}

# =============================================================================
# SECTION 2 — DATABRICKS
# =============================================================================

Describe "Invoke-Section2Checks — no workspaces" {
    It "returns INFO for all five controls when no Databricks workspaces found" {
        $pd = New-PD -Key "databricks" -Records @()
        # Need subnets key too to avoid null dereference
        $pd["subnets"] = @{}
        $results = @(Invoke-Section2Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        $results | Should -HaveCount 5
        $results | ForEach-Object { $_.Status | Should -Be "INFO" }
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

        Mock Invoke-AzCli { [PSCustomObject]@{ Success = $true; Data = @([PSCustomObject]@{ name = "diag1" }) } }

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

        Mock Invoke-AzCli { [PSCustomObject]@{ Success = $true; Data = @() } }

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
        Mock Invoke-AzCli { [PSCustomObject]@{ Success = $true; Data = @() } }
        $results = @(Invoke-Section2Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "2.1.9" }).Status | Should -Be "PASS"
    }

    It "returns FAIL when noPublicIp is false" {
        $ws = [PSCustomObject]@{
            id = "/sub/x/ws/ws1"; name = "ws1"; resourceGroup = "rg"
            vnetId = ""; noPublicIp = "false"; publicAccess = "Enabled"; privateEps = 0
        }
        $pd = Merge-PD @((New-PD "databricks" @($ws)), (New-PD "subnets" @()))
        Mock Invoke-AzCli { [PSCustomObject]@{ Success = $true; Data = @() } }
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
        Mock Invoke-AzCli { [PSCustomObject]@{ Success = $true; Data = @() } }
        $results = @(Invoke-Section2Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "2.1.10" }).Status | Should -Be "PASS"
    }

    It "returns FAIL when publicAccess is Enabled" {
        $ws = [PSCustomObject]@{
            id = "/x"; name = "ws1"; resourceGroup = "rg"
            vnetId = ""; noPublicIp = "true"; publicAccess = "Enabled"; privateEps = 0
        }
        $pd = Merge-PD @((New-PD "databricks" @($ws)), (New-PD "subnets" @()))
        Mock Invoke-AzCli { [PSCustomObject]@{ Success = $true; Data = @() } }
        $results = @(Invoke-Section2Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "2.1.10" }).Status | Should -Be "FAIL"
    }
}

# =============================================================================
# SECTION 3 — COMPUTE SERVICES
# =============================================================================

Describe "Invoke-Check3_1_1 — MFA for Privileged VM Access (Manual)" {
    It "returns MANUAL status" {
        $r = Invoke-Check3_1_1
        $r.Status | Should -Be "MANUAL"
    }

    It "returns control id 3.1.1" {
        $r = Invoke-Check3_1_1
        $r.ControlId | Should -Be "3.1.1"
    }
}

Describe "Invoke-Section3TenantChecks" {
    It "returns exactly one result" {
        $results = @(Invoke-Section3TenantChecks)
        $results | Should -HaveCount 1
    }

    It "result has MANUAL status" {
        $results = @(Invoke-Section3TenantChecks)
        $results[0].Status | Should -Be "MANUAL"
    }
}

# =============================================================================
# SECTION 5 — IDENTITY SERVICES
# =============================================================================

Describe "Invoke-Check5_1_1 — Security Defaults" {
    It "returns PASS when security defaults enabled" {
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ isEnabled = $true } } }
        $r = Invoke-Check5_1_1
        $r.Status | Should -Be "PASS"
    }

    It "returns FAIL when security defaults off and no CA policies" {
        Mock Invoke-ArmRest {
            param($Uri)
            if ($Uri -match "identitySecurityDefaults") {
                return [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ isEnabled = $false } }
            }
            return [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @() } }
        }
        $r = Invoke-Check5_1_1
        $r.Status | Should -Be "FAIL"
    }

    It "returns PASS when security defaults off but CA policies exist" {
        Mock Invoke-ArmRest {
            param($Uri)
            if ($Uri -match "identitySecurityDefaults") {
                return [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ isEnabled = $false } }
            }
            # CA policy response
            return [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @([PSCustomObject]@{ id = "ca1" }) } }
        }
        $r = Invoke-Check5_1_1
        $r.Status | Should -Be "PASS"
    }

    It "returns ERROR on API failure" {
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $false; Error = "403 Forbidden"; Data = $null } }
        $r = Invoke-Check5_1_1
        $r.Status | Should -Be "ERROR"
    }
}

Describe "Invoke-Check5_1_2 — MFA All Users" {
    It "returns PASS when all users have MFA" {
        $users = @(
            [PSCustomObject]@{ userPrincipalName = "alice@test.com"; isMfaRegistered = $true; isAdmin = $true }
            [PSCustomObject]@{ userPrincipalName = "bob@test.com";   isMfaRegistered = $true; isAdmin = $true }
        )
        Mock Invoke-AzRestPaged { [PSCustomObject]@{ Success = $true; Data = $users } }
        $r = Invoke-Check5_1_2
        $r.Status | Should -Be "PASS"
    }

    It "returns FAIL when an admin user lacks MFA" {
        $users = @(
            [PSCustomObject]@{ userPrincipalName = "alice@test.com"; isMfaRegistered = $true;  isAdmin = $true }
            [PSCustomObject]@{ userPrincipalName = "bob@test.com";   isMfaRegistered = $false; isAdmin = $true }
        )
        Mock Invoke-AzRestPaged { [PSCustomObject]@{ Success = $true; Data = $users } }
        $r = Invoke-Check5_1_2
        $r.Status | Should -Be "FAIL"
        $r.Details | Should -Match "1 admin user"
    }

    It "returns ERROR on API failure" {
        Mock Invoke-AzRestPaged { [PSCustomObject]@{ Success = $false; Error = "Forbidden"; Data = $null } }
        $r = Invoke-Check5_1_2
        $r.Status | Should -Be "ERROR"
    }

    It "returns PASS for empty tenant" {
        Mock Invoke-AzRestPaged { [PSCustomObject]@{ Success = $true; Data = @() } }
        $r = Invoke-Check5_1_2
        $r.Status | Should -Be "PASS"
    }

    It "returns PASS when only non-admin user lacks MFA (admin-scope regression)" {
        # A non-admin user without MFA must NOT cause a FAIL — the control only covers admins.
        $users = @(
            [PSCustomObject]@{ userPrincipalName = "admin@test.com";    isMfaRegistered = $true;  isAdmin = $true }
            [PSCustomObject]@{ userPrincipalName = "external@corp.com"; isMfaRegistered = $false; isAdmin = $false }
        )
        Mock Invoke-AzRestPaged { [PSCustomObject]@{ Success = $true; Data = $users } }
        $r = Invoke-Check5_1_2
        $r.Status | Should -Be "PASS"
    }

    It "returns FAIL when admin has no MFA even if non-admin also has no MFA" {
        $users = @(
            [PSCustomObject]@{ userPrincipalName = "admin@test.com";    isMfaRegistered = $false; isAdmin = $true }
            [PSCustomObject]@{ userPrincipalName = "external@corp.com"; isMfaRegistered = $false; isAdmin = $false }
        )
        Mock Invoke-AzRestPaged { [PSCustomObject]@{ Success = $true; Data = $users } }
        $r = Invoke-Check5_1_2
        $r.Status   | Should -Be "FAIL"
        $r.Details  | Should -Match "1 admin user"
        $r.Details  | Should -Match "admin@test.com"
    }
}

Describe "Invoke-Check5_1_3 — Remember MFA on Trusted Devices" {
    It "returns MANUAL status" {
        $r = Invoke-Check5_1_3
        $r.Status    | Should -Be "MANUAL"
        $r.ControlId | Should -Be "5.1.3"
    }
}

Describe "Invoke-Check5_28 — Phishing-Resistant MFA for Privileged Users" {
    It "returns MANUAL status" {
        $r = Invoke-Check5_28
        $r.Status    | Should -Be "MANUAL"
        $r.ControlId | Should -Be "5.28"
    }
}

Describe "Invoke-Check5_4 — Restrict Non-Admin Tenant Creation" {
    It "returns PASS when allowedToCreateTenants is false" {
        $policy = [PSCustomObject]@{
            defaultUserRolePermissions = [PSCustomObject]@{ allowedToCreateTenants = $false }
        }
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $true; Data = $policy } }
        $r = Invoke-Check5_4
        $r.Status | Should -Be "PASS"
    }

    It "returns FAIL when allowedToCreateTenants is true" {
        $policy = [PSCustomObject]@{
            defaultUserRolePermissions = [PSCustomObject]@{ allowedToCreateTenants = $true }
        }
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $true; Data = $policy } }
        $r = Invoke-Check5_4
        $r.Status | Should -Be "FAIL"
    }

    It "returns ERROR on API failure" {
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $false; Error = "Access denied"; Data = $null } }
        $r = Invoke-Check5_4
        $r.Status | Should -Be "ERROR"
    }
}

Describe "Invoke-Check5_14 — Users Cannot Register Apps" {
    It "returns PASS when allowedToCreateApps is false" {
        $policy = [PSCustomObject]@{
            defaultUserRolePermissions = [PSCustomObject]@{ allowedToCreateApps = $false }
        }
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $true; Data = $policy } }
        $r = Invoke-Check5_14
        $r.Status | Should -Be "PASS"
    }

    It "returns FAIL when allowedToCreateApps is true" {
        $policy = [PSCustomObject]@{
            defaultUserRolePermissions = [PSCustomObject]@{ allowedToCreateApps = $true }
        }
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $true; Data = $policy } }
        $r = Invoke-Check5_14
        $r.Status | Should -Be "FAIL"
    }
}

Describe "Invoke-Check5_15 — Guest User Access Restrictions" {
    It "returns PASS when guestUserRoleId is the most restrictive GUID" {
        $policy = [PSCustomObject]@{ guestUserRoleId = "10dae51f-b6af-4016-8d66-8c2a99b929b3" }
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $true; Data = $policy } }
        $r = Invoke-Check5_15
        $r.Status | Should -Be "PASS"
    }

    It "returns FAIL for member-level guest access GUID" {
        $policy = [PSCustomObject]@{ guestUserRoleId = "a0b1b346-4d3e-4e8b-98f8-753987be4970" }
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $true; Data = $policy } }
        $r = Invoke-Check5_15
        $r.Status | Should -Be "FAIL"
    }
}

Describe "Invoke-Check5_16 — Guest Invite Restrictions" {
    It "returns PASS for adminsAndGuestInviters" {
        $policy = [PSCustomObject]@{ allowInvitesFrom = "adminsAndGuestInviters" }
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $true; Data = $policy } }
        (Invoke-Check5_16).Status | Should -Be "PASS"
    }

    It "returns PASS for admins" {
        $policy = [PSCustomObject]@{ allowInvitesFrom = "admins" }
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $true; Data = $policy } }
        (Invoke-Check5_16).Status | Should -Be "PASS"
    }

    It "returns PASS for none" {
        $policy = [PSCustomObject]@{ allowInvitesFrom = "none" }
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $true; Data = $policy } }
        (Invoke-Check5_16).Status | Should -Be "PASS"
    }

    It "returns FAIL for everyone" {
        $policy = [PSCustomObject]@{ allowInvitesFrom = "everyone" }
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $true; Data = $policy } }
        (Invoke-Check5_16).Status | Should -Be "FAIL"
    }

    It "returns FAIL for adminsAndAllMembers" {
        $policy = [PSCustomObject]@{ allowInvitesFrom = "adminsAndAllMembers" }
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $true; Data = $policy } }
        (Invoke-Check5_16).Status | Should -Be "FAIL"
    }
}

Describe "Invoke-Check5_3_3 — No UAA at Subscription Scope" {
    It "returns PASS when no UAA assignments at subscription scope" {
        $pd = New-PD "roles" @()
        $r = Invoke-Check5_3_3 -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd
        $r.Status | Should -Be "PASS"
    }

    It "returns FAIL when UAA assigned at subscription scope" {
        $uaaRole = [PSCustomObject]@{
            roleDefinitionId = "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9"
            scope            = "/subscriptions/$T_SID"
            principalName    = "bad-user"
            principalId      = "pid-123"
        }
        $pd = New-PD "roles" @($uaaRole)
        $r = Invoke-Check5_3_3 -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd
        $r.Status | Should -Be "FAIL"
        $r.Details | Should -Match "bad-user"
    }

    It "does not flag UAA at resource-group scope" {
        $uaaRole = [PSCustomObject]@{
            roleDefinitionId = "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9"
            scope            = "/subscriptions/$T_SID/resourceGroups/my-rg"
            principalName    = "ok-user"
            principalId      = "pid-456"
        }
        $pd = New-PD "roles" @($uaaRole)
        $r = Invoke-Check5_3_3 -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd
        $r.Status | Should -Be "PASS"
    }
}

Describe "Invoke-Check5_27 — 2-3 Subscription Owners" {
    BeforeAll {
        function New-Owner {
            param([string]$Name, [string]$PType = "User")
            [PSCustomObject]@{
                roleDefinitionId = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
                scope            = "/subscriptions/$script:T_SID"
                principalName    = $Name
                principalId      = "pid-$Name"
                principalType    = $PType
            }
        }
    }

    It "returns FAIL for zero owners" {
        $pd = New-PD "roles" @()
        (Invoke-Check5_27 -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd).Status | Should -Be "FAIL"
    }

    It "returns FAIL for one owner" {
        $pd = New-PD "roles" @(New-Owner "alice")
        (Invoke-Check5_27 -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd).Status | Should -Be "FAIL"
    }

    It "returns PASS for two owners" {
        $pd = New-PD "roles" @(New-Owner "alice"; New-Owner "bob")
        (Invoke-Check5_27 -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd).Status | Should -Be "PASS"
    }

    It "returns PASS for three owners" {
        $pd = New-PD "roles" @(New-Owner "alice"; New-Owner "bob"; New-Owner "carol")
        (Invoke-Check5_27 -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd).Status | Should -Be "PASS"
    }

    It "returns FAIL for four owners" {
        $pd = New-PD "roles" @(New-Owner "a"; New-Owner "b"; New-Owner "c"; New-Owner "d")
        (Invoke-Check5_27 -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd).Status | Should -Be "FAIL"
    }

    It "does not count management-group scoped owner" {
        $mgOwner = [PSCustomObject]@{
            roleDefinitionId = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
            scope            = "/providers/Microsoft.Management/managementGroups/root"
            principalName    = "mg-admin"
            principalId      = "pid-mg"
            principalType    = "User"
        }
        $pd = New-PD "roles" @($mgOwner)
        (Invoke-Check5_27 -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd).Status | Should -Be "FAIL"
    }
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
        Mock Invoke-AzCli { [PSCustomObject]@{ Success = $true; Data = @() } }

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
        Mock Invoke-AzCli { [PSCustomObject]@{ Success = $true; Data = @() } }

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
        Mock Invoke-AzCli { [PSCustomObject]@{ Success = $true; Data = @() } }

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
        Mock Invoke-AzCli { [PSCustomObject]@{ Success = $true; Data = @() } }

        $results = @(Invoke-Section7Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "7.2" }).Status | Should -Be "FAIL"
    }
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
        Mock Invoke-AzCli  { [PSCustomObject]@{ Success = $true; Data = @() } }
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
        Mock Invoke-AzCli  { [PSCustomObject]@{ Success = $true; Data = @() } }
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
        Mock Invoke-AzCli  { [PSCustomObject]@{ Success = $true; Data = @() } }
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
        Mock Invoke-AzCli  { [PSCustomObject]@{ Success = $true; Data = @() } }
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
        Mock Invoke-AzCli  { [PSCustomObject]@{ Success = $true; Data = @() } }
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @() } } }

        $results = @(Invoke-Section8Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "8.3.5" }).Status | Should -Be "FAIL"
    }
}

# =============================================================================
# SECTION 9 — STORAGE
# =============================================================================

Describe "Invoke-Section9Checks — no storage accounts" {
    It "returns INFO for all storage controls" {
        $pd = New-PD "storage" @()
        Mock Invoke-AzCli { [PSCustomObject]@{ Success = $true; Data = @() } }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        $results.Count | Should -BeGreaterThan 5
        $results | ForEach-Object { $_.Status | Should -Be "INFO" }
    }
}

Describe "Invoke-Section9Checks — 9.3.4 Secure Transfer" {
    It "returns PASS when httpsOnly is true" {
        $acct = [PSCustomObject]@{
            id = "/sub/x/sa/sa1"; name = "sa1"; resourceGroup = "rg"; kind = "StorageV2"
            httpsOnly = "true"; publicAccess = "Disabled"; crossTenant = "false"
            blobAnon = "false"; defaultAction = "Deny"; bypass = "AzureServices"
            minTls = "TLS1_2"; keyAccess = "false"; oauthDefault = "true"
            sku = "Standard_GRS"; privateEps = 1
        }
        $pd = New-PD "storage" @($acct)

        $blobSvc = [PSCustomObject]@{
            deleteRetentionPolicy          = [PSCustomObject]@{ enabled = $true; days = 7 }
            containerDeleteRetentionPolicy = [PSCustomObject]@{ enabled = $true; days = 7 }
            isVersioningEnabled            = $true
        }
        $fileSvc = [PSCustomObject]@{
            shareDeleteRetentionPolicy = [PSCustomObject]@{ enabled = $true; days = 7 }
            protocolSettings = [PSCustomObject]@{
                smb = [PSCustomObject]@{
                    versions           = "SMB3.0;SMB3.1.1"
                    channelEncryption  = "AES-128-GCM;AES-256-GCM"
                }
            }
        }

        Mock Invoke-AzCli {
            param($Arguments)
            if ($Arguments -contains "blob-service-properties") { return [PSCustomObject]@{ Success = $true; Data = $blobSvc } }
            if ($Arguments -contains "file-service-properties") { return [PSCustomObject]@{ Success = $true; Data = $fileSvc } }
            return [PSCustomObject]@{ Success = $true; Data = @() }
        }

        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.3.4" }).Status | Should -Be "PASS"
    }

    It "returns FAIL when httpsOnly is false" {
        $acct = [PSCustomObject]@{
            id = "/sub/x/sa/sa2"; name = "sa2"; resourceGroup = "rg"; kind = "StorageV2"
            httpsOnly = "false"; publicAccess = "Enabled"; crossTenant = "true"
            blobAnon = "true"; defaultAction = "Allow"; bypass = "None"
            minTls = "TLS1_0"; keyAccess = "true"; oauthDefault = "false"
            sku = "Standard_LRS"; privateEps = 0
        }
        $pd = New-PD "storage" @($acct)
        Mock Invoke-AzCli { [PSCustomObject]@{ Success = $true; Data = @() } }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.3.4" }).Status | Should -Be "FAIL"
    }
}

Describe "Invoke-Section9Checks — 9.3.6 Minimum TLS 1.2" {
    It "returns PASS when minTls is TLS1_2" {
        $acct = [PSCustomObject]@{
            id = "/sub/x/sa/sa3"; name = "sa3"; resourceGroup = "rg"; kind = "StorageV2"
            httpsOnly = "true"; publicAccess = "Enabled"; crossTenant = "false"
            blobAnon = "false"; defaultAction = "Allow"; bypass = "AzureServices"
            minTls = "TLS1_2"; keyAccess = "false"; oauthDefault = "true"
            sku = "Standard_LRS"; privateEps = 0
        }
        $pd = New-PD "storage" @($acct)
        Mock Invoke-AzCli { [PSCustomObject]@{ Success = $true; Data = @() } }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.3.6" }).Status | Should -Be "PASS"
    }

    It "returns FAIL when minTls is TLS1_0" {
        $acct = [PSCustomObject]@{
            id = "/sub/x/sa/sa4"; name = "sa4"; resourceGroup = "rg"; kind = "StorageV2"
            httpsOnly = "true"; publicAccess = "Enabled"; crossTenant = "false"
            blobAnon = "false"; defaultAction = "Allow"; bypass = "AzureServices"
            minTls = "TLS1_0"; keyAccess = "false"; oauthDefault = "true"
            sku = "Standard_LRS"; privateEps = 0
        }
        $pd = New-PD "storage" @($acct)
        Mock Invoke-AzCli { [PSCustomObject]@{ Success = $true; Data = @() } }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.3.6" }).Status | Should -Be "FAIL"
    }
}

Describe "Invoke-Section9Checks — 9.3.8 Blob Public Access" {
    It "returns PASS when blobAnon is false" {
        $acct = [PSCustomObject]@{
            id = "/sub/x/sa/sa5"; name = "sa5"; resourceGroup = "rg"; kind = "StorageV2"
            httpsOnly = "true"; publicAccess = "Enabled"; crossTenant = "false"
            blobAnon = "false"; defaultAction = "Allow"; bypass = "AzureServices"
            minTls = "TLS1_2"; keyAccess = "false"; oauthDefault = "true"
            sku = "Standard_LRS"; privateEps = 0
        }
        $pd = New-PD "storage" @($acct)
        Mock Invoke-AzCli { [PSCustomObject]@{ Success = $true; Data = @() } }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.3.8" }).Status | Should -Be "PASS"
    }

    It "returns FAIL when blobAnon is true" {
        $acct = [PSCustomObject]@{
            id = "/sub/x/sa/sa6"; name = "sa6"; resourceGroup = "rg"; kind = "StorageV2"
            httpsOnly = "true"; publicAccess = "Enabled"; crossTenant = "false"
            blobAnon = "true"; defaultAction = "Allow"; bypass = "AzureServices"
            minTls = "TLS1_2"; keyAccess = "false"; oauthDefault = "true"
            sku = "Standard_LRS"; privateEps = 0
        }
        $pd = New-PD "storage" @($acct)
        Mock Invoke-AzCli { [PSCustomObject]@{ Success = $true; Data = @() } }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.3.8" }).Status | Should -Be "FAIL"
    }
}

Describe "Invoke-Section9Checks — 9.3.7 Cross-Tenant Replication" {
    It "returns PASS when crossTenant is false" {
        $acct = [PSCustomObject]@{
            id = "/x"; name = "sa7"; resourceGroup = "rg"; kind = "StorageV2"
            httpsOnly = "true"; publicAccess = "Enabled"; crossTenant = "false"
            blobAnon = "false"; defaultAction = "Allow"; bypass = "AzureServices"
            minTls = "TLS1_2"; keyAccess = "false"; oauthDefault = "true"
            sku = "Standard_LRS"; privateEps = 0
        }
        $pd = New-PD "storage" @($acct)
        Mock Invoke-AzCli { [PSCustomObject]@{ Success = $true; Data = @() } }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.3.7" }).Status | Should -Be "PASS"
    }

    It "returns FAIL when crossTenant is true" {
        $acct = [PSCustomObject]@{
            id = "/x"; name = "sa8"; resourceGroup = "rg"; kind = "StorageV2"
            httpsOnly = "true"; publicAccess = "Enabled"; crossTenant = "true"
            blobAnon = "false"; defaultAction = "Allow"; bypass = "AzureServices"
            minTls = "TLS1_2"; keyAccess = "false"; oauthDefault = "true"
            sku = "Standard_LRS"; privateEps = 0
        }
        $pd = New-PD "storage" @($acct)
        Mock Invoke-AzCli { [PSCustomObject]@{ Success = $true; Data = @() } }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.3.7" }).Status | Should -Be "FAIL"
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
        Mock Invoke-AzCli { [PSCustomObject]@{ Success = $true; Data = @() } }
        $results = @(Invoke-Section2Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "2.1.11" }).Status | Should -Be "PASS"
    }

    It "returns FAIL when no private endpoints" {
        $ws = [PSCustomObject]@{
            id = "/sub/x/ws/ws1"; name = "ws1"; resourceGroup = "rg"
            vnetId = ""; noPublicIp = "true"; publicAccess = "Disabled"; privateEps = 0
        }
        $pd = Merge-PD @((New-PD "databricks" @($ws)), (New-PD "subnets" @()))
        Mock Invoke-AzCli { [PSCustomObject]@{ Success = $true; Data = @() } }
        $results = @(Invoke-Section2Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "2.1.11" }).Status | Should -Be "FAIL"
    }
}

# =============================================================================
# SECTION 5 — IDENTITY (additional coverage)
# =============================================================================

Describe "Invoke-Check5_23 — No Custom Owner Roles" {
    It "returns PASS when no custom wildcard roles" {
        Mock Get-AzRoleDefinition { @() }
        $r = Invoke-Check5_23 -SubscriptionId $T_SID -SubscriptionName $T_SNAME
        $r.Status | Should -Be "PASS"
    }

    It "returns FAIL when custom wildcard role found" {
        Mock Get-AzRoleDefinition {
            [PSCustomObject]@{ Name = "SuperOwner"; Id = "xyz"; Actions = @("*") }
        }
        $r = Invoke-Check5_23 -SubscriptionId $T_SID -SubscriptionName $T_SNAME
        $r.Status | Should -Be "FAIL"
        $r.Details | Should -Match "SuperOwner"
    }

    It "returns ERROR on API failure" {
        Mock Get-AzRoleDefinition { throw "Role definition API failed" }
        $r = Invoke-Check5_23 -SubscriptionId $T_SID -SubscriptionName $T_SNAME
        $r.Status | Should -Be "ERROR"
    }
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

Describe "Invoke-Section6Checks — 6.1.1.3 Activity Log Retention" {
    BeforeAll {
        function New-S6PD { Merge-PD @((New-PD "keyvaults" @()), (New-PD "app_services" @())) }
    }

    It "returns PASS when retention >= 365" {
        Mock Get-AzLogProfile {
            [PSCustomObject]@{ RetentionPolicy = [PSCustomObject]@{ Enabled = $true; Days = 365 } }
        }
        Mock Invoke-AzRestPaged { [PSCustomObject]@{ Success = $true; Data = @() } }

        $results = @(Invoke-Section6Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData (New-S6PD))
        ($results | Where-Object { $_.ControlId -eq "6.1.1.3" }).Status | Should -Be "PASS"
    }

    It "returns FAIL when retention < 365" {
        Mock Get-AzLogProfile {
            [PSCustomObject]@{ RetentionPolicy = [PSCustomObject]@{ Enabled = $true; Days = 30 } }
        }
        Mock Invoke-AzRestPaged { [PSCustomObject]@{ Success = $true; Data = @() } }

        $results = @(Invoke-Section6Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData (New-S6PD))
        ($results | Where-Object { $_.ControlId -eq "6.1.1.3" }).Status | Should -Be "FAIL"
    }

    It "returns FAIL when no log profiles" {
        Mock Get-AzLogProfile { @() }
        Mock Invoke-ArmRest {
            [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @() } }
        }
        Mock Invoke-AzRestPaged { [PSCustomObject]@{ Success = $true; Data = @() } }

        $results = @(Invoke-Section6Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData (New-S6PD))
        ($results | Where-Object { $_.ControlId -eq "6.1.1.3" }).Status | Should -Be "FAIL"
    }

    It "returns PASS when no log profile but subscription diagnostic settings route Administrative logs" {
        Mock Get-AzLogProfile { @() }
        Mock Invoke-ArmRest {
            [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @([PSCustomObject]@{
                name        = "subscriptionToLa"
                workspaceId = "/subscriptions/test/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/law"
                logs        = @(
                    [PSCustomObject]@{ category = "Administrative"; enabled = "True" }
                    [PSCustomObject]@{ category = "Security";       enabled = "True" }
                )
            }) } }
        }
        Mock Invoke-AzRestPaged { [PSCustomObject]@{ Success = $true; Data = @() } }

        $results = @(Invoke-Section6Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData (New-S6PD))
        ($results | Where-Object { $_.ControlId -eq "6.1.1.3" }).Status | Should -Be "PASS"
    }

    It "returns FAIL when no log profile and no subscription diagnostic settings" {
        Mock Get-AzLogProfile { @() }
        Mock Invoke-ArmRest {
            [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @() } }
        }
        Mock Invoke-AzRestPaged { [PSCustomObject]@{ Success = $true; Data = @() } }

        $results = @(Invoke-Section6Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData (New-S6PD))
        ($results | Where-Object { $_.ControlId -eq "6.1.1.3" }).Status | Should -Be "FAIL"
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

        Mock Invoke-AzCli {
            param($Arguments)
            if ($Arguments -contains "diagnostic-settings" -and $Arguments[-1] -match 'kv1') {
                return [PSCustomObject]@{ Success = $true; Data = @([PSCustomObject]@{
                    logs = @([PSCustomObject]@{ enabled = "False"; category = "AuditEvent" })
                }) }
            }
            if ($Arguments -contains "diagnostic-settings" -and $Arguments -contains "subscription") {
                return [PSCustomObject]@{ Success = $true; Data = @() }
            }
            if ($Arguments -contains "log-profiles") {
                return [PSCustomObject]@{ Success = $true; Data = @() }
            }
            if ($Arguments -contains "activity-log") {
                return [PSCustomObject]@{ Success = $true; Data = @() }
            }
            return [PSCustomObject]@{ Success = $true; Data = @() }
        }
        Mock Invoke-AzRestPaged { [PSCustomObject]@{ Success = $true; Data = @() } }

        $results = @(Invoke-Section6Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "6.1.1.4" }).Status | Should -Be "FAIL"
    }

    It "returns INFO when no Key Vaults" {
        $pd = Merge-PD @((New-PD "keyvaults" @()), (New-PD "app_services" @()))

        Mock Invoke-AzCli {
            param($Arguments)
            if ($Arguments -contains "diagnostic-settings") { return [PSCustomObject]@{ Success = $true; Data = @() } }
            if ($Arguments -contains "log-profiles") { return [PSCustomObject]@{ Success = $true; Data = @() } }
            if ($Arguments -contains "activity-log") { return [PSCustomObject]@{ Success = $true; Data = @() } }
            return [PSCustomObject]@{ Success = $true; Data = @() }
        }
        Mock Invoke-AzRestPaged { [PSCustomObject]@{ Success = $true; Data = @() } }

        $results = @(Invoke-Section6Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "6.1.1.4" }).Status | Should -Be "INFO"
    }
}

Describe "Invoke-Section6Checks — 6.1.1.6 App Service Resource Logs" {
    It "returns PASS for app with compliant diagnostic setting (Log Analytics)" {
        $app = [PSCustomObject]@{ id = "/sub/x/sites/app1"; name = "app1"; kind = "app" }
        $pd = Merge-PD @((New-PD "keyvaults" @()), (New-PD "app_services" @($app)))

        Mock Get-AzDiagnosticSetting {
            [PSCustomObject]@{
                Log = @([PSCustomObject]@{ Enabled = $true; RetentionPolicyEnabled = $false; RetentionPolicyDay = 0 })
                StorageAccountId = $null
            }
        }
        Mock Get-AzLogProfile { @() }
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @() } } }
        Mock Invoke-AzRestPaged { [PSCustomObject]@{ Success = $true; Data = @() } }

        $results = @(Invoke-Section6Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "6.1.1.6" }).Status | Should -Be "PASS"
    }

    It "returns FAIL for app with no diagnostic settings" {
        $app = [PSCustomObject]@{ id = "/sub/x/sites/app2"; name = "app2"; kind = "app" }
        $pd = Merge-PD @((New-PD "keyvaults" @()), (New-PD "app_services" @($app)))

        Mock Invoke-AzCli {
            param($Arguments)
            if ($Arguments -contains "diagnostic-settings" -and $Arguments[-1] -match 'app2') {
                return [PSCustomObject]@{ Success = $true; Data = @() }
            }
            if ($Arguments -contains "diagnostic-settings" -and $Arguments -contains "subscription") {
                return [PSCustomObject]@{ Success = $true; Data = @() }
            }
            if ($Arguments -contains "log-profiles") { return [PSCustomObject]@{ Success = $true; Data = @() } }
            if ($Arguments -contains "activity-log") { return [PSCustomObject]@{ Success = $true; Data = @() } }
            return [PSCustomObject]@{ Success = $true; Data = @() }
        }
        Mock Invoke-AzRestPaged { [PSCustomObject]@{ Success = $true; Data = @() } }

        $results = @(Invoke-Section6Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "6.1.1.6" }).Status | Should -Be "FAIL"
    }

    It "returns INFO when no App Services" {
        $pd = Merge-PD @((New-PD "keyvaults" @()), (New-PD "app_services" @()))

        Mock Invoke-AzCli {
            param($Arguments)
            if ($Arguments -contains "diagnostic-settings") { return [PSCustomObject]@{ Success = $true; Data = @() } }
            if ($Arguments -contains "log-profiles") { return [PSCustomObject]@{ Success = $true; Data = @() } }
            if ($Arguments -contains "activity-log") { return [PSCustomObject]@{ Success = $true; Data = @() } }
            return [PSCustomObject]@{ Success = $true; Data = @() }
        }
        Mock Invoke-AzRestPaged { [PSCustomObject]@{ Success = $true; Data = @() } }

        $results = @(Invoke-Section6Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "6.1.1.6" }).Status | Should -Be "INFO"
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
        Mock Invoke-AzCli {
            param($Arguments)
            if ($Arguments -contains "diagnostic-settings") { return [PSCustomObject]@{ Success = $true; Data = @() } }
            if ($Arguments -contains "log-profiles") { return [PSCustomObject]@{ Success = $true; Data = @() } }
            if ($Arguments -contains "activity-log") { return [PSCustomObject]@{ Success = $true; Data = @() } }
            return [PSCustomObject]@{ Success = $true; Data = @() }
        }
        Mock Invoke-AzRestPaged { [PSCustomObject]@{ Success = $true; Data = @([PSCustomObject]@{ name = "ai1" }) } }

        $results = @(Invoke-Section6Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData (New-S6PD))
        ($results | Where-Object { $_.ControlId -eq "6.1.3.1" }).Status | Should -Be "PASS"
    }

    It "returns FAIL when no App Insights components" {
        Mock Invoke-AzCli {
            param($Arguments)
            if ($Arguments -contains "diagnostic-settings") { return [PSCustomObject]@{ Success = $true; Data = @() } }
            if ($Arguments -contains "log-profiles") { return [PSCustomObject]@{ Success = $true; Data = @() } }
            if ($Arguments -contains "activity-log") { return [PSCustomObject]@{ Success = $true; Data = @() } }
            return [PSCustomObject]@{ Success = $true; Data = @() }
        }
        Mock Invoke-AzRestPaged { [PSCustomObject]@{ Success = $true; Data = @() } }

        $results = @(Invoke-Section6Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData (New-S6PD))
        ($results | Where-Object { $_.ControlId -eq "6.1.3.1" }).Status | Should -Be "FAIL"
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
        Mock Invoke-AzCli { [PSCustomObject]@{ Success = $true; Data = @() } }
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
        Mock Invoke-AzCli { [PSCustomObject]@{ Success = $true; Data = @() } }
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
        Mock Invoke-AzCli { [PSCustomObject]@{ Success = $true; Data = @() } }
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
        Mock Invoke-AzCli { [PSCustomObject]@{ Success = $true; Data = @() } }
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
        Mock Invoke-AzCli { [PSCustomObject]@{ Success = $true; Data = @() } }
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
        Mock Invoke-AzCli { [PSCustomObject]@{ Success = $true; Data = @() } }
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
        Mock Invoke-AzCli { [PSCustomObject]@{ Success = $true; Data = @() } }
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
        Mock Invoke-AzCli { [PSCustomObject]@{ Success = $true; Data = @() } }
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
        Mock Invoke-AzCli { [PSCustomObject]@{ Success = $true; Data = @() } }
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
        Mock Invoke-AzCli { [PSCustomObject]@{ Success = $true; Data = @() } }
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
        Mock Invoke-AzCli { [PSCustomObject]@{ Success = $true; Data = @() } }
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
        Mock Invoke-AzCli { [PSCustomObject]@{ Success = $true; Data = @() } }
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
        Mock Invoke-AzCli { [PSCustomObject]@{ Success = $true; Data = @() } }
        $results = @(Invoke-Section7Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "7.10" }).Status | Should -Be "FAIL"
    }

    It "returns INFO when no App Gateways" {
        $pd = Merge-PD @(
            (New-PD "nsgs" @()), (New-PD "app_gateways" @()), (New-PD "watchers" @()),
            (New-PD "locations" @()), (New-PD "waf_policies" @()), (New-PD "subnets" @()), (New-PD "vnets" @())
        )
        Mock Invoke-AzCli { [PSCustomObject]@{ Success = $true; Data = @() } }
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
        Mock Invoke-AzCli { [PSCustomObject]@{ Success = $true; Data = @() } }
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
        Mock Invoke-AzCli { [PSCustomObject]@{ Success = $true; Data = @() } }
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
        Mock Invoke-AzCli { [PSCustomObject]@{ Success = $true; Data = @() } }
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
        Mock Invoke-AzCli { [PSCustomObject]@{ Success = $true; Data = @() } }
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
        Mock Invoke-AzCli { [PSCustomObject]@{ Success = $true; Data = @() } }
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
        Mock Invoke-AzCli { [PSCustomObject]@{ Success = $true; Data = @() } }
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
        Mock Invoke-AzCli { [PSCustomObject]@{ Success = $true; Data = @() } }
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
        Mock Invoke-AzCli { [PSCustomObject]@{ Success = $true; Data = @() } }
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
        Mock Invoke-AzCli { [PSCustomObject]@{ Success = $true; Data = @() } }
        $results = @(Invoke-Section7Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "7.15" }).Status | Should -Be "INFO"
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
        Mock Invoke-AzCli {
            param($Arguments)
            if ($Arguments -contains "pricing" -and $Arguments -contains "show") {
                return [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ pricingTier = "Standard" } }
            }
            if ($Arguments -contains "contact") { return [PSCustomObject]@{ Success = $true; Data = @() } }
            return [PSCustomObject]@{ Success = $true; Data = @() }
        }
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ properties = [PSCustomObject]@{ enabled = "true" }; value = @() } } }

        $results = @(Invoke-Section8Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData (New-S8PD))
        ($results | Where-Object { $_.ControlId -eq "8.1.1.1" }).Status | Should -Be "PASS"
    }

    It "returns FAIL for Defender plan when tier is Free" {
        Mock Invoke-AzCli {
            param($Arguments)
            if ($Arguments -contains "pricing" -and $Arguments -contains "show") {
                return [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ pricingTier = "Free" } }
            }
            if ($Arguments -contains "contact") { return [PSCustomObject]@{ Success = $true; Data = @() } }
            return [PSCustomObject]@{ Success = $true; Data = @() }
        }
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
        Mock Invoke-AzCli {
            param($Arguments)
            if ($Arguments -contains "pricing") { return [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ pricingTier = "Standard" } } }
            if ($Arguments -contains "contact") { return [PSCustomObject]@{ Success = $true; Data = @() } }
            return [PSCustomObject]@{ Success = $true; Data = @() }
        }
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
        Mock Invoke-AzCli {
            param($Arguments)
            if ($Arguments -contains "pricing") { return [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ pricingTier = "Standard" } } }
            if ($Arguments -contains "contact") { return [PSCustomObject]@{ Success = $true; Data = @() } }
            return [PSCustomObject]@{ Success = $true; Data = @() }
        }
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
        Mock Invoke-AzCli {
            param($Arguments)
            if ($Arguments -contains "pricing") { return [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ pricingTier = "Standard" } } }
            if ($Arguments -contains "contact") { return [PSCustomObject]@{ Success = $true; Data = @() } }
            return [PSCustomObject]@{ Success = $true; Data = @() }
        }
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
        Mock Invoke-AzCli {
            param($Arguments)
            if ($Arguments -contains "pricing") { return [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ pricingTier = "Standard" } } }
            if ($Arguments -contains "contact") { return [PSCustomObject]@{ Success = $true; Data = @() } }
            return [PSCustomObject]@{ Success = $true; Data = @() }
        }
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
        Mock Invoke-AzCli {
            param($Arguments)
            if ($Arguments -contains "pricing") { return [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ pricingTier = "Standard" } } }
            if ($Arguments -contains "contact") {
                return [PSCustomObject]@{ Success = $true; Data = @([PSCustomObject]@{
                    notificationsByRole = [PSCustomObject]@{ roles = @("Owner") }
                    emails = "admin@test.com"
                }) }
            }
            return [PSCustomObject]@{ Success = $true; Data = @() }
        }
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
        Mock Invoke-AzCli {
            param($Arguments)
            if ($Arguments -contains "pricing") { return [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ pricingTier = "Standard" } } }
            if ($Arguments -contains "contact") {
                return [PSCustomObject]@{ Success = $true; Data = @([PSCustomObject]@{
                    notificationsByRole = [PSCustomObject]@{ roles = @("Contributor") }
                    emails = ""
                }) }
            }
            return [PSCustomObject]@{ Success = $true; Data = @() }
        }
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
        Mock Invoke-AzCli { [PSCustomObject]@{ Success = $true; Data = @() } }
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @() } } }
        $results = @(Invoke-Section8Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "8.3.6" }).Status | Should -Be "PASS"
    }

    It "8.3.6 — FAIL when RBAC not enabled" {
        $pd = Merge-PD @((New-PD "keyvaults" @(New-KV -Rbac $false)), (New-PD "bastion" @()), (New-PD "vms" @()), (New-PD "vnets" @()))
        Mock Invoke-AzCli { [PSCustomObject]@{ Success = $true; Data = @() } }
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @() } } }
        $results = @(Invoke-Section8Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "8.3.6" }).Status | Should -Be "FAIL"
    }

    It "8.3.7 — PASS when public access Disabled" {
        $pd = Merge-PD @((New-PD "keyvaults" @(New-KV -Pub "Disabled")), (New-PD "bastion" @()), (New-PD "vms" @()), (New-PD "vnets" @()))
        Mock Invoke-AzCli { [PSCustomObject]@{ Success = $true; Data = @() } }
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @() } } }
        $results = @(Invoke-Section8Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "8.3.7" }).Status | Should -Be "PASS"
    }

    It "8.3.7 — FAIL when public access Enabled" {
        $pd = Merge-PD @((New-PD "keyvaults" @(New-KV -Pub "Enabled")), (New-PD "bastion" @()), (New-PD "vms" @()), (New-PD "vnets" @()))
        Mock Invoke-AzCli { [PSCustomObject]@{ Success = $true; Data = @() } }
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @() } } }
        $results = @(Invoke-Section8Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "8.3.7" }).Status | Should -Be "FAIL"
    }

    It "8.3.8 — PASS when private endpoints configured" {
        $pd = Merge-PD @((New-PD "keyvaults" @(New-KV -Eps 2)), (New-PD "bastion" @()), (New-PD "vms" @()), (New-PD "vnets" @()))
        Mock Invoke-AzCli { [PSCustomObject]@{ Success = $true; Data = @() } }
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @() } } }
        $results = @(Invoke-Section8Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "8.3.8" }).Status | Should -Be "PASS"
    }

    It "8.3.8 — FAIL when no private endpoints" {
        $pd = Merge-PD @((New-PD "keyvaults" @(New-KV -Eps 0)), (New-PD "bastion" @()), (New-PD "vms" @()), (New-PD "vnets" @()))
        Mock Invoke-AzCli { [PSCustomObject]@{ Success = $true; Data = @() } }
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @() } } }
        $results = @(Invoke-Section8Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "8.3.8" }).Status | Should -Be "FAIL"
    }

    It "8.3.1 — PASS when all keys have expiration (RBAC vault)" {
        $kv = New-KV -Rbac $true
        $pd = Merge-PD @((New-PD "keyvaults" @($kv)), (New-PD "bastion" @()), (New-PD "vms" @()), (New-PD "vnets" @()))
        Mock Invoke-AzCli {
            param($Arguments)
            if ($Arguments -contains "key" -and $Arguments -contains "list") {
                return [PSCustomObject]@{ Success = $true; Data = @(
                    [PSCustomObject]@{ name = "k1"; attributes = [PSCustomObject]@{ expires = "2025-12-31T00:00:00Z" } }
                ) }
            }
            if ($Arguments -contains "pricing") { return [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ pricingTier = "Free" } } }
            if ($Arguments -contains "contact") { return [PSCustomObject]@{ Success = $true; Data = @() } }
            return [PSCustomObject]@{ Success = $true; Data = @() }
        }
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @() } } }
        $results = @(Invoke-Section8Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "8.3.1" }).Status | Should -Be "PASS"
    }

    It "8.3.1 — FAIL when key has no expiration (RBAC vault)" {
        $kv = New-KV -Rbac $true
        $pd = Merge-PD @((New-PD "keyvaults" @($kv)), (New-PD "bastion" @()), (New-PD "vms" @()), (New-PD "vnets" @()))
        Mock Invoke-AzCli {
            param($Arguments)
            if ($Arguments -contains "key" -and $Arguments -contains "list") {
                return [PSCustomObject]@{ Success = $true; Data = @(
                    [PSCustomObject]@{ name = "k-no-exp"; attributes = [PSCustomObject]@{ expires = $null } }
                ) }
            }
            if ($Arguments -contains "pricing") { return [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ pricingTier = "Free" } } }
            if ($Arguments -contains "contact") { return [PSCustomObject]@{ Success = $true; Data = @() } }
            return [PSCustomObject]@{ Success = $true; Data = @() }
        }
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @() } } }
        $results = @(Invoke-Section8Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "8.3.1" }).Status | Should -Be "FAIL"
    }

    It "8.3.3 — PASS when all secrets have expiration (RBAC vault)" {
        $kv = New-KV -Rbac $true
        $pd = Merge-PD @((New-PD "keyvaults" @($kv)), (New-PD "bastion" @()), (New-PD "vms" @()), (New-PD "vnets" @()))
        Mock Invoke-AzCli {
            param($Arguments)
            if ($Arguments -contains "secret" -and $Arguments -contains "list") {
                return [PSCustomObject]@{ Success = $true; Data = @(
                    [PSCustomObject]@{ name = "s1"; attributes = [PSCustomObject]@{ expires = "2025-12-31T00:00:00Z" } }
                ) }
            }
            if ($Arguments -contains "key" -and $Arguments -contains "list") { return [PSCustomObject]@{ Success = $true; Data = @() } }
            if ($Arguments -contains "certificate") { return [PSCustomObject]@{ Success = $true; Data = @() } }
            if ($Arguments -contains "pricing") { return [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ pricingTier = "Free" } } }
            if ($Arguments -contains "contact") { return [PSCustomObject]@{ Success = $true; Data = @() } }
            return [PSCustomObject]@{ Success = $true; Data = @() }
        }
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @() } } }
        $results = @(Invoke-Section8Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "8.3.3" }).Status | Should -Be "PASS"
    }

    It "8.3.3 — FAIL when secret has no expiration (RBAC vault)" {
        $kv = New-KV -Rbac $true
        $pd = Merge-PD @((New-PD "keyvaults" @($kv)), (New-PD "bastion" @()), (New-PD "vms" @()), (New-PD "vnets" @()))
        Mock Invoke-AzCli {
            param($Arguments)
            if ($Arguments -contains "secret" -and $Arguments -contains "list") {
                return [PSCustomObject]@{ Success = $true; Data = @(
                    [PSCustomObject]@{ name = "s-no-exp"; attributes = [PSCustomObject]@{ expires = $null } }
                ) }
            }
            if ($Arguments -contains "key" -and $Arguments -contains "list") { return [PSCustomObject]@{ Success = $true; Data = @() } }
            if ($Arguments -contains "certificate") { return [PSCustomObject]@{ Success = $true; Data = @() } }
            if ($Arguments -contains "pricing") { return [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ pricingTier = "Free" } } }
            if ($Arguments -contains "contact") { return [PSCustomObject]@{ Success = $true; Data = @() } }
            return [PSCustomObject]@{ Success = $true; Data = @() }
        }
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @() } } }
        $results = @(Invoke-Section8Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "8.3.3" }).Status | Should -Be "FAIL"
    }

    It "8.3.11 — PASS when cert validity <= 12 months" {
        $kv = New-KV -Rbac $true
        $pd = Merge-PD @((New-PD "keyvaults" @($kv)), (New-PD "bastion" @()), (New-PD "vms" @()), (New-PD "vnets" @()))
        $now = [datetime]::UtcNow
        Mock Invoke-AzCli {
            param($Arguments)
            if ($Arguments -contains "certificate" -and $Arguments -contains "list") {
                return [PSCustomObject]@{ Success = $true; Data = @(
                    [PSCustomObject]@{ name = "c1"; attributes = [PSCustomObject]@{
                        created = $now.AddMonths(-6).ToString("o")
                        expires = $now.AddMonths(6).ToString("o")
                    } }
                ) }
            }
            if ($Arguments -contains "key") { return [PSCustomObject]@{ Success = $true; Data = @() } }
            if ($Arguments -contains "secret") { return [PSCustomObject]@{ Success = $true; Data = @() } }
            if ($Arguments -contains "pricing") { return [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ pricingTier = "Free" } } }
            if ($Arguments -contains "contact") { return [PSCustomObject]@{ Success = $true; Data = @() } }
            return [PSCustomObject]@{ Success = $true; Data = @() }
        }
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @() } } }
        $results = @(Invoke-Section8Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "8.3.11" }).Status | Should -Be "PASS"
    }

    It "8.3.11 — FAIL when cert validity > 12 months" {
        $kv = New-KV -Rbac $true
        $pd = Merge-PD @((New-PD "keyvaults" @($kv)), (New-PD "bastion" @()), (New-PD "vms" @()), (New-PD "vnets" @()))
        Mock Invoke-AzCli {
            param($Arguments)
            if ($Arguments -contains "certificate" -and $Arguments -contains "list") {
                return [PSCustomObject]@{ Success = $true; Data = @(
                    [PSCustomObject]@{ name = "c-long"; attributes = [PSCustomObject]@{
                        created = "2024-01-01T00:00:00Z"
                        expires = "2026-01-01T00:00:00Z"
                    } }
                ) }
            }
            if ($Arguments -contains "key") { return [PSCustomObject]@{ Success = $true; Data = @() } }
            if ($Arguments -contains "secret") { return [PSCustomObject]@{ Success = $true; Data = @() } }
            if ($Arguments -contains "pricing") { return [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ pricingTier = "Free" } } }
            if ($Arguments -contains "contact") { return [PSCustomObject]@{ Success = $true; Data = @() } }
            return [PSCustomObject]@{ Success = $true; Data = @() }
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
        Mock Invoke-AzCli {
            param($Arguments)
            if ($Arguments -contains "pricing") { return [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ pricingTier = "Standard" } } }
            if ($Arguments -contains "contact") { return [PSCustomObject]@{ Success = $true; Data = @() } }
            return [PSCustomObject]@{ Success = $true; Data = @() }
        }
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
        Mock Invoke-AzCli {
            param($Arguments)
            if ($Arguments -contains "pricing") { return [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ pricingTier = "Standard" } } }
            if ($Arguments -contains "contact") { return [PSCustomObject]@{ Success = $true; Data = @() } }
            return [PSCustomObject]@{ Success = $true; Data = @() }
        }
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @() } } }

        $results = @(Invoke-Section8Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "8.5" }).Status | Should -Be "FAIL"
    }

    It "returns INFO when no VNets" {
        $pd = Merge-PD @(
            (New-PD "keyvaults" @()), (New-PD "bastion" @()),
            (New-PD "vms" @()), (New-PD "vnets" @())
        )
        Mock Invoke-AzCli {
            param($Arguments)
            if ($Arguments -contains "pricing") { return [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ pricingTier = "Standard" } } }
            if ($Arguments -contains "contact") { return [PSCustomObject]@{ Success = $true; Data = @() } }
            return [PSCustomObject]@{ Success = $true; Data = @() }
        }
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @() } } }

        $results = @(Invoke-Section8Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "8.5" }).Status | Should -Be "INFO"
    }
}

# =============================================================================
# SECTION 9 — STORAGE (additional coverage)
# =============================================================================

Describe "Invoke-Section9Checks — 9.3.1.1 Key Rotation Reminder" {
    It "returns PASS when keyExpirationPeriodInDays is set" {
        $acct = [PSCustomObject]@{
            id = "/x"; name = "sa-keyrem"; resourceGroup = "rg"; kind = "StorageV2"
            httpsOnly = "true"; publicAccess = "Disabled"; crossTenant = "false"
            blobAnon = "false"; defaultAction = "Deny"; bypass = "AzureServices"
            minTls = "TLS1_2"; keyAccess = "false"; oauthDefault = "true"
            sku = "Standard_GRS"; privateEps = 1
        }
        $pd = New-PD "storage" @($acct)
        $keyData = [PSCustomObject]@{
            keyCreationTime = [PSCustomObject]@{
                key1 = (Get-Date).AddDays(-30).ToString("o")
                key2 = (Get-Date).AddDays(-30).ToString("o")
            }
            keyExpirationPeriodInDays = 90
        }
        Mock Invoke-AzCli {
            param($Arguments)
            if ($Arguments -contains "show" -and $Arguments -contains "account") { return [PSCustomObject]@{ Success = $true; Data = $keyData } }
            return [PSCustomObject]@{ Success = $true; Data = @() }
        }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.3.1.1" }).Status | Should -Be "PASS"
    }

    It "returns FAIL when keyExpirationPeriodInDays is null" {
        $acct = [PSCustomObject]@{
            id = "/x"; name = "sa-nokeyr"; resourceGroup = "rg"; kind = "StorageV2"
            httpsOnly = "true"; publicAccess = "Disabled"; crossTenant = "false"
            blobAnon = "false"; defaultAction = "Deny"; bypass = "AzureServices"
            minTls = "TLS1_2"; keyAccess = "false"; oauthDefault = "true"
            sku = "Standard_GRS"; privateEps = 1
        }
        $pd = New-PD "storage" @($acct)
        $keyData = [PSCustomObject]@{
            keyCreationTime = [PSCustomObject]@{
                key1 = (Get-Date).AddDays(-30).ToString("o")
                key2 = (Get-Date).AddDays(-30).ToString("o")
            }
            keyExpirationPeriodInDays = $null
        }
        Mock Invoke-AzCli {
            param($Arguments)
            if ($Arguments -contains "show" -and $Arguments -contains "account") { return [PSCustomObject]@{ Success = $true; Data = $keyData } }
            return [PSCustomObject]@{ Success = $true; Data = @() }
        }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.3.1.1" }).Status | Should -Be "FAIL"
    }
}

Describe "Invoke-Section9Checks — 9.3.1.2 Key Rotation Within 90 Days" {
    It "returns PASS when both keys are within 90 days" {
        $acct = [PSCustomObject]@{
            id = "/x"; name = "sa-keyrot"; resourceGroup = "rg"; kind = "StorageV2"
            httpsOnly = "true"; publicAccess = "Disabled"; crossTenant = "false"
            blobAnon = "false"; defaultAction = "Deny"; bypass = "AzureServices"
            minTls = "TLS1_2"; keyAccess = "false"; oauthDefault = "true"
            sku = "Standard_GRS"; privateEps = 1
        }
        $pd = New-PD "storage" @($acct)
        $keyData = [PSCustomObject]@{
            keyCreationTime = [PSCustomObject]@{
                key1 = (Get-Date).AddDays(-30).ToString("o")
                key2 = (Get-Date).AddDays(-10).ToString("o")
            }
            keyExpirationPeriodInDays = 90
        }
        Mock Invoke-AzCli {
            param($Arguments)
            if ($Arguments -contains "show" -and $Arguments -contains "account") { return [PSCustomObject]@{ Success = $true; Data = $keyData } }
            return [PSCustomObject]@{ Success = $true; Data = @() }
        }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.3.1.2" }).Status | Should -Be "PASS"
    }

    It "returns FAIL when a key is older than 90 days" {
        $acct = [PSCustomObject]@{
            id = "/x"; name = "sa-keyold"; resourceGroup = "rg"; kind = "StorageV2"
            httpsOnly = "true"; publicAccess = "Disabled"; crossTenant = "false"
            blobAnon = "false"; defaultAction = "Deny"; bypass = "AzureServices"
            minTls = "TLS1_2"; keyAccess = "false"; oauthDefault = "true"
            sku = "Standard_GRS"; privateEps = 1
        }
        $pd = New-PD "storage" @($acct)
        $keyData = [PSCustomObject]@{
            keyCreationTime = [PSCustomObject]@{
                key1 = (Get-Date).AddDays(-120).ToString("o")
                key2 = (Get-Date).AddDays(-30).ToString("o")
            }
            keyExpirationPeriodInDays = 90
        }
        Mock Invoke-AzCli {
            param($Arguments)
            if ($Arguments -contains "show" -and $Arguments -contains "account") { return [PSCustomObject]@{ Success = $true; Data = $keyData } }
            return [PSCustomObject]@{ Success = $true; Data = @() }
        }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.3.1.2" }).Status | Should -Be "FAIL"
    }
}

Describe "Invoke-Section9Checks — 9.3.1.3 Shared Key Access" {
    It "returns PASS when keyAccess is false" {
        $acct = [PSCustomObject]@{
            id = "/x"; name = "sa9"; resourceGroup = "rg"; kind = "StorageV2"
            httpsOnly = "true"; publicAccess = "Disabled"; crossTenant = "false"
            blobAnon = "false"; defaultAction = "Deny"; bypass = "AzureServices"
            minTls = "TLS1_2"; keyAccess = "false"; oauthDefault = "true"
            sku = "Standard_GRS"; privateEps = 1
        }
        $pd = New-PD "storage" @($acct)
        Mock Invoke-AzCli { [PSCustomObject]@{ Success = $true; Data = @() } }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.3.1.3" }).Status | Should -Be "PASS"
    }

    It "returns FAIL when keyAccess is true" {
        $acct = [PSCustomObject]@{
            id = "/x"; name = "sa10"; resourceGroup = "rg"; kind = "StorageV2"
            httpsOnly = "true"; publicAccess = "Enabled"; crossTenant = "false"
            blobAnon = "false"; defaultAction = "Allow"; bypass = "None"
            minTls = "TLS1_2"; keyAccess = "true"; oauthDefault = "false"
            sku = "Standard_LRS"; privateEps = 0
        }
        $pd = New-PD "storage" @($acct)
        Mock Invoke-AzCli { [PSCustomObject]@{ Success = $true; Data = @() } }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.3.1.3" }).Status | Should -Be "FAIL"
    }
}

Describe "Invoke-Section9Checks — 9.3.3.1 OAuth Default" {
    It "returns PASS when oauthDefault is true" {
        $acct = [PSCustomObject]@{
            id = "/x"; name = "sa-oauth"; resourceGroup = "rg"; kind = "StorageV2"
            httpsOnly = "true"; publicAccess = "Disabled"; crossTenant = "false"
            blobAnon = "false"; defaultAction = "Deny"; bypass = "AzureServices"
            minTls = "TLS1_2"; keyAccess = "false"; oauthDefault = "true"
            sku = "Standard_GRS"; privateEps = 1
        }
        $pd = New-PD "storage" @($acct)
        Mock Invoke-AzCli { [PSCustomObject]@{ Success = $true; Data = @() } }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.3.3.1" }).Status | Should -Be "PASS"
    }

    It "returns FAIL when oauthDefault is false" {
        $acct = [PSCustomObject]@{
            id = "/x"; name = "sa-nooauth"; resourceGroup = "rg"; kind = "StorageV2"
            httpsOnly = "true"; publicAccess = "Enabled"; crossTenant = "false"
            blobAnon = "false"; defaultAction = "Allow"; bypass = "None"
            minTls = "TLS1_2"; keyAccess = "true"; oauthDefault = "false"
            sku = "Standard_LRS"; privateEps = 0
        }
        $pd = New-PD "storage" @($acct)
        Mock Invoke-AzCli { [PSCustomObject]@{ Success = $true; Data = @() } }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.3.3.1" }).Status | Should -Be "FAIL"
    }
}

Describe "Invoke-Section9Checks — 9.3.2.x Network Checks" {
    BeforeAll {
        $script:compliantAcct = [PSCustomObject]@{
            id = "/x"; name = "sa-net"; resourceGroup = "rg"; kind = "StorageV2"
            httpsOnly = "true"; publicAccess = "Disabled"; crossTenant = "false"
            blobAnon = "false"; defaultAction = "Deny"; bypass = "AzureServices"
            minTls = "TLS1_2"; keyAccess = "false"; oauthDefault = "true"
            sku = "Standard_GRS"; privateEps = 2
        }
        $script:nonCompliantAcct = [PSCustomObject]@{
            id = "/x"; name = "sa-net2"; resourceGroup = "rg"; kind = "StorageV2"
            httpsOnly = "true"; publicAccess = "Enabled"; crossTenant = "false"
            blobAnon = "false"; defaultAction = "Allow"; bypass = "None"
            minTls = "TLS1_2"; keyAccess = "false"; oauthDefault = "true"
            sku = "Standard_LRS"; privateEps = 0
        }
    }

    It "9.3.2.1 — PASS with private endpoints" {
        $pd = New-PD "storage" @($compliantAcct)
        Mock Invoke-AzCli { [PSCustomObject]@{ Success = $true; Data = @() } }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.3.2.1" }).Status | Should -Be "PASS"
    }

    It "9.3.2.1 — FAIL without private endpoints" {
        $pd = New-PD "storage" @($nonCompliantAcct)
        Mock Invoke-AzCli { [PSCustomObject]@{ Success = $true; Data = @() } }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.3.2.1" }).Status | Should -Be "FAIL"
    }

    It "9.3.2.2 — PASS when publicAccess Disabled" {
        $pd = New-PD "storage" @($compliantAcct)
        Mock Invoke-AzCli { [PSCustomObject]@{ Success = $true; Data = @() } }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.3.2.2" }).Status | Should -Be "PASS"
    }

    It "9.3.2.2 — FAIL when publicAccess Enabled" {
        $pd = New-PD "storage" @($nonCompliantAcct)
        Mock Invoke-AzCli { [PSCustomObject]@{ Success = $true; Data = @() } }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.3.2.2" }).Status | Should -Be "FAIL"
    }

    It "9.3.2.3 — PASS when defaultAction Deny" {
        $pd = New-PD "storage" @($compliantAcct)
        Mock Invoke-AzCli { [PSCustomObject]@{ Success = $true; Data = @() } }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.3.2.3" }).Status | Should -Be "PASS"
    }

    It "9.3.2.3 — FAIL when defaultAction Allow" {
        $pd = New-PD "storage" @($nonCompliantAcct)
        Mock Invoke-AzCli { [PSCustomObject]@{ Success = $true; Data = @() } }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.3.2.3" }).Status | Should -Be "FAIL"
    }
}

Describe "Invoke-Section9Checks — 9.3.5 Trusted Services Bypass" {
    It "returns PASS when bypass includes AzureServices" {
        $acct = [PSCustomObject]@{
            id = "/x"; name = "sa-bp"; resourceGroup = "rg"; kind = "StorageV2"
            httpsOnly = "true"; publicAccess = "Disabled"; crossTenant = "false"
            blobAnon = "false"; defaultAction = "Deny"; bypass = "AzureServices"
            minTls = "TLS1_2"; keyAccess = "false"; oauthDefault = "true"
            sku = "Standard_GRS"; privateEps = 1
        }
        $pd = New-PD "storage" @($acct)
        Mock Invoke-AzCli { [PSCustomObject]@{ Success = $true; Data = @() } }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.3.5" }).Status | Should -Be "PASS"
    }

    It "returns FAIL when bypass does not include AzureServices" {
        $acct = [PSCustomObject]@{
            id = "/x"; name = "sa-nobp"; resourceGroup = "rg"; kind = "StorageV2"
            httpsOnly = "true"; publicAccess = "Disabled"; crossTenant = "false"
            blobAnon = "false"; defaultAction = "Deny"; bypass = "None"
            minTls = "TLS1_2"; keyAccess = "false"; oauthDefault = "true"
            sku = "Standard_GRS"; privateEps = 1
        }
        $pd = New-PD "storage" @($acct)
        Mock Invoke-AzCli { [PSCustomObject]@{ Success = $true; Data = @() } }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.3.5" }).Status | Should -Be "FAIL"
    }
}

Describe "Invoke-Section9Checks — 9.3.11 Geo-Redundant Storage" {
    It "returns PASS for GRS SKU" {
        $acct = [PSCustomObject]@{
            id = "/x"; name = "sa-grs"; resourceGroup = "rg"; kind = "StorageV2"
            httpsOnly = "true"; publicAccess = "Disabled"; crossTenant = "false"
            blobAnon = "false"; defaultAction = "Deny"; bypass = "AzureServices"
            minTls = "TLS1_2"; keyAccess = "false"; oauthDefault = "true"
            sku = "Standard_GRS"; privateEps = 1
        }
        $pd = New-PD "storage" @($acct)
        Mock Invoke-AzCli { [PSCustomObject]@{ Success = $true; Data = @() } }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.3.11" }).Status | Should -Be "PASS"
    }

    It "returns FAIL for LRS SKU" {
        $acct = [PSCustomObject]@{
            id = "/x"; name = "sa-lrs"; resourceGroup = "rg"; kind = "StorageV2"
            httpsOnly = "true"; publicAccess = "Disabled"; crossTenant = "false"
            blobAnon = "false"; defaultAction = "Deny"; bypass = "AzureServices"
            minTls = "TLS1_2"; keyAccess = "false"; oauthDefault = "true"
            sku = "Standard_LRS"; privateEps = 1
        }
        $pd = New-PD "storage" @($acct)
        Mock Invoke-AzCli { [PSCustomObject]@{ Success = $true; Data = @() } }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.3.11" }).Status | Should -Be "FAIL"
    }
}

Describe "Invoke-Section9Checks — 9.2.x Blob Service" {
    BeforeAll {
        $script:saBase = [PSCustomObject]@{
            id = "/x"; name = "sa-blob"; resourceGroup = "rg"; kind = "StorageV2"
            httpsOnly = "true"; publicAccess = "Disabled"; crossTenant = "false"
            blobAnon = "false"; defaultAction = "Deny"; bypass = "AzureServices"
            minTls = "TLS1_2"; keyAccess = "false"; oauthDefault = "true"
            sku = "Standard_GRS"; privateEps = 1
        }
    }

    It "returns PASS for all blob checks when compliant" {
        $pd = New-PD "storage" @($saBase)
        $blobSvc = [PSCustomObject]@{
            deleteRetentionPolicy          = [PSCustomObject]@{ enabled = $true; days = 7 }
            containerDeleteRetentionPolicy = [PSCustomObject]@{ enabled = $true; days = 7 }
            isVersioningEnabled            = $true
            logging = [PSCustomObject]@{ read = "true"; write = "true"; delete = "true" }
        }
        Mock Invoke-AzCli {
            param($Arguments)
            if ($Arguments -contains "blob-service-properties") { return [PSCustomObject]@{ Success = $true; Data = $blobSvc } }
            if ($Arguments -contains "file-service-properties") { return [PSCustomObject]@{ Success = $true; Data = @() } }
            if ($Arguments -contains "lock") { return [PSCustomObject]@{ Success = $true; Data = @() } }
            return [PSCustomObject]@{ Success = $true; Data = @() }
        }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.2.1" }).Status | Should -Be "PASS"
        ($results | Where-Object { $_.ControlId -eq "9.2.2" }).Status | Should -Be "PASS"
        ($results | Where-Object { $_.ControlId -eq "9.2.3" }).Status | Should -Be "PASS"
        ($results | Where-Object { $_.ControlId -eq "9.2.4" }).Status | Should -Be "PASS"
        ($results | Where-Object { $_.ControlId -eq "9.2.5" }).Status | Should -Be "PASS"
        ($results | Where-Object { $_.ControlId -eq "9.2.6" }).Status | Should -Be "PASS"
    }

    It "returns FAIL when blob soft delete disabled" {
        $pd = New-PD "storage" @($saBase)
        $blobSvc = [PSCustomObject]@{
            deleteRetentionPolicy          = [PSCustomObject]@{ enabled = $false; days = 0 }
            containerDeleteRetentionPolicy = [PSCustomObject]@{ enabled = $false; days = 0 }
            isVersioningEnabled            = $false
            logging = [PSCustomObject]@{ read = "false"; write = "false"; delete = "false" }
        }
        Mock Invoke-AzCli {
            param($Arguments)
            if ($Arguments -contains "blob-service-properties") { return [PSCustomObject]@{ Success = $true; Data = $blobSvc } }
            if ($Arguments -contains "file-service-properties") { return [PSCustomObject]@{ Success = $true; Data = @() } }
            if ($Arguments -contains "lock") { return [PSCustomObject]@{ Success = $true; Data = @() } }
            return [PSCustomObject]@{ Success = $true; Data = @() }
        }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.2.1" }).Status | Should -Be "FAIL"
        ($results | Where-Object { $_.ControlId -eq "9.2.2" }).Status | Should -Be "FAIL"
        ($results | Where-Object { $_.ControlId -eq "9.2.3" }).Status | Should -Be "FAIL"
        ($results | Where-Object { $_.ControlId -eq "9.2.4" }).Status | Should -Be "FAIL"
    }
}

Describe "Invoke-Section9Checks — 9.1.x File Service" {
    BeforeAll {
        $script:saFile = [PSCustomObject]@{
            id = "/x"; name = "sa-file"; resourceGroup = "rg"; kind = "StorageV2"
            httpsOnly = "true"; publicAccess = "Disabled"; crossTenant = "false"
            blobAnon = "false"; defaultAction = "Deny"; bypass = "AzureServices"
            minTls = "TLS1_2"; keyAccess = "false"; oauthDefault = "true"
            sku = "Standard_GRS"; privateEps = 1
        }
    }

    It "returns PASS when file soft delete and SMB settings compliant" {
        $pd = New-PD "storage" @($saFile)
        $fileSvc = [PSCustomObject]@{
            shareDeleteRetentionPolicy = [PSCustomObject]@{ enabled = $true; days = 14 }
            protocolSettings = [PSCustomObject]@{
                smb = [PSCustomObject]@{
                    versions          = "SMB3.0;SMB3.1.1"
                    channelEncryption = "AES-128-GCM;AES-256-GCM"
                }
            }
        }
        Mock Invoke-AzCli {
            param($Arguments)
            if ($Arguments -contains "file-service-properties") { return [PSCustomObject]@{ Success = $true; Data = $fileSvc } }
            if ($Arguments -contains "blob-service-properties") { return [PSCustomObject]@{ Success = $true; Data = @() } }
            if ($Arguments -contains "lock") { return [PSCustomObject]@{ Success = $true; Data = @() } }
            return [PSCustomObject]@{ Success = $true; Data = @() }
        }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.1.1" }).Status | Should -Be "PASS"
        ($results | Where-Object { $_.ControlId -eq "9.1.2" }).Status | Should -Be "PASS"
        ($results | Where-Object { $_.ControlId -eq "9.1.3" }).Status | Should -Be "PASS"
    }

    It "returns FAIL when file soft delete disabled" {
        $pd = New-PD "storage" @($saFile)
        $fileSvc = [PSCustomObject]@{
            shareDeleteRetentionPolicy = [PSCustomObject]@{ enabled = $false; days = 0 }
            protocolSettings = [PSCustomObject]@{
                smb = [PSCustomObject]@{
                    versions          = "SMB2.1;SMB3.0"
                    channelEncryption = "AES-128-GCM"
                }
            }
        }
        Mock Invoke-AzCli {
            param($Arguments)
            if ($Arguments -contains "file-service-properties") { return [PSCustomObject]@{ Success = $true; Data = $fileSvc } }
            if ($Arguments -contains "blob-service-properties") { return [PSCustomObject]@{ Success = $true; Data = @() } }
            if ($Arguments -contains "lock") { return [PSCustomObject]@{ Success = $true; Data = @() } }
            return [PSCustomObject]@{ Success = $true; Data = @() }
        }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.1.1" }).Status | Should -Be "FAIL"
        ($results | Where-Object { $_.ControlId -eq "9.1.2" }).Status | Should -Be "FAIL"
        ($results | Where-Object { $_.ControlId -eq "9.1.3" }).Status | Should -Be "FAIL"
    }
}

Describe "Invoke-Section9Checks — 9.3.9/9.3.10 Resource Locks" {
    BeforeAll {
        $script:saLock = [PSCustomObject]@{
            id = "/subscriptions/$($script:T_SID)/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa-lock"
            name = "sa-lock"; resourceGroup = "rg"; kind = "StorageV2"
            httpsOnly = "true"; publicAccess = "Disabled"; crossTenant = "false"
            blobAnon = "false"; defaultAction = "Deny"; bypass = "AzureServices"
            minTls = "TLS1_2"; keyAccess = "false"; oauthDefault = "true"
            sku = "Standard_GRS"; privateEps = 1
        }
    }

    It "returns PASS for both when ReadOnly lock exists" {
        $pd = New-PD "storage" @($saLock)
        Mock Invoke-AzCli {
            param($Arguments)
            if ($Arguments -contains "lock") {
                return [PSCustomObject]@{ Success = $true; Data = @([PSCustomObject]@{
                    id = "/subscriptions/$($script:T_SID)/providers/Microsoft.Authorization/locks/mylock"
                    level = "ReadOnly"
                }) }
            }
            if ($Arguments -contains "blob-service-properties") { return [PSCustomObject]@{ Success = $true; Data = @() } }
            if ($Arguments -contains "file-service-properties") { return [PSCustomObject]@{ Success = $true; Data = @() } }
            return [PSCustomObject]@{ Success = $true; Data = @() }
        }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.3.9" }).Status | Should -Be "PASS"
        ($results | Where-Object { $_.ControlId -eq "9.3.10" }).Status | Should -Be "PASS"
    }

    It "returns 9.3.9 PASS / 9.3.10 FAIL for CanNotDelete lock" {
        $pd = New-PD "storage" @($saLock)
        Mock Invoke-AzCli {
            param($Arguments)
            if ($Arguments -contains "lock") {
                return [PSCustomObject]@{ Success = $true; Data = @([PSCustomObject]@{
                    id = "/subscriptions/$($script:T_SID)/providers/Microsoft.Authorization/locks/dellock"
                    level = "CanNotDelete"
                }) }
            }
            if ($Arguments -contains "blob-service-properties") { return [PSCustomObject]@{ Success = $true; Data = @() } }
            if ($Arguments -contains "file-service-properties") { return [PSCustomObject]@{ Success = $true; Data = @() } }
            return [PSCustomObject]@{ Success = $true; Data = @() }
        }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.3.9" }).Status | Should -Be "PASS"
        ($results | Where-Object { $_.ControlId -eq "9.3.10" }).Status | Should -Be "FAIL"
    }

    It "returns FAIL for both when no locks" {
        $pd = New-PD "storage" @($saLock)
        Mock Invoke-AzCli {
            param($Arguments)
            if ($Arguments -contains "lock") { return [PSCustomObject]@{ Success = $true; Data = @() } }
            if ($Arguments -contains "blob-service-properties") { return [PSCustomObject]@{ Success = $true; Data = @() } }
            if ($Arguments -contains "file-service-properties") { return [PSCustomObject]@{ Success = $true; Data = @() } }
            return [PSCustomObject]@{ Success = $true; Data = @() }
        }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.3.9" }).Status | Should -Be "FAIL"
        ($results | Where-Object { $_.ControlId -eq "9.3.10" }).Status | Should -Be "FAIL"
    }
}

# =============================================================================
# SECTION 9 — ADLS Gen2 HNS detection (regression)
# =============================================================================

Describe "Invoke-Section9Checks — ADLS Gen2 HNS detection (regression)" {
    It "skips blob-service-properties call for HNS-enabled account (isHns=true)" {
        # StorageV2 account with Standard_LRS SKU and isHnsEnabled=true.
        # The old SKU heuristic would not detect it as ADLS and would wrongly call
        # blob-service-properties, which is unsupported for HNS accounts.
        $adlsAcct = [PSCustomObject]@{
            id = "/x"; name = "sa-adls"; resourceGroup = "rg"; kind = "StorageV2"
            httpsOnly = "true"; publicAccess = "Disabled"; crossTenant = "false"
            blobAnon = "false"; defaultAction = "Deny"; bypass = "AzureServices"
            minTls = "TLS1_2"; keyAccess = "false"; oauthDefault = "true"
            isHns = "true"; sku = "Standard_LRS"; privateEps = 1
        }
        $pd = New-PD "storage" @($adlsAcct)
        $script:blobApiCalled = $false
        Mock Invoke-AzCli {
            param($Arguments)
            if ($Arguments -contains "blob-service-properties") { $script:blobApiCalled = $true }
            if ($Arguments -contains "lock") { return [PSCustomObject]@{ Success = $true; Data = @() } }
            return [PSCustomObject]@{ Success = $true; Data = @() }
        }
        Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd | Out-Null
        $script:blobApiCalled | Should -BeFalse
    }

    It "calls blob-service-properties for a regular StorageV2 account (isHns=null)" {
        # A standard StorageV2 account (isHns null/false) must still call the blob API.
        $regularAcct = [PSCustomObject]@{
            id = "/x"; name = "sa-regular"; resourceGroup = "rg"; kind = "StorageV2"
            httpsOnly = "true"; publicAccess = "Disabled"; crossTenant = "false"
            blobAnon = "false"; defaultAction = "Deny"; bypass = "AzureServices"
            minTls = "TLS1_2"; keyAccess = "false"; oauthDefault = "true"
            isHns = $null; sku = "Standard_LRS"; privateEps = 1
        }
        $pd = New-PD "storage" @($regularAcct)
        $script:blobApiCalled = $false
        Mock Invoke-AzCli {
            param($Arguments)
            if ($Arguments -contains "blob-service-properties") {
                $script:blobApiCalled = $true
                return [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{
                    deleteRetentionPolicy          = [PSCustomObject]@{ enabled = $true; days = 7 }
                    containerDeleteRetentionPolicy = [PSCustomObject]@{ enabled = $true; days = 7 }
                    isVersioningEnabled            = $true
                    logging = [PSCustomObject]@{ read = "true"; write = "true"; delete = "true" }
                } }
            }
            if ($Arguments -contains "lock") { return [PSCustomObject]@{ Success = $true; Data = @() } }
            return [PSCustomObject]@{ Success = $true; Data = @() }
        }
        Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd | Out-Null
        $script:blobApiCalled | Should -BeTrue
    }
}
