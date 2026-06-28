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
    . (Join-Path $moduleRoot "Private\ModuleManifest.ps1")
    foreach ($f in $script:ModuleFiles) {
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

    # ── Hermetic default mocks ────────────────────────────────────────────────
    # Every real Az cmdlet (and the AzureClient REST wrappers) a check function
    # can invoke is mocked here with a benign empty return. Without these, a check
    # path not explicitly mocked by a test (e.g. Section2's 2.1.2 block still runs
    # the 2.1.7 Get-AzDiagnosticSetting call) makes a live API call. On a CI runner
    # with no Az context that call hangs and aborts the whole run; it only "passes"
    # on a dev machine that happens to be logged in. These root-level mocks keep the
    # suite offline; per-Describe/It Mock calls override them where output matters.
    Mock Get-AzDiagnosticSetting        { @() }
    Mock Get-AzLogProfile               { @() }
    Mock Get-AzActivityLogAlert         { @() }
    Mock Get-AzNetworkWatcherFlowLog    { @() }
    Mock Get-AzRoleDefinition           { @() }
    Mock Get-AzStorageAccount           { @() }
    Mock Get-AzStorageBlobServiceProperty { $null }
    Mock Get-AzStorageFileServiceProperty { $null }
    Mock Get-AzResourceLock             { @() }
    Mock Get-AzSecurityPricing          { $null }
    Mock Get-AzKeyVaultKey              { @() }
    Mock Get-AzKeyVaultSecret           { @() }
    Mock Get-AzKeyVaultCertificate      { @() }
    Mock Get-AzKeyVaultKeyRotationPolicy { $null }
    Mock Invoke-ArmRest                 { [PSCustomObject]@{ Success = $true; Data = @(); Error = $null } }
    Mock Invoke-AzRestPaged             { [PSCustomObject]@{ Success = $true; Data = @(); Error = $null } }
    Mock Invoke-AzGraphQuery            { [PSCustomObject]@{ Success = $true; Data = @(); Error = $null } }
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
# RETRY / THROTTLE (AzureClient)
# =============================================================================

Describe "Test-TransientError" {
    It "matches throttling and 5xx phrasings" {
        Test-TransientError "Response status code does not indicate success: 429 (Too Many Requests)" | Should -BeTrue
        Test-TransientError "TooManyRequests"            | Should -BeTrue
        Test-TransientError "Transient HTTP status (503)" | Should -BeTrue
        Test-TransientError "request was throttled"      | Should -BeTrue
        Test-TransientError "InternalServerError"        | Should -BeTrue
        Test-TransientError "connection was reset"       | Should -BeTrue
    }
    It "does not match ordinary errors" {
        Test-TransientError "AuthorizationFailed: caller does not have permission" | Should -BeFalse
        Test-TransientError "Resource not found (404)" | Should -BeFalse
        Test-TransientError "Found 500 storage accounts" | Should -BeFalse
    }
}

Describe "Invoke-WithRetry" {
    BeforeEach {
        Mock Start-Sleep {}
        $script:_throttleBag = $null
    }

    It "returns the value on first success without retrying" {
        $script:wrCalls = 0
        $result = Invoke-WithRetry -ScriptBlock { $script:wrCalls++; "ok" }
        $result | Should -Be "ok"
        $script:wrCalls | Should -Be 1
    }

    It "succeeds after N transient failures" {
        $script:wrCalls = 0
        $result = Invoke-WithRetry -MaxRetries 3 -ScriptBlock {
            $script:wrCalls++
            if ($script:wrCalls -lt 3) { throw "Transient HTTP status (429)" }
            "recovered"
        }
        $result | Should -Be "recovered"
        $script:wrCalls | Should -Be 3
    }

    It "gives up after MaxRetries transient failures" {
        $script:wrCalls = 0
        { Invoke-WithRetry -MaxRetries 2 -ScriptBlock {
            $script:wrCalls++
            throw "Too Many Requests"
        } } | Should -Throw
        # 1 initial attempt + 2 retries = 3 invocations
        $script:wrCalls | Should -Be 3
    }

    It "does not retry non-transient errors" {
        $script:wrCalls = 0
        { Invoke-WithRetry -MaxRetries 3 -ScriptBlock {
            $script:wrCalls++
            throw "AuthorizationFailed"
        } } | Should -Throw
        $script:wrCalls | Should -Be 1
    }

    It "feeds the throttle bag once per transient retry" {
        $script:_throttleBag = [System.Collections.Concurrent.ConcurrentBag[int]]::new()
        $script:wrCalls = 0
        Invoke-WithRetry -MaxRetries 3 -ScriptBlock {
            $script:wrCalls++
            if ($script:wrCalls -lt 3) { throw "Transient HTTP status (503)" }
            "done"
        } | Out-Null
        # 2 transient retries before success
        $script:_throttleBag.Count | Should -Be 2
        $script:_throttleBag = $null
    }
}

# =============================================================================
# MODULE MANIFEST CONSISTENCY
# =============================================================================

Describe "Module manifest (Private\ModuleManifest.ps1)" {
    BeforeAll {
        $script:repoRoot = Split-Path $PSScriptRoot -Parent
        . (Join-Path $script:repoRoot "Private\ModuleManifest.ps1")
    }

    It "lists every Private\*.ps1 and Checks\*.ps1 on disk (except the manifest itself)" {
        $onDisk = Get-ChildItem -Path (Join-Path $script:repoRoot 'Private'), (Join-Path $script:repoRoot 'Checks') -Filter *.ps1 |
            Where-Object { $_.Name -ne 'ModuleManifest.ps1' } |
            ForEach-Object { (Resolve-Path $_.FullName).Path }
        $listed = $script:ModuleFiles | ForEach-Object { (Resolve-Path (Join-Path $script:repoRoot $_)).Path }
        $missing = @($onDisk | Where-Object { $_ -notin $listed })
        $missing | Should -BeNullOrEmpty -Because "every module file must be in the shared manifest so parallel workers load it"
    }

    It "references only files that exist" {
        foreach ($f in $script:ModuleFiles) {
            Test-Path (Join-Path $script:repoRoot $f) | Should -BeTrue -Because "$f is listed in the manifest"
        }
    }
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

Describe "Invoke-Check5_1_2 — Device Registration MFA (manual)" {
    It "returns MANUAL status" {
        $r = Invoke-Check5_1_2
        $r.Status    | Should -Be "MANUAL"
        $r.ControlId | Should -Be "5.1.2"
    }
}

Describe "Invoke-Check5_1_3 — MFA for All Users" {
    It "returns PASS when all users have MFA" {
        $users = @(
            [PSCustomObject]@{ userPrincipalName = "alice@test.com"; isMfaRegistered = $true }
            [PSCustomObject]@{ userPrincipalName = "bob@test.com";   isMfaRegistered = $true }
        )
        Mock Invoke-AzRestPaged { [PSCustomObject]@{ Success = $true; Data = $users } }
        $r = Invoke-Check5_1_3
        $r.Status | Should -Be "PASS"
    }

    It "returns FAIL when any user lacks MFA" {
        $users = @(
            [PSCustomObject]@{ userPrincipalName = "alice@test.com"; isMfaRegistered = $true }
            [PSCustomObject]@{ userPrincipalName = "bob@test.com";   isMfaRegistered = $false }
        )
        Mock Invoke-AzRestPaged { [PSCustomObject]@{ Success = $true; Data = $users } }
        $r = Invoke-Check5_1_3
        $r.Status  | Should -Be "FAIL"
        $r.Details | Should -Match "1 user"
        $r.Details | Should -Match "bob@test.com"
    }

    It "returns FAIL when a non-admin user lacks MFA (all-user scope)" {
        # v6 5.1.3 covers ALL users, not just admins — a non-admin without MFA must FAIL.
        $users = @(
            [PSCustomObject]@{ userPrincipalName = "admin@test.com";    isMfaRegistered = $true }
            [PSCustomObject]@{ userPrincipalName = "external@corp.com"; isMfaRegistered = $false }
        )
        Mock Invoke-AzRestPaged { [PSCustomObject]@{ Success = $true; Data = $users } }
        $r = Invoke-Check5_1_3
        $r.Status | Should -Be "FAIL"
    }

    It "returns ERROR on API failure" {
        Mock Invoke-AzRestPaged { [PSCustomObject]@{ Success = $false; Error = "Forbidden"; Data = $null } }
        (Invoke-Check5_1_3).Status | Should -Be "ERROR"
    }

    It "returns PASS for empty tenant" {
        Mock Invoke-AzRestPaged { [PSCustomObject]@{ Success = $true; Data = @() } }
        (Invoke-Check5_1_3).Status | Should -Be "PASS"
    }
}

Describe "Section 5 manual controls" {
    It "5.1.4 remember-MFA returns MANUAL" {
        $r = Invoke-Check5_1_4; $r.Status | Should -Be "MANUAL"; $r.ControlId | Should -Be "5.1.4"
    }
    It "5.3.1 admin accounts daily ops returns MANUAL" {
        $r = Invoke-Check5_3_1; $r.Status | Should -Be "MANUAL"; $r.ControlId | Should -Be "5.3.1"
    }
    It "5.3.2 guest users reviewed returns MANUAL" {
        $r = Invoke-Check5_3_2; $r.Status | Should -Be "MANUAL"; $r.ControlId | Should -Be "5.3.2"
    }
    It "5.3.4 privileged role review returns MANUAL" {
        $r = Invoke-Check5_3_4; $r.Status | Should -Be "MANUAL"; $r.ControlId | Should -Be "5.3.4"
    }
    It "5.3.5 disabled accounts returns MANUAL" {
        $r = Invoke-Check5_3_5; $r.Status | Should -Be "MANUAL"; $r.ControlId | Should -Be "5.3.5"
    }
    It "5.3.6 tenant creator review returns MANUAL" {
        $r = Invoke-Check5_3_6; $r.Status | Should -Be "MANUAL"; $r.ControlId | Should -Be "5.3.6"
    }
    It "5.3.7 non-privileged review returns MANUAL" {
        $r = Invoke-Check5_3_7; $r.Status | Should -Be "MANUAL"; $r.ControlId | Should -Be "5.3.7"
    }
    It "5.5 resource-lock custom role returns MANUAL (L2)" {
        $r = Invoke-Check5_5; $r.Status | Should -Be "MANUAL"; $r.ControlId | Should -Be "5.5"; $r.Level | Should -Be 2
    }
    It "5.6 subscription leaving/entering returns MANUAL (L2)" {
        $r = Invoke-Check5_6; $r.Status | Should -Be "MANUAL"; $r.ControlId | Should -Be "5.6"; $r.Level | Should -Be 2
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

Describe "Invoke-Check5_4 — No Custom Subscription Administrator Roles" {
    It "returns PASS when no custom wildcard roles" {
        Mock Get-AzRoleDefinition { @() }
        $r = Invoke-Check5_4 -SubscriptionId $T_SID -SubscriptionName $T_SNAME
        $r.Status    | Should -Be "PASS"
        $r.ControlId | Should -Be "5.4"
    }

    It "returns FAIL when a custom role has wildcard (*) actions" {
        Mock Get-AzRoleDefinition { @([PSCustomObject]@{ Name = "MyAdminRole"; IsCustom = $true; Actions = @('*') }) }
        $r = Invoke-Check5_4 -SubscriptionId $T_SID -SubscriptionName $T_SNAME
        $r.Status  | Should -Be "FAIL"
        $r.Details | Should -Match "MyAdminRole"
    }

    It "returns ERROR on API failure" {
        Mock Get-AzRoleDefinition { throw "AuthorizationFailed" }
        (Invoke-Check5_4 -SubscriptionId $T_SID -SubscriptionName $T_SNAME).Status | Should -Be "ERROR"
    }
}

Describe "Invoke-Check5_7 — 2-3 Subscription Owners" {
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
        (Invoke-Check5_7 -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd).Status | Should -Be "FAIL"
    }

    It "returns FAIL for one owner" {
        $pd = New-PD "roles" @(New-Owner "alice")
        (Invoke-Check5_7 -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd).Status | Should -Be "FAIL"
    }

    It "returns PASS for two owners" {
        $pd = New-PD "roles" @(New-Owner "alice"; New-Owner "bob")
        (Invoke-Check5_7 -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd).Status | Should -Be "PASS"
    }

    It "returns PASS for three owners" {
        $pd = New-PD "roles" @(New-Owner "alice"; New-Owner "bob"; New-Owner "carol")
        (Invoke-Check5_7 -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd).Status | Should -Be "PASS"
    }

    It "returns FAIL for four owners" {
        $pd = New-PD "roles" @(New-Owner "a"; New-Owner "b"; New-Owner "c"; New-Owner "d")
        (Invoke-Check5_7 -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd).Status | Should -Be "FAIL"
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
        (Invoke-Check5_7 -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd).Status | Should -Be "FAIL"
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
# SECTION 9 — STORAGE
# =============================================================================

Describe "Invoke-Section9Checks — no storage accounts" {
    It "returns INFO for all storage controls" {
        $pd = New-PD "storage" @()
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
            DeleteRetentionPolicy          = [PSCustomObject]@{ Enabled = $true; Days = 7 }
            ContainerDeleteRetentionPolicy = [PSCustomObject]@{ Enabled = $true; Days = 7 }
            IsVersioningEnabled            = $true
            Logging                        = [PSCustomObject]@{ Read = $true; Write = $true; Delete = $true }
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

        Mock Get-AzStorageBlobServiceProperty { $blobSvc }
        Mock Get-AzStorageFileServiceProperty  { $fileSvc }
        Mock Get-AzStorageAccount              { throw "not available" }
        Mock Get-AzResourceLock                { @() }

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
        Mock Get-AzStorageBlobServiceProperty { throw "not available" }
        Mock Get-AzStorageFileServiceProperty  { throw "not available" }
        Mock Get-AzStorageAccount              { throw "not available" }
        Mock Get-AzResourceLock                { @() }
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
        Mock Get-AzStorageBlobServiceProperty { throw "not available" }
        Mock Get-AzStorageFileServiceProperty  { throw "not available" }
        Mock Get-AzStorageAccount              { throw "not available" }
        Mock Get-AzResourceLock                { @() }
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
        Mock Get-AzStorageBlobServiceProperty { throw "not available" }
        Mock Get-AzStorageFileServiceProperty  { throw "not available" }
        Mock Get-AzStorageAccount              { throw "not available" }
        Mock Get-AzResourceLock                { @() }
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
        Mock Get-AzStorageBlobServiceProperty { throw "not available" }
        Mock Get-AzStorageFileServiceProperty  { throw "not available" }
        Mock Get-AzStorageAccount              { throw "not available" }
        Mock Get-AzResourceLock                { @() }
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
        Mock Get-AzStorageBlobServiceProperty { throw "not available" }
        Mock Get-AzStorageFileServiceProperty  { throw "not available" }
        Mock Get-AzStorageAccount              { throw "not available" }
        Mock Get-AzResourceLock                { @() }
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
        Mock Get-AzStorageBlobServiceProperty { throw "not available" }
        Mock Get-AzStorageFileServiceProperty  { throw "not available" }
        Mock Get-AzStorageAccount              { throw "not available" }
        Mock Get-AzResourceLock                { @() }
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
        Mock Get-AzStorageBlobServiceProperty { throw "not available" }
        Mock Get-AzStorageFileServiceProperty  { throw "not available" }
        Mock Get-AzStorageAccount              { throw "not available" }
        Mock Get-AzResourceLock                { @() }
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
        Mock Get-AzStorageBlobServiceProperty { throw "not available" }
        Mock Get-AzStorageFileServiceProperty  { throw "not available" }
        Mock Get-AzStorageAccount {
            [PSCustomObject]@{
                StorageAccountName = "sa-keyrem"
                ResourceGroupName  = "rg"
                KeyPolicy          = [PSCustomObject]@{ KeyExpirationPeriodInDays = 90 }
                KeyCreationTime    = [PSCustomObject]@{
                    Key1 = (Get-Date).AddDays(-30)
                    Key2 = (Get-Date).AddDays(-30)
                }
            }
        }
        Mock Get-AzResourceLock { @() }
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
        Mock Get-AzStorageBlobServiceProperty { throw "not available" }
        Mock Get-AzStorageFileServiceProperty  { throw "not available" }
        Mock Get-AzStorageAccount {
            [PSCustomObject]@{
                StorageAccountName = "sa-nokeyr"
                ResourceGroupName  = "rg"
                KeyPolicy          = $null
                KeyCreationTime    = [PSCustomObject]@{
                    Key1 = (Get-Date).AddDays(-30)
                    Key2 = (Get-Date).AddDays(-30)
                }
            }
        }
        Mock Get-AzResourceLock { @() }
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
        Mock Get-AzStorageBlobServiceProperty { throw "not available" }
        Mock Get-AzStorageFileServiceProperty  { throw "not available" }
        Mock Get-AzStorageAccount {
            [PSCustomObject]@{
                StorageAccountName = "sa-keyrot"
                ResourceGroupName  = "rg"
                KeyPolicy          = [PSCustomObject]@{ KeyExpirationPeriodInDays = 90 }
                KeyCreationTime    = [PSCustomObject]@{
                    Key1 = (Get-Date).AddDays(-30)
                    Key2 = (Get-Date).AddDays(-10)
                }
            }
        }
        Mock Get-AzResourceLock { @() }
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
        Mock Get-AzStorageBlobServiceProperty { throw "not available" }
        Mock Get-AzStorageFileServiceProperty  { throw "not available" }
        Mock Get-AzStorageAccount {
            [PSCustomObject]@{
                StorageAccountName = "sa-keyold"
                ResourceGroupName  = "rg"
                KeyPolicy          = [PSCustomObject]@{ KeyExpirationPeriodInDays = 90 }
                KeyCreationTime    = [PSCustomObject]@{
                    Key1 = (Get-Date).AddDays(-120)
                    Key2 = (Get-Date).AddDays(-30)
                }
            }
        }
        Mock Get-AzResourceLock { @() }
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
        Mock Get-AzStorageBlobServiceProperty { throw "not available" }
        Mock Get-AzStorageFileServiceProperty  { throw "not available" }
        Mock Get-AzStorageAccount              { throw "not available" }
        Mock Get-AzResourceLock                { @() }
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
        Mock Get-AzStorageBlobServiceProperty { throw "not available" }
        Mock Get-AzStorageFileServiceProperty  { throw "not available" }
        Mock Get-AzStorageAccount              { throw "not available" }
        Mock Get-AzResourceLock                { @() }
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
        Mock Get-AzStorageBlobServiceProperty { throw "not available" }
        Mock Get-AzStorageFileServiceProperty  { throw "not available" }
        Mock Get-AzStorageAccount              { throw "not available" }
        Mock Get-AzResourceLock                { @() }
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
        Mock Get-AzStorageBlobServiceProperty { throw "not available" }
        Mock Get-AzStorageFileServiceProperty  { throw "not available" }
        Mock Get-AzStorageAccount              { throw "not available" }
        Mock Get-AzResourceLock                { @() }
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
        Mock Get-AzStorageBlobServiceProperty { throw "not available" }
        Mock Get-AzStorageFileServiceProperty  { throw "not available" }
        Mock Get-AzStorageAccount              { throw "not available" }
        Mock Get-AzResourceLock                { @() }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.3.2.1" }).Status | Should -Be "PASS"
    }

    It "9.3.2.1 — FAIL without private endpoints" {
        $pd = New-PD "storage" @($nonCompliantAcct)
        Mock Get-AzStorageBlobServiceProperty { throw "not available" }
        Mock Get-AzStorageFileServiceProperty  { throw "not available" }
        Mock Get-AzStorageAccount              { throw "not available" }
        Mock Get-AzResourceLock                { @() }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.3.2.1" }).Status | Should -Be "FAIL"
    }

    It "9.3.2.2 — PASS when publicAccess Disabled" {
        $pd = New-PD "storage" @($compliantAcct)
        Mock Get-AzStorageBlobServiceProperty { throw "not available" }
        Mock Get-AzStorageFileServiceProperty  { throw "not available" }
        Mock Get-AzStorageAccount              { throw "not available" }
        Mock Get-AzResourceLock                { @() }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.3.2.2" }).Status | Should -Be "PASS"
    }

    It "9.3.2.2 — FAIL when publicAccess Enabled" {
        $pd = New-PD "storage" @($nonCompliantAcct)
        Mock Get-AzStorageBlobServiceProperty { throw "not available" }
        Mock Get-AzStorageFileServiceProperty  { throw "not available" }
        Mock Get-AzStorageAccount              { throw "not available" }
        Mock Get-AzResourceLock                { @() }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.3.2.2" }).Status | Should -Be "FAIL"
    }

    It "9.3.2.3 — PASS when defaultAction Deny" {
        $pd = New-PD "storage" @($compliantAcct)
        Mock Get-AzStorageBlobServiceProperty { throw "not available" }
        Mock Get-AzStorageFileServiceProperty  { throw "not available" }
        Mock Get-AzStorageAccount              { throw "not available" }
        Mock Get-AzResourceLock                { @() }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.3.2.3" }).Status | Should -Be "PASS"
    }

    It "9.3.2.3 — FAIL when defaultAction Allow" {
        $pd = New-PD "storage" @($nonCompliantAcct)
        Mock Get-AzStorageBlobServiceProperty { throw "not available" }
        Mock Get-AzStorageFileServiceProperty  { throw "not available" }
        Mock Get-AzStorageAccount              { throw "not available" }
        Mock Get-AzResourceLock                { @() }
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
        Mock Get-AzStorageBlobServiceProperty { throw "not available" }
        Mock Get-AzStorageFileServiceProperty  { throw "not available" }
        Mock Get-AzStorageAccount              { throw "not available" }
        Mock Get-AzResourceLock                { @() }
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
        Mock Get-AzStorageBlobServiceProperty { throw "not available" }
        Mock Get-AzStorageFileServiceProperty  { throw "not available" }
        Mock Get-AzStorageAccount              { throw "not available" }
        Mock Get-AzResourceLock                { @() }
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
        Mock Get-AzStorageBlobServiceProperty { throw "not available" }
        Mock Get-AzStorageFileServiceProperty  { throw "not available" }
        Mock Get-AzStorageAccount              { throw "not available" }
        Mock Get-AzResourceLock                { @() }
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
        Mock Get-AzStorageBlobServiceProperty { throw "not available" }
        Mock Get-AzStorageFileServiceProperty  { throw "not available" }
        Mock Get-AzStorageAccount              { throw "not available" }
        Mock Get-AzResourceLock                { @() }
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
            DeleteRetentionPolicy          = [PSCustomObject]@{ Enabled = $true; Days = 7 }
            ContainerDeleteRetentionPolicy = [PSCustomObject]@{ Enabled = $true; Days = 7 }
            IsVersioningEnabled            = $true
            Logging                        = [PSCustomObject]@{ Read = $true; Write = $true; Delete = $true }
        }
        Mock Get-AzStorageBlobServiceProperty { $blobSvc }
        Mock Get-AzStorageFileServiceProperty  { throw "not available" }
        Mock Get-AzStorageAccount              { throw "not available" }
        Mock Get-AzResourceLock                { @() }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.2.1" }).Status | Should -Be "PASS"
        ($results | Where-Object { $_.ControlId -eq "9.2.2" }).Status | Should -Be "PASS"
        ($results | Where-Object { $_.ControlId -eq "9.2.3" }).Status | Should -Be "PASS"
    }

    It "returns FAIL when blob soft delete disabled" {
        $pd = New-PD "storage" @($saBase)
        $blobSvc = [PSCustomObject]@{
            DeleteRetentionPolicy          = [PSCustomObject]@{ Enabled = $false; Days = 0 }
            ContainerDeleteRetentionPolicy = [PSCustomObject]@{ Enabled = $false; Days = 0 }
            IsVersioningEnabled            = $false
            Logging                        = [PSCustomObject]@{ Read = $false; Write = $false; Delete = $false }
        }
        Mock Get-AzStorageBlobServiceProperty { $blobSvc }
        Mock Get-AzStorageFileServiceProperty  { throw "not available" }
        Mock Get-AzStorageAccount              { throw "not available" }
        Mock Get-AzResourceLock                { @() }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.2.1" }).Status | Should -Be "FAIL"
        ($results | Where-Object { $_.ControlId -eq "9.2.2" }).Status | Should -Be "FAIL"
        ($results | Where-Object { $_.ControlId -eq "9.2.3" }).Status | Should -Be "FAIL"
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
        Mock Get-AzStorageBlobServiceProperty { throw "not available" }
        Mock Get-AzStorageFileServiceProperty  { $fileSvc }
        Mock Get-AzStorageAccount              { throw "not available" }
        Mock Get-AzResourceLock                { @() }
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
        Mock Get-AzStorageBlobServiceProperty { throw "not available" }
        Mock Get-AzStorageFileServiceProperty  { $fileSvc }
        Mock Get-AzStorageAccount              { throw "not available" }
        Mock Get-AzResourceLock                { @() }
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
        Mock Get-AzStorageBlobServiceProperty { throw "not available" }
        Mock Get-AzStorageFileServiceProperty  { throw "not available" }
        Mock Get-AzStorageAccount              { throw "not available" }
        Mock Get-AzResourceLock {
            @([PSCustomObject]@{
                LockId = "/subscriptions/$($script:T_SID)/providers/Microsoft.Authorization/locks/mylock"
                Level  = "ReadOnly"
            })
        }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.3.9" }).Status | Should -Be "PASS"
        ($results | Where-Object { $_.ControlId -eq "9.3.10" }).Status | Should -Be "PASS"
    }

    It "returns 9.3.9 PASS / 9.3.10 FAIL for CanNotDelete lock" {
        $pd = New-PD "storage" @($saLock)
        Mock Get-AzStorageBlobServiceProperty { throw "not available" }
        Mock Get-AzStorageFileServiceProperty  { throw "not available" }
        Mock Get-AzStorageAccount              { throw "not available" }
        Mock Get-AzResourceLock {
            @([PSCustomObject]@{
                LockId = "/subscriptions/$($script:T_SID)/providers/Microsoft.Authorization/locks/dellock"
                Level  = "CanNotDelete"
            })
        }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.3.9" }).Status | Should -Be "PASS"
        ($results | Where-Object { $_.ControlId -eq "9.3.10" }).Status | Should -Be "FAIL"
    }

    It "returns FAIL for both when no locks" {
        $pd = New-PD "storage" @($saLock)
        Mock Get-AzStorageBlobServiceProperty { throw "not available" }
        Mock Get-AzStorageFileServiceProperty  { throw "not available" }
        Mock Get-AzStorageAccount              { throw "not available" }
        Mock Get-AzResourceLock { @() }
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
        Mock Get-AzStorageBlobServiceProperty { $script:blobApiCalled = $true }
        Mock Get-AzStorageFileServiceProperty  { throw "not available" }
        Mock Get-AzStorageAccount              { throw "not available" }
        Mock Get-AzResourceLock                { @() }
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
        Mock Get-AzStorageBlobServiceProperty {
            $script:blobApiCalled = $true
            [PSCustomObject]@{
                DeleteRetentionPolicy          = [PSCustomObject]@{ Enabled = $true; Days = 7 }
                ContainerDeleteRetentionPolicy = [PSCustomObject]@{ Enabled = $true; Days = 7 }
                IsVersioningEnabled            = $true
                Logging                        = [PSCustomObject]@{ Read = $true; Write = $true; Delete = $true }
            }
        }
        Mock Get-AzStorageFileServiceProperty  { throw "not available" }
        Mock Get-AzStorageAccount              { throw "not available" }
        Mock Get-AzResourceLock                { @() }
        Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd | Out-Null
        $script:blobApiCalled | Should -BeTrue
    }
}

# =============================================================================
# SUPPRESSIONS — Get-Suppressions, Invoke-Suppressions, Find-SuppressionMatch
# =============================================================================

Describe "Get-Suppressions — file loading and validation" {
    BeforeEach {
        $script:tmpSup = [System.IO.Path]::GetTempFileName()
    }
    AfterEach {
        if (Test-Path $script:tmpSup) { Remove-Item $script:tmpSup -Force }
    }

    It "returns empty array when file does not exist" {
        $result = @(Get-Suppressions -Path "C:\this_path_does_not_exist_xyz123.json")
        $result | Should -HaveCount 0
    }

    It "returns empty array for invalid JSON" {
        Set-Content $script:tmpSup -Value "not: valid: json: {{{" -Encoding UTF8
        $result = @(Get-Suppressions -Path $script:tmpSup)
        $result | Should -HaveCount 0
    }

    It "loads a valid flat-array suppression" {
        $future = [datetime]::Today.AddDays(30).ToString("yyyy-MM-dd")
        Set-Content $script:tmpSup -Value "[{`"control_id`":`"7.1`",`"justification`":`"test`",`"expires`":`"$future`"}]" -Encoding UTF8
        $result = @(Get-Suppressions -Path $script:tmpSup)
        $result | Should -HaveCount 1
        $result[0].ControlId | Should -Be "7.1"
    }

    It "loads a wrapped { suppressions: [...] } format" {
        $future = [datetime]::Today.AddDays(30).ToString("yyyy-MM-dd")
        Set-Content $script:tmpSup -Value "{`"suppressions`":[{`"control_id`":`"5.1`",`"justification`":`"test`",`"expires`":`"$future`"}]}" -Encoding UTF8
        $result = @(Get-Suppressions -Path $script:tmpSup)
        $result | Should -HaveCount 1
        $result[0].ControlId | Should -Be "5.1"
    }

    It "skips entry missing required field control_id" {
        $future = [datetime]::Today.AddDays(30).ToString("yyyy-MM-dd")
        Set-Content $script:tmpSup -Value "[{`"justification`":`"test`",`"expires`":`"$future`"}]" -Encoding UTF8
        $result = @(Get-Suppressions -Path $script:tmpSup)
        $result | Should -HaveCount 0
    }

    It "skips entry missing required field justification" {
        $future = [datetime]::Today.AddDays(30).ToString("yyyy-MM-dd")
        Set-Content $script:tmpSup -Value "[{`"control_id`":`"7.1`",`"expires`":`"$future`"}]" -Encoding UTF8
        $result = @(Get-Suppressions -Path $script:tmpSup)
        $result | Should -HaveCount 0
    }

    It "skips entry missing required field expires" {
        Set-Content $script:tmpSup -Value "[{`"control_id`":`"7.1`",`"justification`":`"test`"}]" -Encoding UTF8
        $result = @(Get-Suppressions -Path $script:tmpSup)
        $result | Should -HaveCount 0
    }

    It "skips entry with invalid expires date format" {
        Set-Content $script:tmpSup -Value "[{`"control_id`":`"7.1`",`"justification`":`"test`",`"expires`":`"31/12/2027`"}]" -Encoding UTF8
        $result = @(Get-Suppressions -Path $script:tmpSup)
        $result | Should -HaveCount 0
    }

    It "skips an expired entry (expires yesterday)" {
        $past = [datetime]::Today.AddDays(-1).ToString("yyyy-MM-dd")
        Set-Content $script:tmpSup -Value "[{`"control_id`":`"7.1`",`"justification`":`"test`",`"expires`":`"$past`"}]" -Encoding UTF8
        $result = @(Get-Suppressions -Path $script:tmpSup)
        $result | Should -HaveCount 0
    }

    It "accepts an entry expiring today (not expired)" {
        $today = [datetime]::Today.ToString("yyyy-MM-dd")
        Set-Content $script:tmpSup -Value "[{`"control_id`":`"7.1`",`"justification`":`"test`",`"expires`":`"$today`"}]" -Encoding UTF8
        $result = @(Get-Suppressions -Path $script:tmpSup)
        $result | Should -HaveCount 1
    }

    It "caps expiry beyond 1 year to today + 365 days" {
        $farFuture = [datetime]::Today.AddDays(400).ToString("yyyy-MM-dd")
        Set-Content $script:tmpSup -Value "[{`"control_id`":`"7.1`",`"justification`":`"test`",`"expires`":`"$farFuture`"}]" -Encoding UTF8
        $result = @(Get-Suppressions -Path $script:tmpSup)
        $result | Should -HaveCount 1
        $result[0].Expires | Should -Be ([datetime]::Today.AddDays(365))
    }

    It "Resource is null when field is absent" {
        $future = [datetime]::Today.AddDays(30).ToString("yyyy-MM-dd")
        Set-Content $script:tmpSup -Value "[{`"control_id`":`"7.1`",`"justification`":`"test`",`"expires`":`"$future`"}]" -Encoding UTF8
        $result = @(Get-Suppressions -Path $script:tmpSup)
        $result[0].Resource | Should -BeNullOrEmpty
    }

    It "Subscription is null when field is absent" {
        $future = [datetime]::Today.AddDays(30).ToString("yyyy-MM-dd")
        Set-Content $script:tmpSup -Value "[{`"control_id`":`"7.1`",`"justification`":`"test`",`"expires`":`"$future`"}]" -Encoding UTF8
        $result = @(Get-Suppressions -Path $script:tmpSup)
        $result[0].Subscription | Should -BeNullOrEmpty
    }

    It "maps resource and subscription when present" {
        $future = [datetime]::Today.AddDays(30).ToString("yyyy-MM-dd")
        Set-Content $script:tmpSup -Value "[{`"control_id`":`"7.1`",`"resource`":`"my-nsg`",`"subscription`":`"Prod`",`"justification`":`"test`",`"expires`":`"$future`"}]" -Encoding UTF8
        $result = @(Get-Suppressions -Path $script:tmpSup)
        $result[0].Resource     | Should -Be "my-nsg"
        $result[0].Subscription | Should -Be "Prod"
    }

    It "returns only valid entries from a mixed list" {
        $future = [datetime]::Today.AddDays(30).ToString("yyyy-MM-dd")
        $past   = [datetime]::Today.AddDays(-1).ToString("yyyy-MM-dd")
        $json   = "[" +
                  "{`"control_id`":`"7.1`",`"justification`":`"valid`",`"expires`":`"$future`"}," +
                  "{`"control_id`":`"7.2`",`"justification`":`"expired`",`"expires`":`"$past`"}," +
                  "{`"justification`":`"missing-id`",`"expires`":`"$future`"}" +
                  "]"
        Set-Content $script:tmpSup -Value $json -Encoding UTF8
        $result = @(Get-Suppressions -Path $script:tmpSup)
        $result | Should -HaveCount 1
        $result[0].ControlId | Should -Be "7.1"
    }
}

Describe "Invoke-Suppressions — matching and status updates" {
    BeforeAll {
        function New-TestResult {
            param(
                [string]$ControlId,
                [string]$Status,
                [string]$Resource    = "",
                [string]$SubName     = "Test Sub"
            )
            [PSCustomObject]@{
                ControlId        = $ControlId
                Title            = "Test Title"
                Level            = 1
                Section          = "7"
                Status           = $Status
                Details          = "original detail"
                Remediation      = "fix it"
                SubscriptionId   = "aaaabbbb-0000-0000-0000-000000000000"
                SubscriptionName = $SubName
                Resource         = $Resource
            }
        }

        function New-TestSup {
            param(
                [string]$ControlId,
                [string]$Resource      = $null,
                [string]$Subscription  = $null,
                [string]$Justification = "accepted risk"
            )
            [PSCustomObject]@{
                ControlId     = $ControlId
                Resource      = $Resource
                Subscription  = $Subscription
                Justification = $Justification
                Expires       = [datetime]::Today.AddDays(30)
            }
        }
    }

    It "returns results unchanged when suppressions list is empty" {
        $results = @(New-TestResult "7.1" $script:FAIL)
        $out = @(Invoke-Suppressions -Results $results -Suppressions @())
        $out | Should -HaveCount 1
        $out[0].Status | Should -Be $script:FAIL
    }

    It "suppresses a FAIL result matching by control_id" {
        $results = @(New-TestResult "7.1" $script:FAIL)
        $sups    = @(New-TestSup "7.1")
        $out = @(Invoke-Suppressions -Results $results -Suppressions $sups)
        $out[0].Status | Should -Be $script:SUPPRESSED
    }

    It "suppresses an ERROR result matching by control_id" {
        $results = @(New-TestResult "7.1" $script:ERR)
        $sups    = @(New-TestSup "7.1")
        $out = @(Invoke-Suppressions -Results $results -Suppressions $sups)
        $out[0].Status | Should -Be $script:SUPPRESSED
    }

    It "does not suppress a PASS result" {
        $results = @(New-TestResult "7.1" $script:PASS)
        $sups    = @(New-TestSup "7.1")
        $out = @(Invoke-Suppressions -Results $results -Suppressions $sups)
        $out[0].Status | Should -Be $script:PASS
    }

    It "does not suppress an INFO result" {
        $results = @(New-TestResult "7.1" $script:INFO)
        $sups    = @(New-TestSup "7.1")
        $out = @(Invoke-Suppressions -Results $results -Suppressions $sups)
        $out[0].Status | Should -Be $script:INFO
    }

    It "does not suppress FAIL when control_id does not match" {
        $results = @(New-TestResult "7.1" $script:FAIL)
        $sups    = @(New-TestSup "9.1")
        $out = @(Invoke-Suppressions -Results $results -Suppressions $sups)
        $out[0].Status | Should -Be $script:FAIL
    }

    It "suppresses FAIL when resource filter matches" {
        $results = @(New-TestResult "7.1" $script:FAIL -Resource "my-nsg")
        $sups    = @(New-TestSup "7.1" -Resource "my-nsg")
        $out = @(Invoke-Suppressions -Results $results -Suppressions $sups)
        $out[0].Status | Should -Be $script:SUPPRESSED
    }

    It "does not suppress FAIL when resource filter does not match" {
        $results = @(New-TestResult "7.1" $script:FAIL -Resource "other-nsg")
        $sups    = @(New-TestSup "7.1" -Resource "my-nsg")
        $out = @(Invoke-Suppressions -Results $results -Suppressions $sups)
        $out[0].Status | Should -Be $script:FAIL
    }

    It "resource filter match is case-insensitive" {
        $results = @(New-TestResult "7.1" $script:FAIL -Resource "MY-NSG")
        $sups    = @(New-TestSup "7.1" -Resource "my-nsg")
        $out = @(Invoke-Suppressions -Results $results -Suppressions $sups)
        $out[0].Status | Should -Be $script:SUPPRESSED
    }

    It "suppresses FAIL when subscription filter matches" {
        $results = @(New-TestResult "7.1" $script:FAIL -SubName "Production")
        $sups    = @(New-TestSup "7.1" -Subscription "Production")
        $out = @(Invoke-Suppressions -Results $results -Suppressions $sups)
        $out[0].Status | Should -Be $script:SUPPRESSED
    }

    It "does not suppress FAIL when subscription filter does not match" {
        $results = @(New-TestResult "7.1" $script:FAIL -SubName "Development")
        $sups    = @(New-TestSup "7.1" -Subscription "Production")
        $out = @(Invoke-Suppressions -Results $results -Suppressions $sups)
        $out[0].Status | Should -Be $script:FAIL
    }

    It "subscription filter match is case-insensitive" {
        $results = @(New-TestResult "7.1" $script:FAIL -SubName "PRODUCTION")
        $sups    = @(New-TestSup "7.1" -Subscription "production")
        $out = @(Invoke-Suppressions -Results $results -Suppressions $sups)
        $out[0].Status | Should -Be $script:SUPPRESSED
    }

    It "suppression without resource filter matches any resource" {
        $results = @(New-TestResult "7.1" $script:FAIL -Resource "some-nsg")
        $sups    = @(New-TestSup "7.1")   # no Resource filter
        $out = @(Invoke-Suppressions -Results $results -Suppressions $sups)
        $out[0].Status | Should -Be $script:SUPPRESSED
    }

    It "appends justification and expiry to Details" {
        $results = @(New-TestResult "7.1" $script:FAIL)
        $sups    = @(New-TestSup "7.1" -Justification "WAF in front")
        $out = @(Invoke-Suppressions -Results $results -Suppressions $sups)
        $out[0].Details | Should -Match "WAF in front"
        $out[0].Details | Should -Match "expires"
    }

    It "preserves all other result fields when suppressing" {
        $results = @(New-TestResult "7.1" $script:FAIL -Resource "nsg-1" -SubName "Prod")
        $sups    = @(New-TestSup "7.1")
        $out = @(Invoke-Suppressions -Results $results -Suppressions $sups)
        $out[0].ControlId        | Should -Be "7.1"
        $out[0].Title            | Should -Be "Test Title"
        $out[0].Resource         | Should -Be "nsg-1"
        $out[0].SubscriptionName | Should -Be "Prod"
    }

    It "only suppresses matched results in a mixed list" {
        $results = @(
            (New-TestResult "7.1" $script:FAIL),
            (New-TestResult "8.1" $script:FAIL),
            (New-TestResult "9.1" $script:PASS)
        )
        $sups = @(New-TestSup "7.1")
        $out = @(Invoke-Suppressions -Results $results -Suppressions $sups)
        $out | Should -HaveCount 3
        ($out | Where-Object { $_.ControlId -eq "7.1" }).Status | Should -Be $script:SUPPRESSED
        ($out | Where-Object { $_.ControlId -eq "8.1" }).Status | Should -Be $script:FAIL
        ($out | Where-Object { $_.ControlId -eq "9.1" }).Status | Should -Be $script:PASS
    }
}
