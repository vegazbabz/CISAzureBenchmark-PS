#Requires -Version 7.0
<#
.SYNOPSIS
    Pure helpers: NSG rule parsing, sort keys, result factories, control catalog, scoring, error classifiers, retry/paging, manifest consistency, prefetch plumbing.
    Split from the former Tests\Checks.Tests.ps1 monolith; shared fixtures and the
    hermetic default mocks live in Tests\TestHelpers.ps1.
#>

param()

BeforeAll {
    . (Join-Path $PSScriptRoot "TestHelpers.ps1")
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
        $r = New-ErrorResult "1.1" "Some error message" -Title "Title" -Level 1 -Section "Section"
        $r.Status | Should -Be "ERROR"
    }

    It "truncates long messages to ~220 chars" {
        $long = "A" * 300
        $r = New-ErrorResult "1.1" $long -Title "T" -Level 1 -Section "S"
        $r.Details.Length | Should -BeLessOrEqual 225
    }
}

Describe "New-InfoResult" {
    It "creates an INFO status result" {
        $r = New-InfoResult "7.1" "No NSGs found."
        $r.Status  | Should -Be "INFO"
        $r.Details | Should -Be "No NSGs found."
    }
}

Describe "Control catalog (Get-ControlMeta)" {
    It "resolves title, level, and section for a known control" {
        $m = Get-ControlMeta -ControlId "9.2.3"
        $m.Title   | Should -Be "Ensure 'Versioning' is Set to 'Enabled' on Azure Blob Storage Storage Accounts"
        $m.Level   | Should -Be 2
        $m.Section | Should -Be "9 - Storage Services"
    }

    It "throws on an unknown control id" {
        { Get-ControlMeta -ControlId "99.99" } | Should -Throw "*not in the catalog*"
    }

    It "has 127 controls, each with a non-empty title, a valid level, and a known section" {
        $script:CONTROLS.Count | Should -Be 127
        foreach ($id in $script:CONTROLS.Keys) {
            $m = Get-ControlMeta -ControlId $id
            $m.Title   | Should -Not -BeNullOrEmpty -Because "control $id needs a title"
            $m.Level   | Should -BeIn @(1, 2) -Because "control $id needs level 1 or 2"
            $m.Section | Should -Not -BeNullOrEmpty -Because "control $id needs a section"
            $m.Page    | Should -BeGreaterThan 20 -Because "control $id needs its CIS v6.0.0 PDF page"
            $m.Page    | Should -BeLessThan 552 -Because "the v6.0.0 PDF has 551 pages"
        }
    }

    It "benchmark page references match the v6.0.0 PDF for known controls" {
        (Get-ControlMeta -ControlId "2.1.1").Page  | Should -Be 27
        (Get-ControlMeta -ControlId "5.4").Page    | Should -Be 104
        (Get-ControlMeta -ControlId "8.3.6").Page  | Should -Be 378
        (Get-ControlMeta -ControlId "9.3.11").Page | Should -Be 481
    }

    It "benchmark pages ascend with control order within each section" {
        $ordered = $script:CONTROLS.Keys | Sort-Object { Get-ControlSortKey $_ }
        $prev = $null
        foreach ($id in $ordered) {
            $cur = Get-ControlMeta -ControlId $id
            if ($prev -and $prev.Section -eq $cur.Section) {
                $cur.Page | Should -BeGreaterOrEqual $prev.Page -Because "control $id cannot precede $($prev.ControlId) in the PDF"
            }
            $prev = $cur
        }
    }

    It "matches the control inventory documented in the README" {
        $readme = Get-Content (Join-Path (Split-Path $PSScriptRoot -Parent) "README.md") -Raw
        $readmeIds = [regex]::Matches($readme, '(?m)^\|\s*`?(\d+(?:\.\d+)+)`?\s*\|') |
            ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique
        $catalogIds = @($script:CONTROLS.Keys | Sort-Object)
        $missingFromCatalog = @($readmeIds  | Where-Object { $_ -notin $catalogIds })
        $missingFromReadme  = @($catalogIds | Where-Object { $_ -notin $readmeIds })
        $missingFromCatalog | Should -BeNullOrEmpty -Because "every README control needs a catalog entry"
        $missingFromReadme  | Should -BeNullOrEmpty -Because "every catalog control should be documented in the README"
    }

    It "New-CISResult resolves metadata from the catalog when only the id is given" {
        $r = New-CISResult -ControlId "8.3.5" -Status "PASS"
        $r.Title   | Should -Be "Ensure 'Purge protection' is Set to 'Enabled'"
        $r.Level   | Should -Be 1
        $r.Section | Should -Be "8 - Security Services"
    }

    It "explicit metadata still overrides the catalog" {
        $r = New-CISResult -ControlId "8.3.5" -Status "PASS" -Title "Custom" -Level 2 -Section "X"
        $r.Title   | Should -Be "Custom"
        $r.Level   | Should -Be 2
        $r.Section | Should -Be "X"
    }
}

Describe "Add-ClassifiedErrorSet" {
    BeforeEach {
        $script:ces = [System.Collections.Generic.List[object]]::new()
    }

    It "emits INFO for every control on a not-applicable error when a message is provided" {
        Add-ClassifiedErrorSet -Results $script:ces -ControlIds @("9.2.1","9.2.2","9.2.3") `
            -Message "Blob service is not supported for this account type." `
            -NotApplicableMessage "Blob service not supported." -Resource "sa1"
        $script:ces.Count | Should -Be 3
        $script:ces | ForEach-Object {
            $_.Status  | Should -Be "INFO"
            $_.Details | Should -Be "Blob service not supported."
        }
    }

    It "emits ERROR with the authz remediation on an authorization error" {
        Add-ClassifiedErrorSet -Results $script:ces -ControlIds @("8.3.1") `
            -Message "Operation returned Forbidden" `
            -AuthzMessage "Grant Key Vault Reader." -Resource "kv1"
        $script:ces[0].Status  | Should -Be "ERROR"
        $script:ces[0].Details | Should -Be "Grant Key Vault Reader."
    }

    It "classifies the real Key Vault firewall message as firewall, not authz" {
        Add-ClassifiedErrorSet -Results $script:ces -ControlIds @("8.3.1") `
            -Message "Client address is not authorized and caller is not a trusted service" `
            -AuthzMessage "Grant Key Vault Reader." -FirewallMessage "Add IP to the vault firewall allowlist." -Resource "kv1"
        $script:ces[0].Status  | Should -Be "ERROR"
        # Format-AzErrorMessage normalizes firewall-flavored text into its canned guidance —
        # the point here is the classification: firewall wording, not the authz message.
        $script:ces[0].Details | Should -Match "Network access blocked"
        $script:ces[0].Details | Should -Not -Match "Key Vault Reader"
    }

    It "falls back to the raw message for unclassified errors and fills metadata from the catalog" {
        Add-ClassifiedErrorSet -Results $script:ces -ControlIds @("9.1.1") `
            -Message "Something completely unexpected happened" -Resource "sa1"
        $script:ces[0].Status  | Should -Be "ERROR"
        $script:ces[0].Details | Should -Match "unexpected"
        $script:ces[0].Title   | Should -Be "Ensure Soft Delete for Azure File Shares is Enabled"
        $script:ces[0].Level   | Should -Be 1
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

Describe "Scoring — Get-AuditCounts / Get-AssessedCount / Get-AuditScore" {
    BeforeAll {
        function New-StatusResult { param([string]$Status, [int]$Level = 1)
            [PSCustomObject]@{ Status = $Status; Level = $Level }
        }
    }

    It "counts every status and ignores unknown ones" {
        $results = @(
            (New-StatusResult PASS), (New-StatusResult PASS), (New-StatusResult FAIL),
            (New-StatusResult ERROR), (New-StatusResult INFO), (New-StatusResult MANUAL),
            (New-StatusResult SUPPRESSED), (New-StatusResult BOGUS)
        )
        $counts = Get-AuditCounts -Results $results
        $counts.PASS       | Should -Be 2
        $counts.FAIL       | Should -Be 1
        $counts.ERROR      | Should -Be 1
        $counts.INFO       | Should -Be 1
        $counts.MANUAL     | Should -Be 1
        $counts.SUPPRESSED | Should -Be 1
    }

    It "returns all-zero counts for an empty result set" {
        $counts = Get-AuditCounts -Results @()
        ($counts.Values | Measure-Object -Sum).Sum | Should -Be 0
    }

    It "assessed = PASS + FAIL + ERROR, excluding INFO/MANUAL/SUPPRESSED" {
        $counts = @{ PASS = 3; FAIL = 2; ERROR = 1; INFO = 9; MANUAL = 9; SUPPRESSED = 9 }
        Get-AssessedCount -Counts $counts | Should -Be 6
    }

    It "score treats ERROR as failing" {
        # 8 PASS / (8+1+1) assessed = 80.0 — ERROR pulls the score down like FAIL
        Get-AuditScore -Counts @{ PASS = 8; FAIL = 1; ERROR = 1 } | Should -Be 80.0
    }

    It "score rounds to one decimal" {
        Get-AuditScore -Counts @{ PASS = 1; FAIL = 2; ERROR = 0 } | Should -Be 33.3
    }

    It "score is 0 when nothing was assessed" {
        Get-AuditScore -Counts @{ PASS = 0; FAIL = 0; ERROR = 0; INFO = 5; MANUAL = 3 } | Should -Be 0
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

Describe "Invoke-AzRestPaged" {
    It "follows ARM 'nextLink' continuation and accumulates all pages" {
        Mock Invoke-ArmRest {
            if ($Uri -eq 'https://management/page2') {
                [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @(3) }; Error = $null }
            } else {
                [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @(1, 2); nextLink = 'https://management/page2' }; Error = $null }
            }
        }
        $r = Invoke-AzRestPaged -Uri 'https://management/page1'
        $r.Success       | Should -BeTrue
        @($r.Data).Count | Should -Be 3
        Should -Invoke Invoke-ArmRest -Times 2 -Exactly
    }

    It "follows Microsoft Graph '@odata.nextLink' continuation" {
        Mock Invoke-ArmRest {
            if ($Uri -eq 'https://graph/page2') {
                [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @([PSCustomObject]@{ id = 'u3' }) }; Error = $null }
            } else {
                [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{
                    value = @([PSCustomObject]@{ id = 'u1' }, [PSCustomObject]@{ id = 'u2' })
                    '@odata.nextLink' = 'https://graph/page2'
                }; Error = $null }
            }
        }
        $r = Invoke-AzRestPaged -Uri 'https://graph/page1'
        $r.Success       | Should -BeTrue
        @($r.Data).Count | Should -Be 3
        Should -Invoke Invoke-ArmRest -Times 2 -Exactly
    }

    It "stops when the continuation link is present but empty" {
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @(1); nextLink = '' }; Error = $null } }
        $r = Invoke-AzRestPaged -Uri 'https://management/only'
        @($r.Data).Count | Should -Be 1
        Should -Invoke Invoke-ArmRest -Times 1 -Exactly
    }

    It "propagates a failed page as failure" {
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $false; Data = $null; Error = 'boom' } }
        $r = Invoke-AzRestPaged -Uri 'https://management/x'
        $r.Success | Should -BeFalse
        $r.Error   | Should -Be 'boom'
    }
}

Describe "Error classifiers — firewall vs authorization" {
    It "classifies the Key Vault firewall-block message as firewall, not authorization" {
        $msg = "Client address is not authorized and caller is not a trusted service. Client address: 1.2.3.4"
        Test-FirewallError $msg | Should -BeTrue
        Test-AuthzError $msg    | Should -BeFalse
    }

    It "still classifies plain authorization failures as authorization" {
        $msg = "The client does not have authorization to perform action"
        Test-AuthzError $msg    | Should -BeTrue
        Test-FirewallError $msg | Should -BeFalse
    }
}


# ══════════════════════════════════════════════════════════════════════════════
# Prefetch failure propagation — unreadable data must become ERROR, never PASS/INFO
# ══════════════════════════════════════════════════════════════════════════════

Describe "Get-PrefetchError" {
    It "returns the error message for a failed prefetch key" {
        $pd = @{ nsgs = @{ __error = "Graph query throttled" } }
        Get-PrefetchError -PrefetchData $pd -Key "nsgs" | Should -Be "Graph query throttled"
    }
    It "returns null for a successful prefetch key" {
        $pd = New-PD "nsgs" @()
        Get-PrefetchError -PrefetchData $pd -Key "nsgs" | Should -BeNullOrEmpty
    }
    It "returns null for a missing key" {
        Get-PrefetchError -PrefetchData @{} -Key "nsgs" | Should -BeNullOrEmpty
    }
    It "Get-PrefetchData returns empty array for a failed key" {
        $pd = @{ nsgs = @{ __error = "boom" } }
        @(Get-PrefetchData -PrefetchData $pd -Key "nsgs" -SubscriptionId $script:T_SID) | Should -HaveCount 0
    }
}

Describe "Prefetch failure propagation" {
    It "Section 2: databricks prefetch failure yields ERROR for all six automated controls" {
        $pd = @{ databricks = @{ __error = "access denied" } }
        $r = @(Invoke-Section2Checks -SubscriptionId $script:T_SID -SubscriptionName $script:T_SNAME -PrefetchData $pd)
        $r | Should -HaveCount 6
        @($r | Where-Object { $_.Status -ne $script:ERR }) | Should -HaveCount 0
        (@($r.ControlId) | Sort-Object) -join "," | Should -Be "2.1.1,2.1.10,2.1.11,2.1.2,2.1.7,2.1.9"
    }

    It "Section 5: 5.3.3 emits ERROR when roles prefetch failed" {
        $pd = @{ roles = @{ __error = "throttled" } }
        $r = Invoke-Check5_3_3 -SubscriptionId $script:T_SID -SubscriptionName $script:T_SNAME -PrefetchData $pd
        $r.Status | Should -Be $script:ERR
    }

    It "Section 5: 5.7 emits ERROR when roles prefetch failed" {
        $pd = @{ roles = @{ __error = "throttled" } }
        $r = Invoke-Check5_7 -SubscriptionId $script:T_SID -SubscriptionName $script:T_SNAME -PrefetchData $pd
        $r.Status | Should -Be $script:ERR
    }

    It "Section 7: NSG prefetch failure yields ERROR (not INFO) for 7.1-7.4" {
        $pd = @{ nsgs = @{ __error = "graph query failed" } }
        $r = @(Invoke-Section7Checks -SubscriptionId $script:T_SID -SubscriptionName $script:T_SNAME -PrefetchData $pd)
        foreach ($cid in @("7.1","7.2","7.3","7.4")) {
            @($r | Where-Object { $_.ControlId -eq $cid -and $_.Status -eq $script:ERR }) | Should -HaveCount 1 -Because "control $cid must be ERROR"
        }
    }

    It "Section 8: Key Vault prefetch failure yields ERROR for the 8.3.x block" {
        $pd = @{ keyvaults = @{ __error = "forbidden" } }
        $r = @(Invoke-Section8Checks -SubscriptionId $script:T_SID -SubscriptionName $script:T_SNAME -PrefetchData $pd)
        $kvResults = @($r | Where-Object { $_.ControlId -like "8.3.*" })
        $kvResults.Count | Should -BeGreaterThan 0
        @($kvResults | Where-Object { $_.Status -ne $script:ERR }) | Should -HaveCount 0
    }

    It "Section 9: storage prefetch failure with no direct fallback yields ERROR for all 21 controls" {
        Mock Get-AzStorageAccount { @() }
        $pd = @{ storage = @{ __error = "resource graph unavailable" } }
        $r = @(Invoke-Section9Checks -SubscriptionId $script:T_SID -SubscriptionName $script:T_SNAME -PrefetchData $pd)
        $r | Should -HaveCount 21
        @($r | Where-Object { $_.Status -ne $script:ERR }) | Should -HaveCount 0
    }

    It "Section 9: storage prefetch failure recovers via direct fallback read" {
        Mock Get-AzStorageAccount {
            [PSCustomObject]@{
                Id = "/subscriptions/$($script:T_SID)/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa1"
                StorageAccountName = "sa1"; ResourceGroupName = "rg"
                EnableHierarchicalNamespace = $false
                Sku = [PSCustomObject]@{ Name = "Standard_LRS" }
            }
        }
        $pd = @{ storage = @{ __error = "resource graph unavailable" } }
        $r = @(Invoke-Section9Checks -SubscriptionId $script:T_SID -SubscriptionName $script:T_SNAME -PrefetchData $pd)
        # Fallback read succeeded — results must be evaluated per-account, not blanket ERROR
        @($r | Where-Object { $_.Details -match "Storage prefetch failed" }) | Should -HaveCount 0
    }
}
