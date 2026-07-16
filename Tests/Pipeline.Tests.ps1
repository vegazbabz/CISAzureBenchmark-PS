#Requires -Version 7.0
<#
.SYNOPSIS
    Report/summary pipeline: SARIF export, Complete-AuditRun tail, suppressions, run history.
    Split from the former Tests\Checks.Tests.ps1 monolith; shared fixtures and the
    hermetic default mocks live in Tests\TestHelpers.ps1.
#>

param()

BeforeAll {
    . (Join-Path $PSScriptRoot "TestHelpers.ps1")
}

Describe "New-CISSarifReport" {
    BeforeAll {
        function New-SarifTestResults {
            @(
                New-CISResult -ControlId "8.3.1" -Title "Key Vault RBAC" -Level 1 -Section "8 Key Vault" `
                    -Status "FAIL" -Details "Vault kv1 uses access policies." -Remediation "Migrate to RBAC." `
                    -SubscriptionId "sub-1" -SubscriptionName "Prod" -Resource "kv1"
                New-CISResult -ControlId "8.3.1" -Title "Key Vault RBAC" -Level 1 -Section "8 Key Vault" `
                    -Status "FAIL" -Details "Vault kv2 uses access policies." -Remediation "Migrate to RBAC." `
                    -SubscriptionId "sub-1" -SubscriptionName "Prod" -Resource "kv2"
                New-CISResult -ControlId "5.6" -Title "Transfer policy" -Level 2 -Section "5 Identity" `
                    -Status "ERROR" -Details "Could not read policy." -SubscriptionId "sub-1" -SubscriptionName "Prod"
                New-CISResult -ControlId "9.3.4" -Title "Secure transfer" -Level 1 -Section "9 Storage" `
                    -Status "PASS" -SubscriptionId "sub-1" -SubscriptionName "Prod" -Resource "sa1"
                New-CISResult -ControlId "5.1.4" -Title "Remember MFA" -Level 1 -Section "5 Identity" -Status "MANUAL"
                New-CISResult -ControlId "7.1" -Title "RDP restricted" -Level 1 -Section "7 Network" `
                    -Status "SUPPRESSED" -Details "Open RDP. [Accepted risk: jumpbox — expires 2026-12-01]" `
                    -SubscriptionId "sub-1" -SubscriptionName "Prod" -Resource "nsg1"
            )
        }
        function Get-SarifLog([object[]]$Results) {
            $path = Join-Path $TestDrive "out.sarif"
            $null = New-CISSarifReport -Results $Results -OutputPath $path
            Get-Content $path -Raw | ConvertFrom-Json
        }
    }

    It "emits a valid SARIF 2.1.0 envelope with tool metadata" {
        $log = Get-SarifLog (New-SarifTestResults)
        $log.version | Should -Be "2.1.0"
        $log.'$schema' | Should -Match 'sarif-2\.1\.0'
        $log.runs.Count | Should -Be 1
        $log.runs[0].tool.driver.name    | Should -Be "CISAzureBenchmark"
        $log.runs[0].tool.driver.version | Should -Be $script:CIS_VERSION
        $log.runs[0].tool.driver.properties.benchmarkVersion | Should -Be $script:BENCHMARK_VER
    }

    It "maps FAIL to error and ERROR to warning; excludes PASS and MANUAL" {
        $log = Get-SarifLog (New-SarifTestResults)
        $results = @($log.runs[0].results)
        $results.Count | Should -Be 4
        @($results | Where-Object ruleId -eq "8.3.1").level | Should -Be @("error", "error")
        @($results | Where-Object ruleId -eq "5.6").level   | Should -Be "warning"
        @($results | Where-Object ruleId -eq "9.3.4").Count | Should -Be 0
        @($results | Where-Object ruleId -eq "5.1.4").Count | Should -Be 0
    }

    It "emits one rule per control with title and remediation, referenced by ruleIndex" {
        $log   = Get-SarifLog (New-SarifTestResults)
        $rules = @($log.runs[0].tool.driver.rules)
        @($rules | Where-Object id -eq "8.3.1").Count | Should -Be 1
        $kvRule = $rules | Where-Object id -eq "8.3.1"
        $kvRule.shortDescription.text | Should -Be "Key Vault RBAC"
        $kvRule.help.text             | Should -Be "Migrate to RBAC."
        $kvRule.properties.section    | Should -Be "8 Key Vault"
        foreach ($r in @($log.runs[0].results)) {
            $rules[$r.ruleIndex].id | Should -Be $r.ruleId
        }
    }

    It "marks SUPPRESSED results as note-level with a SARIF suppression" {
        $log = Get-SarifLog (New-SarifTestResults)
        $sup = @($log.runs[0].results) | Where-Object ruleId -eq "7.1"
        $sup.level | Should -Be "note"
        $sup.suppressions[0].kind | Should -Be "external"
        $sup.suppressions[0].justification | Should -Match "Accepted risk"
    }

    It "gives every result a physical location and a stable fingerprint" {
        $log = Get-SarifLog (New-SarifTestResults)
        foreach ($r in @($log.runs[0].results)) {
            $r.locations[0].physicalLocation.artifactLocation.uri | Should -Not -BeNullOrEmpty
            $r.locations[0].physicalLocation.region.startLine     | Should -Be 1
            $r.partialFingerprints.cisResultKey | Should -Match "^$([regex]::Escape($r.ruleId))\|"
        }
        $tenantLevel = @($log.runs[0].results) | Where-Object ruleId -eq "5.6"
        $tenantLevel.locations[0].physicalLocation.artifactLocation.uri | Should -Be "azure/sub-1"
    }

    It "writes an empty results array when there are no findings" {
        $pass = @(New-CISResult -ControlId "1.1" -Title "T" -Level 1 -Section "S" -Status "PASS")
        $log = Get-SarifLog $pass
        @($log.runs[0].results).Count | Should -Be 0
        @($log.runs[0].tool.driver.rules).Count | Should -Be 0
    }
}

Describe "Complete-AuditRun (shared report/summary tail)" {
    BeforeAll {
        function New-TailFixtureResults {
            @(
                (New-CISResult -ControlId "8.3.5" -Status "PASS" -Details "ok"   -SubscriptionId "sub1" -SubscriptionName "Sub One" -Resource "kv1"),
                (New-CISResult -ControlId "8.3.6" -Status "FAIL" -Details "bad"  -SubscriptionId "sub1" -SubscriptionName "Sub One" -Resource "kv1"),
                (New-CISResult -ControlId "8.3.6" -Status "FAIL" -Details "bad"  -SubscriptionId "sub1" -SubscriptionName "Sub One" -Resource "kv1"),  # duplicate
                (New-CISResult -ControlId "8.3.8" -Status "MANUAL" -Details "l2" -SubscriptionId "sub1" -SubscriptionName "Sub One" -Resource "kv1")   # Level 2 from catalog
            )
        }
        function Invoke-TailFixture {
            param([hashtable]$ExtraArgs = @{})
            $outPath = Join-Path $TestDrive ("report_{0}.html" -f ([guid]::NewGuid().ToString('N')))
            $tailParams = @{
                Results          = New-TailFixtureResults
                OutputPath       = $outPath
                SuppressionsFile = (Join-Path $TestDrive "no-suppressions.json")
                Level            = "both"
                ScopeLabel       = "Test scope"
                Tenant           = "tenant-id"
                CallerName       = "tester@example.com"
                CallerType       = "User"
                SubscriptionNames = @("Sub One")
                SubscriptionCount = 1
                NoOpen           = $true
            }
            foreach ($k in $ExtraArgs.Keys) { $tailParams[$k] = $ExtraArgs[$k] }
            Complete-AuditRun @tailParams
        }
    }

    It "writes the report, dedupes, and returns a typed summary" {
        $summary = Invoke-TailFixture
        $summary.PSObject.TypeNames | Should -Contain 'CISAzureBenchmark.AuditSummary'
        Test-Path $summary.ReportPath | Should -BeTrue
        # 4 raw results, 1 exact duplicate removed
        $summary.Results.Count | Should -Be 3
        $summary.Counts.PASS   | Should -Be 1
        $summary.Counts.FAIL   | Should -Be 1
        $summary.Score         | Should -Be 50.0
        $summary.SubscriptionCount | Should -Be 1
    }

    It "sets exit code 2 only when -SetExitCode is passed and FAIL/ERROR exist" {
        (Invoke-TailFixture).ExitCode | Should -Be 0
        (Invoke-TailFixture -ExtraArgs @{ SetExitCode = $true }).ExitCode | Should -Be 2
    }

    It "applies the level filter" {
        $summary = Invoke-TailFixture -ExtraArgs @{ Level = "1" }
        # 8.3.6 and 8.3.8 are Level 2 in the catalog — only 8.3.5 (L1) survives
        @($summary.Results | Where-Object { $_.Level -eq 2 }).Count | Should -Be 0
        $summary.Results.Count | Should -Be 1
    }

    It "appends a history entry only when -AppendHistory is passed" {
        $s1 = Invoke-TailFixture
        Test-Path (Get-HistoryPathFor -OutputPath $s1.ReportPath) | Should -BeFalse
        $s2 = Invoke-TailFixture -ExtraArgs @{ AppendHistory = $true; HistorySubscriptionIds = @("sub1") }
        $historyPath = Get-HistoryPathFor -OutputPath $s2.ReportPath
        Test-Path $historyPath | Should -BeTrue
        $entries = @(Get-Content $historyPath -Raw | ConvertFrom-Json)
        $entries.Count | Should -BeGreaterOrEqual 1
        $entries[-1].fail | Should -Be 1
    }

    It "writes a .diff.json and renders the diff section when -CompareWith is passed" {
        # Baseline: 8.3.5 was FAIL (now PASS = improvement), 8.3.6 was PASS (now FAIL =
        # regression), plus a control that no longer exists (removed). 8.3.8 is new.
        $baseline = Join-Path $TestDrive "baseline.json"
        ConvertTo-Json -InputObject @(
            [ordered]@{ control = "8.3.5"; title = "t"; level = 1; subscription = "Sub One"; resource = "kv1"; status = "FAIL"; details = "was bad" }
            [ordered]@{ control = "8.3.6"; title = "t"; level = 2; subscription = "Sub One"; resource = "kv1"; status = "PASS"; details = "was ok" }
            [ordered]@{ control = "6.4";   title = "t"; level = 1; subscription = "Sub One"; resource = "";    status = "PASS"; details = "retired" }
        ) | Set-Content (Join-Path $TestDrive "baseline.json") -Encoding UTF8

        $summary  = Invoke-TailFixture -ExtraArgs @{ CompareWith = $baseline }
        $diffPath = [System.IO.Path]::ChangeExtension($summary.ReportPath, '.diff.json')
        Test-Path $diffPath | Should -BeTrue

        $diff = Get-Content $diffPath -Raw | ConvertFrom-Json
        $diff.counts.regressions  | Should -Be 1
        $diff.counts.improvements | Should -Be 1
        $diff.counts.new          | Should -Be 1
        $diff.counts.removed      | Should -Be 1
        $diff.regressions[0].control        | Should -Be "8.3.6"
        $diff.regressions[0].previousStatus | Should -Be "PASS"
        $diff.improvements[0].control       | Should -Be "8.3.5"
        $diff.new[0].control                | Should -Be "8.3.8"
        $diff.removed[0].control            | Should -Be "6.4"

        (Get-Content $summary.ReportPath -Raw) | Should -Match "Changes vs previous run"
    }

    It "skips the diff without failing when the -CompareWith baseline does not exist" {
        $summary  = Invoke-TailFixture -ExtraArgs @{ CompareWith = (Join-Path $TestDrive "missing.json") }
        $diffPath = [System.IO.Path]::ChangeExtension($summary.ReportPath, '.diff.json')
        Test-Path $diffPath | Should -BeFalse
        $summary.ExitCode | Should -Be 0
        (Get-Content $summary.ReportPath -Raw) | Should -Not -Match "Changes vs previous run"
    }
}

Describe "Get-RunDiff — run-to-run classification" {
    BeforeAll {
        function New-DiffCurrent {
            param([string]$Cid, [string]$Status, [string]$Resource = "r1", [string]$Sub = "Prod")
            New-CISResult -ControlId $Cid -Title "T $Cid" -Level 1 -Section "S" -Status $Status `
                -Details "d" -SubscriptionId "sub-1" -SubscriptionName $Sub -Resource $Resource
        }
        function New-DiffPrevious {
            param([string]$Cid, [string]$Status, [string]$Resource = "r1", [string]$Sub = "Prod")
            [PSCustomObject]@{ control = $Cid; title = "T $Cid"; level = 1; subscription = $Sub; resource = $Resource; status = $Status; details = "d" }
        }
    }

    It "classifies PASS-to-FAIL as a regression and FAIL-to-PASS as an improvement" {
        $diff = Get-RunDiff `
            -CurrentResults @((New-DiffCurrent "1.1" "FAIL"), (New-DiffCurrent "1.2" "PASS")) `
            -PreviousResults @((New-DiffPrevious "1.1" "PASS"), (New-DiffPrevious "1.2" "FAIL"))
        $diff.Regressions.Count  | Should -Be 1
        $diff.Regressions[0].control | Should -Be "1.1"
        $diff.Regressions[0].previousStatus | Should -Be "PASS"
        $diff.Improvements.Count | Should -Be 1
        $diff.Improvements[0].control | Should -Be "1.2"
    }

    It "treats a new ERROR as a regression (ERROR counts as failing)" {
        $diff = Get-RunDiff `
            -CurrentResults @((New-DiffCurrent "1.1" "ERROR")) `
            -PreviousResults @((New-DiffPrevious "1.1" "MANUAL"))
        $diff.Regressions.Count | Should -Be 1
    }

    It "does not report unchanged results or FAIL/ERROR swaps" {
        $diff = Get-RunDiff `
            -CurrentResults @((New-DiffCurrent "1.1" "FAIL"), (New-DiffCurrent "1.2" "PASS")) `
            -PreviousResults @((New-DiffPrevious "1.1" "ERROR"), (New-DiffPrevious "1.2" "PASS"))
        $diff.Regressions.Count  | Should -Be 0
        $diff.Improvements.Count | Should -Be 0
        $diff.New.Count          | Should -Be 0
        $diff.Removed.Count      | Should -Be 0
    }

    It "reports results only in the current run as new and only in the previous run as removed" {
        $diff = Get-RunDiff `
            -CurrentResults @((New-DiffCurrent "1.1" "PASS" -Resource "r-new")) `
            -PreviousResults @((New-DiffPrevious "1.1" "PASS" -Resource "r-old"))
        $diff.New.Count     | Should -Be 1
        $diff.New[0].resource | Should -Be "r-new"
        $diff.Removed.Count | Should -Be 1
        $diff.Removed[0].resource | Should -Be "r-old"
        $diff.Removed[0].previousStatus | Should -Be "PASS"
    }

    It "keys on control, subscription and resource — same control in another subscription is distinct" {
        $diff = Get-RunDiff `
            -CurrentResults @((New-DiffCurrent "1.1" "FAIL" -Sub "Staging")) `
            -PreviousResults @((New-DiffPrevious "1.1" "PASS" -Sub "Prod"))
        $diff.Regressions.Count | Should -Be 0
        $diff.New.Count     | Should -Be 1
        $diff.Removed.Count | Should -Be 1
    }

    It "handles empty runs on either side" {
        $diff = Get-RunDiff -CurrentResults @() -PreviousResults @((New-DiffPrevious "1.1" "PASS"))
        $diff.Removed.Count | Should -Be 1
        $diff = Get-RunDiff -CurrentResults @((New-DiffCurrent "1.1" "PASS")) -PreviousResults @()
        $diff.New.Count | Should -Be 1
    }
}

Describe "Find-PreviousReportJson — 'auto' baseline discovery" {
    It "picks the newest report JSON, ignoring history, diff and suppressions files" {
        $dir = Join-Path $TestDrive "autodiff"
        $null = New-Item -ItemType Directory -Path $dir
        Set-Content (Join-Path $dir "cis_audit_report_old.json")  -Value "[]" -Encoding UTF8
        Set-Content (Join-Path $dir "cis_audit_report_new.json")  -Value "[]" -Encoding UTF8
        Set-Content (Join-Path $dir "cis_run_history.json")       -Value "[]" -Encoding UTF8
        Set-Content (Join-Path $dir "cis_audit_report_old.diff.json") -Value "{}" -Encoding UTF8
        Set-Content (Join-Path $dir "suppressions.json")          -Value "[]" -Encoding UTF8
        # Ensure a strict ordering regardless of filesystem timestamp resolution
        (Get-Item (Join-Path $dir "cis_audit_report_new.json")).LastWriteTimeUtc = [DateTime]::UtcNow
        (Get-Item (Join-Path $dir "cis_audit_report_old.json")).LastWriteTimeUtc = [DateTime]::UtcNow.AddMinutes(-5)

        $found = Find-PreviousReportJson -OutputPath (Join-Path $dir "cis_audit_report_current.html")
        Split-Path $found -Leaf | Should -Be "cis_audit_report_new.json"
    }

    It "excludes the current run's own JSON and returns null when nothing remains" {
        $dir = Join-Path $TestDrive "autodiff2"
        $null = New-Item -ItemType Directory -Path $dir
        Set-Content (Join-Path $dir "report.json") -Value "[]" -Encoding UTF8
        Find-PreviousReportJson -OutputPath (Join-Path $dir "report.html") | Should -BeNullOrEmpty
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


# ══════════════════════════════════════════════════════════════════════════════
# Compliance score & history serialization
# ══════════════════════════════════════════════════════════════════════════════

Describe "Add-AuditHistoryEntry" {
    BeforeAll {
        function New-ScoreResult {
            param([string]$Status)
            [PSCustomObject]@{
                ControlId = "1.1"; Title = "t"; Level = 1; Section = "s"
                Status = $Status; Details = ""; Remediation = ""
                SubscriptionId = $script:T_SID; SubscriptionName = $script:T_SNAME; Resource = ""
            }
        }
    }

    It "counts ERROR against the compliance score" {
        $hist = Join-Path $TestDrive "hist1.json"
        $results = @(
            (New-ScoreResult $script:PASS),
            (New-ScoreResult $script:FAIL),
            (New-ScoreResult $script:ERR),
            (New-ScoreResult $script:ERR)
        )
        Add-AuditHistoryEntry -HistoryPath $hist -Results $results -SubscriptionIds @($script:T_SID)
        $entry = @(Get-AuditHistory -HistoryPath $hist)[-1]
        $entry.score | Should -Be 25.0
    }

    It "excludes INFO, MANUAL and SUPPRESSED from the score" {
        $hist = Join-Path $TestDrive "hist2.json"
        $results = @(
            (New-ScoreResult $script:PASS),
            (New-ScoreResult $script:INFO),
            (New-ScoreResult $script:MANUAL),
            (New-ScoreResult $script:SUPPRESSED)
        )
        Add-AuditHistoryEntry -HistoryPath $hist -Results $results -SubscriptionIds @($script:T_SID)
        $entry = @(Get-AuditHistory -HistoryPath $hist)[-1]
        $entry.score | Should -Be 100.0
    }

    It "writes a JSON array even with a single history entry" {
        $hist = Join-Path $TestDrive "hist3.json"
        Add-AuditHistoryEntry -HistoryPath $hist -Results @((New-ScoreResult $script:PASS)) -SubscriptionIds @($script:T_SID)
        (Get-Content $hist -Raw).TrimStart() | Should -Match '^\['
    }
}
