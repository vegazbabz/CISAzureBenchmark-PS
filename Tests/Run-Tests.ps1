#!/usr/bin/env pwsh
#Requires -Version 7.0
<#
.SYNOPSIS
    Runs the Pester test suite for CISAzureBenchmark-PS.

.EXAMPLE
    .\Tests\Run-Tests.ps1
    .\Tests\Run-Tests.ps1 -Coverage
    .\Tests\Run-Tests.ps1 -Coverage -MinCoverage 70
    .\Tests\Run-Tests.ps1 -Test "5_27"
#>
[CmdletBinding()]
param(
    [switch]$Coverage,
    # Fail (exit 1) when coverage falls below this percentage; implies -Coverage.
    [ValidateRange(0, 100)]
    [double]$MinCoverage = 0,
    [string]$Test
)

Set-StrictMode -Version Latest

if ($MinCoverage -gt 0) { $Coverage = $true }

$minVer = [Version]"5.0"
$pester = Get-Module Pester -ListAvailable |
    Where-Object { $_.Version -ge $minVer } |
    Sort-Object Version -Descending |
    Select-Object -First 1

if (-not $pester) {
    Write-Error "Pester $minVer or later is required. Install with: Install-Module Pester -Force -Scope CurrentUser"
    exit 1
}

Import-Module (Join-Path $pester.ModuleBase "Pester.psd1") -Force

$config = New-PesterConfiguration
# Discovers every *.Tests.ps1 in Tests\ (per-section files; shared setup in TestHelpers.ps1)
$config.Run.Path        = $PSScriptRoot
$config.Run.PassThru    = $true
$config.Output.Verbosity = "Detailed"

if ($Test) {
    $config.Filter.FullName = "*$Test*"
}

if ($Coverage) {
    $config.CodeCoverage.Enabled    = $true
    $config.CodeCoverage.Path       = @(
        (Join-Path $PSScriptRoot "..\Private\*.ps1"),
        (Join-Path $PSScriptRoot "..\Checks\*.ps1")
    )
    $config.CodeCoverage.OutputPath = Join-Path $PSScriptRoot "..\coverage.xml"
}

$result = Invoke-Pester -Configuration $config

if (-not $result -or $result.Result -ne "Passed") {
    exit 1
}

if ($Coverage) {
    $cc = $result.CodeCoverage
    $pct = [math]::Round($cc.CoveragePercent, 2)
    Write-Host ("Code coverage: {0}% ({1} of {2} analyzed commands executed)" -f $pct, $cc.CommandsExecutedCount, $cc.CommandsAnalyzedCount)

    if ($env:GITHUB_STEP_SUMMARY) {
        $gate = if ($MinCoverage -gt 0) { "floor $MinCoverage%" } else { "no floor" }
        @(
            "### Code coverage"
            ""
            "| Coverage | Commands executed | Commands analyzed | Gate |"
            "| --- | --- | --- | --- |"
            "| **$pct%** | $($cc.CommandsExecutedCount) | $($cc.CommandsAnalyzedCount) | $gate |"
        ) | Add-Content -Path $env:GITHUB_STEP_SUMMARY
    }

    if ($MinCoverage -gt 0 -and $pct -lt $MinCoverage) {
        Write-Error "Code coverage $pct% is below the required minimum of $MinCoverage%."
        exit 1
    }
}

exit 0
