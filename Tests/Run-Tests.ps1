#!/usr/bin/env pwsh
#Requires -Version 7.0
<#
.SYNOPSIS
    Runs the Pester test suite for CISAzureBenchmark-PS.

.EXAMPLE
    .\Tests\Run-Tests.ps1
    .\Tests\Run-Tests.ps1 -Coverage
    .\Tests\Run-Tests.ps1 -Test "5_27"
#>
[CmdletBinding()]
param(
    [switch]$Coverage,
    [string]$Test
)

Set-StrictMode -Version Latest

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
exit 0
