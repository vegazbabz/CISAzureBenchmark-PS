#!/usr/bin/env pwsh
#Requires -Version 7.0
<#
.SYNOPSIS
    CIS Microsoft Azure Foundations Benchmark Audit Tool — PowerShell Edition

.DESCRIPTION
    Compatibility shim: imports the CISAzureFoundationsBenchmark module and forwards all
    parameters to its exported Invoke-CISAzureAudit function, then maps the
    returned summary's ExitCode to a process exit code for CI/CD.

    Existing command lines keep working unchanged:
        .\Invoke-CISAzureAudit.ps1 -TenantId <id>
    Module users can instead:
        Import-Module .\CISAzureFoundationsBenchmark.psd1
        Invoke-CISAzureAudit -TenantId <id>

.EXAMPLE
    .\Invoke-CISAzureAudit.ps1 -TenantId "00000000-0000-0000-0000-000000000000"

.EXAMPLE
    .\Invoke-CISAzureAudit.ps1 -Subscriptions "sub-id-1","sub-id-2" -Output report.html -Parallel 5

.EXAMPLE
    .\Invoke-CISAzureAudit.ps1 -TenantId "00000000-0000-0000-0000-000000000000" -Fresh
#>

[CmdletBinding(PositionalBinding = $false)]
param(
    [string[]]$Subscriptions      = @(),
    [string]  $TenantId           = "",
    [string]  $Output             = "",
    [int]     $Parallel           = 3,
    [switch]  $NoCheckpoint,
    [switch]  $Fresh,
    [switch]  $SkipTenantChecks,
    [switch]  $NoPermissionCheck,
    [ValidateSet("1", "2", "both")]
    [string]  $Level              = "both",
    [switch]  $DebugMode,
    [switch]  $ReportOnly,
    [switch]  $NoOpen,
    [string]  $LogFile            = "",
    [switch]  $ExitCode,
    [string]  $SuppressionsFile   = "suppressions.json",
    [string]  $CompareWith        = "",
    # Catch space-separated subscription names: -Subscriptions "A" "B"
    # PowerShell can't merge named-binding and remaining-binding on the same
    # parameter, so overflow values land here and are merged below.
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$_ExtraSubscriptions = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "CISAzureFoundationsBenchmark.psd1") -Force

# Merge space-separated overflow subscription names before forwarding, then
# drop the internal overflow parameter so the function sees a single clean set.
$forward = @{} + $PSBoundParameters
$null = $forward.Remove('_ExtraSubscriptions')
if ($_ExtraSubscriptions.Count -gt 0) {
    $forward['Subscriptions'] = @(@($Subscriptions) + @($_ExtraSubscriptions)) | Where-Object { $_ }
}

# The function's last output object is the run summary (console output goes
# through Write-Host, so the pipeline carries only the summary).
$summary = CISAzureFoundationsBenchmark\Invoke-CISAzureAudit @forward | Select-Object -Last 1

if ($null -eq $summary -or -not ($summary.PSObject.Properties['ExitCode'])) {
    Write-Host "Audit did not return a run summary — treating as setup failure." -ForegroundColor Red
    exit 1
}
exit ([int]$summary.ExitCode)
