#Requires -Version 7.0
<#
.SYNOPSIS
    Stages a clean, publishable copy of the CISAzureBenchmark module.
.DESCRIPTION
    Publish-PSResource packages the entire contents of the target folder, so
    publishing straight from the repo root would ship tests, docs, reports and
    other non-module files. This script stages exactly the module runtime files
    into <OutputPath>/CISAzureBenchmark and validates the result:

      CISAzureBenchmark.psd1 / .psm1
      Public/  Private/  Checks/
      LICENSE  README.md

    Used by the release workflow before Publish-PSResource, and locally for
    dry-run packaging tests.
.PARAMETER OutputPath
    Directory to stage into (created if missing). The module lands in
    <OutputPath>/CISAzureBenchmark. Defaults to ./out.
.EXAMPLE
    ./scripts/Build-ModulePackage.ps1 -OutputPath $env:RUNNER_TEMP
#>
[CmdletBinding()]
param(
    [string]$OutputPath = "./out"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path $PSScriptRoot -Parent
$stageDir = Join-Path $OutputPath 'CISAzureBenchmark'

if (Test-Path $stageDir) { Remove-Item -Recurse -Force $stageDir }
New-Item -ItemType Directory -Path $stageDir -Force | Out-Null

# Module runtime files only — keep this list in sync with what the psm1 loads.
$rootFiles = @('CISAzureBenchmark.psd1', 'CISAzureBenchmark.psm1', 'LICENSE', 'README.md')
$dirs      = @('Public', 'Private', 'Checks')

foreach ($f in $rootFiles) {
    $src = Join-Path $repoRoot $f
    if (-not (Test-Path $src)) { throw "Missing required module file: $f" }
    Copy-Item $src -Destination $stageDir
}
foreach ($d in $dirs) {
    $src = Join-Path $repoRoot $d
    if (-not (Test-Path $src)) { throw "Missing required module directory: $d" }
    Copy-Item $src -Destination $stageDir -Recurse
}

# Validate the staged module standalone: manifest parses and the loader can
# resolve every file it dot-sources from the staged tree.
$manifest = Test-ModuleManifest (Join-Path $stageDir 'CISAzureBenchmark.psd1')
$staged   = Get-ChildItem $stageDir -Recurse -File
Write-Host ("Staged {0} v{1}: {2} file(s) -> {3}" -f $manifest.Name, $manifest.Version, $staged.Count, $stageDir)

Import-Module (Join-Path $stageDir 'CISAzureBenchmark.psd1') -Force
if (-not (Get-Command Invoke-CISAzureAudit -Module CISAzureBenchmark -ErrorAction SilentlyContinue)) {
    throw "Staged module import did not export Invoke-CISAzureAudit."
}
Remove-Module CISAzureBenchmark -Force
Write-Host "Staged module imports cleanly and exports Invoke-CISAzureAudit."

# Emit the staged path for callers (the only pipeline output).
$stageDir
