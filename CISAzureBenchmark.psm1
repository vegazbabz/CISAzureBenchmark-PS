#Requires -Version 7.0
# Module loader — dot-sources every file from the shared manifest list
# (Private\ModuleManifest.ps1, the same single source of truth the Pester
# bootstrap uses) into module scope, then the public command surface.

Set-StrictMode -Version Latest

$script:ModuleRoot = $PSScriptRoot

. (Join-Path $PSScriptRoot 'Private\ModuleManifest.ps1')
foreach ($moduleFile in $script:ModuleFiles) {
    . (Join-Path $PSScriptRoot $moduleFile)
}

. (Join-Path $PSScriptRoot 'Public\Invoke-CISAzureAudit.ps1')

# The manifest is the single source of truth for the tool version; Config.ps1's
# value remains only as a fallback for the dot-source (test) load path.
if ($MyInvocation.MyCommand.Module) {
    $script:CIS_VERSION = $MyInvocation.MyCommand.Module.Version.ToString()
}

Export-ModuleMember -Function 'Invoke-CISAzureAudit'
