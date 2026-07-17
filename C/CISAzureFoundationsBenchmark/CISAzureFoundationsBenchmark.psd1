@{
    RootModule        = 'CISAzureFoundationsBenchmark.psm1'
    ModuleVersion     = '2.3.0'
    GUID              = '6d9a7e0d-3f09-4c83-8686-01095806dde5'
    Author            = 'vegazbabz'
    Copyright         = '(c) vegazbabz. MIT License.'
    Description       = 'Audits Azure subscriptions against the CIS Microsoft Azure Foundations Benchmark v6.0.0 and produces a self-contained HTML compliance report (plus JSON/CSV). Read-only: performs no changes to the tenant.'
    PowerShellVersion = '7.0'

    # Declared as RequiredModules so the Gallery records them as dependencies:
    # Install-Module CISAzureFoundationsBenchmark pulls the whole Az set in one
    # command. The trade-off is that Import-Module needs them present (CI
    # installs them before manifest validation); the runtime preflight still
    # reports auth/permission gaps with actionable guidance.
    RequiredModules   = @(
        'Az.Accounts', 'Az.ResourceGraph', 'Az.Monitor', 'Az.Network',
        'Az.Storage', 'Az.KeyVault', 'Az.Resources', 'Az.Security'
    )
    FunctionsToExport = @('Invoke-CISAzureAudit')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    PrivateData = @{
        PSData = @{
            Tags         = @('CIS', 'Azure', 'Benchmark', 'Audit', 'Compliance', 'Security', 'Assessment', 'Entra')
            LicenseUri   = 'https://github.com/vegazbabz/CISAzureBenchmark-PS/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/vegazbabz/CISAzureBenchmark-PS'
            ReleaseNotes = 'https://github.com/vegazbabz/CISAzureBenchmark-PS/releases'
        }
    }
}
