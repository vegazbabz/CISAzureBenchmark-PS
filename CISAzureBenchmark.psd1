@{
    RootModule        = 'CISAzureBenchmark.psm1'
    ModuleVersion     = '2.0.0'
    GUID              = '6d9a7e0d-3f09-4c83-8686-01095806dde5'
    Author            = 'vegazbabz'
    Copyright         = '(c) vegazbabz. MIT License.'
    Description       = 'Audits Azure subscriptions against the CIS Microsoft Azure Foundations Benchmark v6.0.0 and produces a self-contained HTML compliance report (plus JSON/CSV). Read-only: performs no changes to the tenant.'
    PowerShellVersion = '7.0'

    # Az module dependencies are validated at runtime with actionable guidance
    # (see the preflight in Invoke-CISAzureAudit) rather than enforced here:
    # RequiredModules would block Import-Module and -ReportOnly usage on
    # machines that lack section-specific Az modules the user may not need.
    FunctionsToExport = @('Invoke-CISAzureAudit')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    PrivateData = @{
        PSData = @{
            Tags                       = @('CIS', 'Azure', 'Benchmark', 'Audit', 'Compliance', 'Security', 'Assessment', 'Entra')
            LicenseUri                 = 'https://github.com/vegazbabz/CISAzureBenchmark-PS/blob/main/LICENSE'
            ProjectUri                 = 'https://github.com/vegazbabz/CISAzureBenchmark-PS'
            ReleaseNotes               = 'https://github.com/vegazbabz/CISAzureBenchmark-PS/releases'
            ExternalModuleDependencies = @(
                'Az.Accounts', 'Az.ResourceGraph', 'Az.Monitor', 'Az.Network',
                'Az.Storage', 'Az.KeyVault', 'Az.Resources', 'Az.Security'
            )
        }
    }
}
