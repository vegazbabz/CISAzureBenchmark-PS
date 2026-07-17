@{
    RootModule        = 'CISAzureFoundationsBenchmark.psm1'
    ModuleVersion     = '2.4.0'
    GUID              = '6d9a7e0d-3f09-4c83-8686-01095806dde5'
    Author            = 'vegazbabz'
    Copyright         = '(c) vegazbabz. MIT License.'
    Description       = 'Audits Azure subscriptions against the CIS Microsoft Azure Foundations Benchmark v6.0.0 and produces a self-contained HTML compliance report (plus JSON/CSV). Read-only: performs no changes to the tenant.'
    PowerShellVersion = '7.0'
    # Gives the package the Core-edition compatibility badge on the Gallery.
    CompatiblePSEditions = @('Core')

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
            # Single-word tags only (Gallery requirement). The Windows/Linux/MacOS
            # and PSEdition_Core tags drive the compatibility badges on the
            # package page; the rest are search terms.
            Tags         = @(
                'CIS', 'CISBenchmark', 'Azure', 'MicrosoftAzure', 'Benchmark',
                'Audit', 'SecurityAudit', 'Compliance', 'Security', 'AzureSecurity',
                'CloudSecurity', 'CSPM', 'Hardening', 'Governance', 'Assessment',
                'Entra', 'EntraID', 'Defender', 'KeyVault', 'DevSecOps',
                'SARIF', 'Reporting',
                'PSEdition_Core', 'Windows', 'Linux', 'MacOS'
            )
            IconUri      = 'https://raw.githubusercontent.com/vegazbabz/CISAzureBenchmark-PS/main/docs/icon.png'
            LicenseUri   = 'https://github.com/vegazbabz/CISAzureBenchmark-PS/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/vegazbabz/CISAzureBenchmark-PS'
            ReleaseNotes = 'https://github.com/vegazbabz/CISAzureBenchmark-PS/releases'
        }
    }
}
