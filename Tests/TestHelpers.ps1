# Shared test bootstrap — dot-sourced inside the BeforeAll of every *.Tests.ps1 file.
#
# Executing this inside BeforeAll means everything here lands in that file's root
# block: the module functions, the fixture helpers/constants, and — crucially — the
# hermetic default Mock registrations (Pester registers mocks against the executing
# block, so they behave exactly like the old monolith's root BeforeAll mocks).
# Not named *.Tests.ps1 on purpose: Pester discovery must skip this file.

    # Dot-source all module files so check functions are available in test scope
    $moduleRoot = Split-Path $PSScriptRoot -Parent
    . (Join-Path $moduleRoot "Private\ModuleManifest.ps1")
    foreach ($f in $script:ModuleFiles) {
        . (Join-Path $moduleRoot $f)
    }

    # Silence logger during tests
    $script:DEBUG_MODE   = $false
    $script:VERBOSE_MODE = $false
    $script:LOG_FILE     = $null

    # Test subscription constants
    $script:T_SID   = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    $script:T_SNAME = "Test Subscription"

    # Helper: build a minimal prefetch hashtable for Get-PrefetchData lookups
    function New-PD {
        param([string]$Key, [object[]]$Records)
        @{ $Key = @{ $script:T_SID.ToLower() = $Records } }
    }

    # Helper: combine multiple prefetch keys into one hashtable
    function Merge-PD {
        param([hashtable[]]$Tables)
        $out = @{}
        foreach ($t in $Tables) { foreach ($k in $t.Keys) { $out[$k] = $t[$k] } }
        $out
    }

    # Helper: build an NSG rule object (Resource Graph flat shape)
    function New-Rule {
        param(
            [string]$Name      = "rule1",
            [string]$Access    = "Allow",
            [string]$Direction = "Inbound",
            [string]$Protocol  = "TCP",
            [string]$Src       = "*",
            [string]$DestPort  = "22"
        )
        [PSCustomObject]@{
            name                    = $Name
            access                  = $Access
            direction               = $Direction
            protocol                = $Protocol
            sourceAddressPrefix     = $Src
            destinationPortRange    = $DestPort
            destinationPortRanges   = @()
        }
    }

    # ── Hermetic default mocks ────────────────────────────────────────────────
    # Every real Az cmdlet (and the AzureClient REST wrappers) a check function
    # can invoke is mocked here with a benign empty return. Without these, a check
    # path not explicitly mocked by a test (e.g. Section2's 2.1.2 block still runs
    # the 2.1.7 Get-AzDiagnosticSetting call) makes a live API call. On a CI runner
    # with no Az context that call hangs and aborts the whole run; it only "passes"
    # on a dev machine that happens to be logged in. These root-level mocks keep the
    # suite offline; per-Describe/It Mock calls override them where output matters.
    Mock Get-AzDiagnosticSetting        { @() }
    Mock Get-AzLogProfile               { @() }
    Mock Get-AzActivityLogAlert         { @() }
    Mock Get-AzNetworkWatcherFlowLog    { @() }
    Mock Get-AzRoleDefinition           { @() }
    Mock Get-AzStorageAccount           { @() }
    Mock Get-AzStorageBlobServiceProperty { $null }
    Mock Get-AzStorageFileServiceProperty { $null }
    Mock Get-AzResourceLock             { @() }
    Mock Get-AzSecurityPricing          { $null }
    Mock Get-AzKeyVaultKey              { @() }
    Mock Get-AzKeyVaultSecret           { @() }
    Mock Get-AzKeyVaultCertificate      { @() }
    Mock Get-AzKeyVaultKeyRotationPolicy { $null }
    Mock Invoke-ArmRest                 { [PSCustomObject]@{ Success = $true; Data = @(); Error = $null } }
    # Invoke-AzRestPaged is deliberately NOT mocked here: it runs for real on top of
    # the mocked Invoke-ArmRest (same empty result), so its paging logic stays testable.
    Mock Invoke-AzGraphQuery            { [PSCustomObject]@{ Success = $true; Data = @(); Error = $null } }