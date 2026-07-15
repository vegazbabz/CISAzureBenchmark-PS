@{
    # Single source of truth for PSScriptAnalyzer rules — used by CI (ci.yml,
    # release.yml) and auto-discovered by the VS Code PowerShell extension, so
    # the Problems panel matches what CI enforces.
    ExcludeRules = @(
        'PSAvoidUsingWriteHost'                        # console UX is intentional (colored audit output)
        'PSAvoidUsingEmptyCatchBlock'                  # deliberate best-effort probes
        'PSUseSingularNouns'                           # Test-AuditPermissions etc.
        'PSUseShouldProcessForStateChangingFunctions'  # functions build objects, not system state
    )
}
