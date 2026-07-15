# Public command surface — the audit orchestrator as an exported module function.
# The repo-root Invoke-CISAzureAudit.ps1 is a thin compatibility shim around this.

function Invoke-CISAzureAudit {
    <#
    .SYNOPSIS
        CIS Microsoft Azure Foundations Benchmark Audit Tool — PowerShell Edition

    .DESCRIPTION
        Audits Azure subscriptions against the CIS Microsoft Azure Foundations Benchmark v6.0.0.
        Produces an HTML report with per-control PASS/FAIL/ERROR/INFO/MANUAL results.

        Returns a summary object (ExitCode, Counts, Score, ReportPath, Results) —
        the script shim maps ExitCode to a process exit code for CI/CD.

        Requires:
          - PowerShell 7.0+
          - Az PowerShell modules (Az.Accounts, Az.ResourceGraph, etc.) authenticated via 'Connect-AzAccount'
          - Reader role (or higher) on target subscriptions

    .PARAMETER Subscriptions
        One or more subscription IDs to audit. Either -Subscriptions or -TenantId must be specified.

    .PARAMETER TenantId
        The Azure AD tenant ID to audit. Scopes subscription enumeration to this tenant.
        Either -TenantId or -Subscriptions must be specified.

    .PARAMETER Output
        Path for the HTML report. Defaults to reports\cis_audit_report_<timestamp>.html under the module root.

    .PARAMETER Parallel
        Number of subscriptions to audit simultaneously. Defaults to 3.

    .PARAMETER NoCheckpoint
        Disable checkpoint save/resume.

    .PARAMETER Fresh
        Clear all existing checkpoints and start a full re-audit.
        Without this flag, the tool auto-resumes from saved checkpoints.

    .PARAMETER SkipTenantChecks
        Skip tenant-level checks (Section 5: 5.1.1, 5.1.2, etc.).

    .PARAMETER NoPermissionCheck
        Skip preflight permission verification.

    .PARAMETER Level
        Only include Level 1, Level 2, or both (default: both).

    .PARAMETER DebugMode
        Enable debug logging (forces sequential execution).

    .PARAMETER ReportOnly
        Regenerate the HTML report from saved checkpoint data without re-running any checks.
        Requires existing checkpoint files in cis_checkpoints/.

    .PARAMETER NoOpen
        Do not auto-open the HTML report in the default browser after completion.

    .PARAMETER LogFile
        Optional path to write a log file.

    .PARAMETER ExitCode
        Set ExitCode=2 on the summary when FAIL or ERROR results are found (for CI/CD).

    .PARAMETER SuppressionsFile
        Path to the suppressions file (default: suppressions.json under the module root).

    .EXAMPLE
        Invoke-CISAzureAudit -TenantId "00000000-0000-0000-0000-000000000000"

    .EXAMPLE
        Invoke-CISAzureAudit -Subscriptions "sub-id-1","sub-id-2" -Output report.html -Parallel 5

    .OUTPUTS
        PSCustomObject (CISAzureBenchmark.AuditSummary) with ExitCode, Reason, Counts,
        Score, ReportPath, Results, SubscriptionCount and Elapsed.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Parameters are consumed inside nested scriptblocks/closures')]
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
        # Catch space-separated subscription names: -Subscriptions "A" "B"
        # PowerShell can't merge named-binding and remaining-binding on the same
        # parameter, so overflow values land here and are merged below.
        [Parameter(ValueFromRemainingArguments = $true)]
        [string[]]$_ExtraSubscriptions = @()
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = "Stop"

    # Uniform result contract for every code path (setup failure, ReportOnly, full run).
    function New-AuditRunSummary {
        param(
            [int]$Code,
            [string]$Reason = "",
            [hashtable]$Counts = $null,
            $Score = $null,
            [string]$ReportPath = "",
            [object[]]$Results = @(),
            [int]$SubscriptionCount = 0,
            [string]$Elapsed = ""
        )
        [PSCustomObject]@{
            PSTypeName        = 'CISAzureBenchmark.AuditSummary'
            ExitCode          = $Code
            Reason            = $Reason
            Counts            = $Counts
            Score             = $Score
            ReportPath        = $ReportPath
            Results           = $Results
            SubscriptionCount = $SubscriptionCount
            Elapsed           = $Elapsed
        }
    }

    # Merge space-separated overflow subscription names into $Subscriptions.
    if ($_ExtraSubscriptions.Count -gt 0) {
        $Subscriptions = @(@($Subscriptions) + @($_ExtraSubscriptions)) | Where-Object { $_ }
    }

    # Module files are already loaded by CISAzureBenchmark.psm1; resolve the root
    # for path defaults and for the parallel workers' dot-source re-import.
    $moduleRoot = if ($script:ModuleRoot) { $script:ModuleRoot } else { Split-Path $PSScriptRoot -Parent }

    # ── Load config file (cis_audit.json) — override defaults for unbound params ─
    $_cfgOverrides = Read-ConfigFile -ScriptRoot $moduleRoot
    foreach ($__key in $_cfgOverrides.Keys) {
        if (-not $PSBoundParameters.ContainsKey($__key)) {
            Set-Variable -Name $__key -Value $_cfgOverrides[$__key] -Scope 0
        }
    }
    Remove-Variable _cfgOverrides -ErrorAction SilentlyContinue

    # ── Resolve paths relative to the module root ─────────────────────────────

    if (-not $Output) {
        $Output = Join-Path $moduleRoot ("reports\cis_audit_report_" + (Get-Date -Format 'yyyyMMdd_HHmmss') + ".html")
    } elseif (-not [System.IO.Path]::IsPathRooted($Output)) {
        $Output = Join-Path $moduleRoot $Output
    }

    if ($LogFile -and -not [System.IO.Path]::IsPathRooted($LogFile)) {
        $LogFile = Join-Path $moduleRoot $LogFile
    }

    if ($SuppressionsFile -and -not [System.IO.Path]::IsPathRooted($SuppressionsFile)) {
        $SuppressionsFile = Join-Path $moduleRoot $SuppressionsFile
    }

    # Ensure output and log directories exist before any writes happen
    foreach ($filePath_ in @($Output, $LogFile) | Where-Object { $_ }) {
        $dir_ = [System.IO.Path]::GetDirectoryName($filePath_)
        if ($dir_ -and -not (Test-Path $dir_)) {
            New-Item -ItemType Directory -Path $dir_ -Force | Out-Null
        }
    }

    # ── Apply settings ────────────────────────────────────────────────────────

    $script:DEBUG_MODE   = $DebugMode.IsPresent
    $script:VERBOSE_MODE = $DebugMode.IsPresent -or ($VerbosePreference -eq "Continue")

    # DebugMode forces sequential so parallel runspaces don't swallow output
    if ($DebugMode.IsPresent -and $Parallel -gt 1) {
        $Parallel = 1
        Write-Host "  [DebugMode] Forcing sequential execution for full visibility." -ForegroundColor DarkYellow
    }
    $script:LOG_FILE     = if ($LogFile) { $LogFile } else { $null }

    # Shared process registry for Ctrl+C cleanup
    $script:_runningProcs = [System.Collections.Concurrent.ConcurrentDictionary[int, System.Diagnostics.Process]]::new()

    # The event action runs in its own dynamic scope, so bind the registry via a
    # closure rather than relying on $script: resolution inside the action.
    $procRegistry = $script:_runningProcs
    $null = Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
        foreach ($proc in $procRegistry.Values) {
            try {
                if (-not $proc.HasExited) {
                    if ($IsWindows -or ($env:OS -eq 'Windows_NT')) {
                        $null = Start-Process -FilePath 'taskkill.exe' -ArgumentList "/PID $($proc.Id) /T /F" -NoNewWindow -Wait -PassThru 2>$null
                    } else {
                        $proc.Kill($true)
                    }
                }
            } catch { <# already exited #> }
        }
    }.GetNewClosure()

    # ── Banner ────────────────────────────────────────────────────────────────

    Write-Host ""
    Write-Host "`u{1F512} CIS Azure Foundations Benchmark v$($script:BENCHMARK_VER) — Audit Tool v$($script:CIS_VERSION)" -ForegroundColor Cyan
    Write-Host ""

    # ── Require explicit audit scope (fail fast, before any network calls) ────

    if (-not $ReportOnly -and -not $PSBoundParameters.ContainsKey('TenantId') -and $Subscriptions.Count -eq 0) {
        Write-Host "  [ERROR] Specify -TenantId or -Subscriptions to define the audit scope." -ForegroundColor Red
        Write-Host "          -TenantId <id>              audit all enabled subscriptions in the given tenant" -ForegroundColor Yellow
        Write-Host "          -Subscriptions <id|name>    audit one or more specific subscriptions by ID or name" -ForegroundColor Yellow
        Write-Host ""
        return New-AuditRunSummary -Code 1 -Reason "No audit scope specified — use -TenantId or -Subscriptions."
    }

    # ── Verify Az PowerShell module is available ──────────────────────────────

    $azAccountsModule = Get-Module -ListAvailable Az.Accounts | Sort-Object Version -Descending | Select-Object -First 1
    if (-not $azAccountsModule) {
        Write-Host "`u{274C} Az PowerShell module not found." -ForegroundColor Red
        Write-Host "  Install with: Install-Module -Name Az -AllowClobber -Scope CurrentUser" -ForegroundColor Red
        return New-AuditRunSummary -Code 1 -Reason "Az.Accounts module not installed."
    }
    Write-Host "`u{2705} Az.Accounts v$($azAccountsModule.Version)" -ForegroundColor Green

    # ── Verify authentication and display identity ────────────────────────────

    $azCtx = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $azCtx) {
        Write-Host ""
        Write-Host "`u{274C} Not logged in to Azure. Run 'Connect-AzAccount' first." -ForegroundColor Red
        return New-AuditRunSummary -Code 1 -Reason "Not logged in to Azure — run Connect-AzAccount."
    }
    $callerName = [string]$azCtx.Account.Id
    $callerType = [string]$azCtx.Account.Type
    $tenantId   = if ($PSBoundParameters.ContainsKey('TenantId') -and $TenantId) { $TenantId } else { [string]$azCtx.Tenant.Id }
    $typeLabel  = switch ($callerType) {
        'ServicePrincipal' { 'Service Principal' }
        'User'             { 'User'              }
        default            { $callerType          }
    }
    Write-Host "`u{2705} Authenticated as: $callerName ($typeLabel)" -ForegroundColor Green
    Write-Host "`u{2705} Tenant: $tenantId" -ForegroundColor Green

    # ── ReportOnly: regenerate report from checkpoints and return ─────────────

    if ($ReportOnly) {
        Write-Host ""
        Write-Host "`u{1F4CA} Report-only mode..." -ForegroundColor Cyan

        $checkpoints = Get-AuditCheckpoints
        if ($checkpoints.Count -eq 0) {
            Write-Host "`u{274C} No checkpoint data found in cis_checkpoints/. Run a full audit first." -ForegroundColor Red
            return New-AuditRunSummary -Code 1 -Reason "No checkpoint data found — run a full audit first."
        }

        # Reconstruct subscription info from checkpoints
        $subIds   = @($checkpoints.Keys)
        $subNames = @{}
        foreach ($sid in $subIds) { $subNames[$sid] = $checkpoints[$sid].SubscriptionName }

        # Collect all results, showing per-subscription loading
        $allResults = [System.Collections.Generic.List[object]]::new()
        foreach ($sid in $subIds) {
            foreach ($r in @($checkpoints[$sid].Results)) { $allResults.Add($r) }
            Write-Host "   `u{2705} Loaded: $($checkpoints[$sid].SubscriptionName)" -ForegroundColor Green
        }

        # Load tenant checkpoint
        $tenantCkpt = Get-TenantCheckpoint
        if ($null -ne $tenantCkpt) {
            Write-Host "   `u{1F4BE} Loaded tenant checks from checkpoint ($($tenantCkpt.Count) results)." -ForegroundColor Green
            foreach ($r in $tenantCkpt) { $allResults.Add($r) }
        } else {
            Write-Host "   `u{1F50D} No tenant checkpoint found — tenant checks will be missing from report." -ForegroundColor DarkYellow
        }

        # Deduplicate
        $finalResults = Remove-DuplicateResults -Results $allResults.ToArray()

        # Apply suppressions
        $suppressions = @(Get-Suppressions -Path $SuppressionsFile)
        $finalResults = @(Invoke-Suppressions -Results $finalResults -Suppressions $suppressions)

        # Apply level filter
        if ($Level -eq "1") { $finalResults = @($finalResults | Where-Object { $_.Level -eq 1 }) }
        if ($Level -eq "2") { $finalResults = @($finalResults | Where-Object { $_.Level -eq 2 }) }

        # Summary
        $counts = @{ PASS = 0; FAIL = 0; ERROR = 0; INFO = 0; MANUAL = 0; SUPPRESSED = 0 }
        foreach ($r in $finalResults) { if ($counts.ContainsKey($r.Status)) { $counts[$r.Status]++ } }
        $assessed = $counts.PASS + $counts.FAIL + $counts.ERROR
        $score    = if ($assessed -gt 0) { [math]::Round(100.0 * $counts.PASS / $assessed, 1) } else { 0 }

        Write-Host ""
        Write-Host ("  " + "`u{2501}" * 60) -ForegroundColor DarkGray
        Write-Host ("  COMPLETE — {0} checks  |  {1} subscription(s)" -f $finalResults.Count, $subIds.Count) -ForegroundColor White
        Write-Host ("  Compliance Score : {0}%  ({1} of {2} assessed controls; ERROR counts as failing, excludes INFO/MANUAL/SUPPRESSED)" -f $score, $counts.PASS, $assessed) -ForegroundColor $(if ($score -ge 80) { "Green" } elseif ($score -ge 60) { "Yellow" } else { "Red" })
        Write-Host ("`u{2705} PASS         {0,4}" -f $counts.PASS)       -ForegroundColor Green
        Write-Host ("`u{274C} FAIL         {0,4}" -f $counts.FAIL)       -ForegroundColor Red
        Write-Host ("`u{26A0}`u{FE0F}  ERROR        {0,4}" -f $counts.ERROR)      -ForegroundColor DarkYellow
        Write-Host ("`u{2139}`u{FE0F}  INFO         {0,4}" -f $counts.INFO)       -ForegroundColor Blue
        Write-Host ("`u{1F4CB} MANUAL       {0,4}" -f $counts.MANUAL)     -ForegroundColor DarkMagenta
        Write-Host ("`u{1F507} SUPPRESSED   {0,4}" -f $counts.SUPPRESSED) -ForegroundColor DarkGray
        Write-Host ("  " + "`u{2501}" * 60) -ForegroundColor DarkGray
        Write-Host ""

        $scopeLabel = "All subscriptions (from checkpoint data)"
        $scopeInfo  = @{
            tenant        = $tenantId
            user          = $callerName
            caller_type   = $callerType
            scope_label   = $scopeLabel
            subscriptions = @($subNames.Values)
            level_filter  = $Level
        }
        $subTimestamps = @{}
        foreach ($sid in $subIds) { $subTimestamps[$subNames[$sid]] = $checkpoints[$sid].Timestamp }

        $historyPath = Get-HistoryPathFor -OutputPath $Output
        $history     = @(Get-AuditHistory -HistoryPath $historyPath)

        New-CISHtmlReport -Results $finalResults -OutputPath $Output -ScopeLabel $scopeLabel -History $history -ScopeInfo $scopeInfo -SubTimestamps $subTimestamps

        Write-Host "  Report: $([System.IO.Path]::GetFullPath($Output))" -ForegroundColor Cyan
        Write-Host ""
        if (-not $NoOpen) {
            try { Invoke-Item ([System.IO.Path]::GetFullPath($Output)) } catch { $null = $_ }
        }

        $roCode = if ($ExitCode -and ($counts.FAIL + $counts.ERROR) -gt 0) { 2 } else { 0 }
        return New-AuditRunSummary -Code $roCode -Counts $counts -Score $score `
            -ReportPath ([System.IO.Path]::GetFullPath($Output)) -Results $finalResults `
            -SubscriptionCount $subIds.Count
    }

    # ── Ensure Az.ResourceGraph module is available ───────────────────────────

    if (-not (Get-Module -ListAvailable Az.ResourceGraph)) {
        Write-Host "`u{274C} Az.ResourceGraph module not found. Run: Install-Module Az.ResourceGraph" -ForegroundColor Red
        return New-AuditRunSummary -Code 1 -Reason "Az.ResourceGraph module not installed."
    }
    Write-Host "`u{2705} Az.ResourceGraph module ready" -ForegroundColor Green

    # ── Preflight the remaining Az modules ────────────────────────────────────
    # Az.Accounts and Az.ResourceGraph above are mandatory (auth + prefetch). These
    # are per-section: a missing one would otherwise surface as opaque per-resource
    # ERROR rows. Sweep once and warn with a single, actionable install hint rather
    # than blocking — a user may deliberately run a subset of sections.

    $optionalModules = [ordered]@{
        'Az.Monitor'   = 'log profiles, diagnostic settings, activity log alerts'
        'Az.Network'   = 'network watcher flow logs'
        'Az.Storage'   = 'storage account enumeration'
        'Az.KeyVault'  = 'key rotation policies'
        'Az.Resources' = 'role definitions'
        'Az.Security'  = 'Microsoft Defender for Cloud checks'
    }
    $missingModules = @($optionalModules.Keys | Where-Object { -not (Get-Module -ListAvailable $_) })
    if ($missingModules.Count -gt 0) {
        Write-Host ("`u{26A0} {0} Az module(s) not installed — related checks will report ERROR:" -f $missingModules.Count) -ForegroundColor Yellow
        foreach ($m in $missingModules) {
            Write-Host ("    {0,-13} ({1})" -f $m, $optionalModules[$m]) -ForegroundColor Yellow
        }
        Write-Host ("    Install: Install-Module {0} -Scope CurrentUser" -f ($missingModules -join ', ')) -ForegroundColor Yellow
    } else {
        Write-Host "`u{2705} All section Az modules present" -ForegroundColor Green
    }
    Write-Host ""

    # ── Resolve subscription list ─────────────────────────────────────────────

    Write-AuditLog "Resolving subscriptions..." -Level INFO

    # Get ALL subscriptions (any state) so we can give accurate diagnostics
    $allSubs = @(Get-SubscriptionList -TenantId $tenantId)

    if ($Subscriptions.Count -eq 0) {
        # Default: audit every Enabled subscription
        $subObjects = @($allSubs | Where-Object { [string]$_.state -eq 'Enabled' })
    } else {
        Write-AuditLog "Subscription filter ($($Subscriptions.Count)): $($Subscriptions -join ', ')" -Level DEBUG

        # Match each requested name/ID against the full list (case-insensitive exact match)
        $subObjects = @($allSubs | Where-Object {
            $id   = [string]$_.id
            $name = [string]$_.name
            @($Subscriptions | Where-Object { $_ -ieq $id -or $_ -ieq $name }).Count -gt 0
        })

        # Report any requested subscription that was not matched at all, or matched but disabled
        foreach ($req in $Subscriptions) {
            $matched = @($subObjects | Where-Object { [string]$_.id -ieq $req -or [string]$_.name -ieq $req })
            if ($matched.Count -eq 0) {
                # Check whether it exists but is not Enabled
                $anyState = @($allSubs | Where-Object { [string]$_.id -ieq $req -or [string]$_.name -ieq $req })
                if ($anyState.Count -gt 0) {
                    Write-AuditLog "Subscription '$req' found but state is '$([string]$anyState[0].state)' — skipping." -Level WARNING
                } else {
                    Write-AuditLog "Subscription '$req' not found or not accessible." -Level WARNING
                    # It may belong to a different tenant — look up which one and guide the user
                    try {
                        $allTenants = @(Get-AzTenant -WarningAction SilentlyContinue -ErrorAction SilentlyContinue)
                        $otherTenants = @($allTenants | Where-Object { [string]$_.Id -ne $tenantId })
                        if ($otherTenants.Count -gt 0) {
                            Write-Host ""
                            Write-Host "   `u{1F4A1} '$req' may belong to a different tenant. Try authenticating to:" -ForegroundColor Yellow
                            foreach ($t in $otherTenants) {
                                $tLabel = if ($t.Name) { $t.Name } else { $t.Id }
                                Write-Host "      Connect-AzAccount -TenantId $($t.Id)  # $tLabel" -ForegroundColor Cyan
                            }
                            Write-Host "   Then re-run the audit." -ForegroundColor Yellow
                            Write-Host ""
                        } else {
                            Write-Host "   Check 'Get-AzSubscription -WarningAction SilentlyContinue' to verify the subscription exists and that you are authenticated to the correct tenant." -ForegroundColor DarkYellow
                        }
                    } catch { $null = $_ }
                }
            }
        }

        # Only audit Enabled subscriptions (warn about others above)
        $subObjects = @($subObjects | Where-Object { [string]$_.state -eq 'Enabled' })
    }

    if ($subObjects.Count -eq 0) {
        Write-Host "No accessible subscriptions found. Run 'Connect-AzAccount' and verify access with 'Get-AzSubscription'." -ForegroundColor Red
        return New-AuditRunSummary -Code 1 -Reason "No accessible subscriptions found in the audit scope."
    }

    $subIds   = @($subObjects | ForEach-Object { $_.id })
    $subNames = @{}
    foreach ($s in $subObjects) { $subNames[$s.id] = $s.name }

    Write-Host ""
    Write-Host ("`u{1F4CB} Subscriptions ({0}):" -f $subObjects.Count) -ForegroundColor White
    foreach ($s in $subObjects) {
        Write-Host ("   `u{2022} {0}  ({1})" -f ([string]$s.name), ([string]$s.id)) -ForegroundColor DarkGray
    }
    $_workerLabel = if ($subObjects.Count -le 1 -or $Parallel -le 1) {
        "sequential (1 worker)"
    } else {
        "$Parallel parallel workers"
    }
    Write-Host ("   Workers : $_workerLabel") -ForegroundColor DarkGray
    Remove-Variable _workerLabel
    Write-Host ""

    Write-AuditLog "Auditing $($subIds.Count) subscription(s): $($subIds -join ', ')" -Level INFO
    Write-Host ""

    # ── Permission preflight ──────────────────────────────────────────────────

    if (-not $NoPermissionCheck) {
        Write-Host "`u{1F510} Checking permissions…" -ForegroundColor DarkGray
        $permCheck = Test-AuditPermissions -SubscriptionIds $subIds -SubNames $subNames -ProbeKeyVaults

        # Show aggregated role summary (mirrors Python output)
        if ($permCheck.UserId) {
            Write-Host "   User: $callerName" -ForegroundColor DarkCyan
        }
        $permRoles = @($permCheck.Roles)
        if ($permRoles.Count -gt 0) {
            foreach ($r in $permRoles) {
                $cnt = $permCheck.RoleSubCount[$r]
                $subLabel = if ($permCheck.TotalSubs -gt 1) { "  ($cnt/$($permCheck.TotalSubs) subs)" } else { "" }
                Write-Host "   Role: $r$subLabel" -ForegroundColor DarkCyan
            }
        }

        $permWarnings = @($permCheck.Warnings)
        if ($permWarnings.Count -gt 0) {
            foreach ($w in $permWarnings) {
                Write-Host "   `u{26A0}`u{FE0F}  $w" -ForegroundColor DarkYellow
                Write-AuditLog $w -Level WARNING
            }
            Write-Host "   `u{1F4A1} Preflight could not fully verify permissions. The audit will continue, but some checks may show as ERROR." -ForegroundColor DarkYellow
        } else {
            Write-Host "   `u{2705} Preflight completed successfully." -ForegroundColor Green
        }
        Write-Host ""
    }

    # ── Load checkpoints (auto-resume unless -Fresh or -NoCheckpoint) ─────────

    if ($Fresh -and -not $NoCheckpoint) {
        Remove-AuditCheckpoints
        Write-AuditLog "`u{1F5D1}`u{FE0F}  Cleared checkpoints." -Level INFO
    }

    $checkpoints = @{}
    if (-not $Fresh -and -not $NoCheckpoint) {
        $checkpoints = Get-AuditCheckpoints
        # Filter to only checkpoints matching current audit scope
        $outOfScope = @($checkpoints.Keys | Where-Object { $subIds -notcontains $_ })
        foreach ($sk in $outOfScope) { $checkpoints.Remove($sk) }
        # Warn about stale checkpoints (> 24 hours old)
        foreach ($cpSid in @($checkpoints.Keys)) {
            $cpTs = $checkpoints[$cpSid].Timestamp
            if ($cpTs) {
                try {
                    $age = (Get-Date) - [datetime]$cpTs
                    if ($age.TotalHours -gt 24) {
                        Write-AuditLog "Checkpoint for $cpSid is $([int]$age.TotalHours)h old — consider a fresh run." -Level WARNING
                    }
                } catch { <# timestamp parse failure, ignore #> }
            }
        }
        $resumedCount = $checkpoints.Count
        if ($resumedCount -gt 0) {
            Write-AuditLog "`u{1F4BE} $resumedCount subscription(s) were already audited in a previous run — loading saved results." -Level INFO
            $skippedNames = @(@($checkpoints.Keys | ForEach-Object { $subNames[$_] }) | Where-Object { $_ })
            if ($skippedNames.Count -gt 0) {
                Write-AuditLog "`u{23ED}`u{FE0F}  Skipping (already audited): $($skippedNames -join ', ')" -Level INFO
            }
        }
    }

    # ── Resource Graph prefetch ───────────────────────────────────────────────

    $auditStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Host ""
    Write-AuditLog "`u{1F4E1} Fetching tenant data via Resource Graph..." -Level INFO

    # Only prefetch for subscriptions NOT covered by checkpoints
    $subIdsToAudit = @($subIds | Where-Object { -not $checkpoints.ContainsKey($_) })

    $prefetchData = @{}   # key -> { sub_id_lower -> [records] }

    # ── All subscriptions already audited ─────────────────────────────────────
    if ($subIdsToAudit.Count -eq 0 -and $checkpoints.Count -gt 0) {
        Write-AuditLog "`u{2705} All subscriptions were already audited — nothing new to scan. Use -Fresh to re-audit from scratch." -Level INFO
    }

    if ($subIdsToAudit.Count -gt 0) {
        $queryNames = @($script:GRAPH_QUERIES.Keys)
        $qIdx = 0
        foreach ($queryName in $queryNames) {
            $qIdx++
            $r = Invoke-AzGraphQuery -Query $script:GRAPH_QUERIES[$queryName] -SubscriptionIds $subIdsToAudit

            if (-not $r.Success) {
                Write-AuditLog ("   {0,-20} {1}  {2}" -f $queryName, [char]0x26A0, $r.Error) -Level WARNING
                # Sentinel: consumers must surface this as ERROR results, never a false PASS
                $prefetchData[$queryName] = @{ __error = [string]$r.Error }
                continue
            }

            # Index by subscription ID (lowercased)
            $indexed = @{}
            foreach ($record in @($r.Data)) {
                $subId = [string]$record.subscriptionId
                if (-not $subId) { continue }
                $key = $subId.ToLower()
                if (-not $indexed.ContainsKey($key)) { $indexed[$key] = [System.Collections.Generic.List[object]]::new() }
                $indexed[$key].Add($record)
            }
            # Convert lists to arrays
            $final = @{}
            foreach ($k in $indexed.Keys) { $final[$k] = $indexed[$k].ToArray() }
            $prefetchData[$queryName] = $final

            $totalRecords = ($final.Values | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum
            Write-AuditLog ("   {0,-20} {1}  {2} record(s)" -f $queryName, [char]0x2705, $totalRecords) -Level INFO
        }

        # Tenant-wide Graph data used by per-subscription checks (5.3.5)
        $disabledUsersPrefetch = Get-DisabledUserPrefetch
        $prefetchData['disabledUsers'] = $disabledUsersPrefetch
        if ($disabledUsersPrefetch.ContainsKey('__error')) {
            Write-AuditLog ("   {0,-20} {1}  {2}" -f 'disabledUsers', [char]0x26A0, $disabledUsersPrefetch['__error']) -Level WARNING
        } else {
            Write-AuditLog ("   {0,-20} {1}  {2} record(s)" -f 'disabledUsers', [char]0x2705, @($disabledUsersPrefetch['users']).Count) -Level INFO
        }

        Write-AuditLog "Prefetch complete. $($prefetchData.Count) resource type(s) cached." -Level INFO
    }
    Write-Host ""

    # ── Tenant-level checks ───────────────────────────────────────────────────

    $allResults = [System.Collections.Generic.List[object]]::new()

    if (-not $SkipTenantChecks) {
        $tenantCheckpoint = @(Get-TenantCheckpoint | Where-Object { $null -ne $_ })
        if ($tenantCheckpoint.Count -gt 0 -and $subIdsToAudit.Count -eq 0) {
            Write-AuditLog "   `u{1F4BE} Loaded tenant checks from checkpoint ($($tenantCheckpoint.Count) results)." -Level INFO
            foreach ($r in $tenantCheckpoint) { $allResults.Add($r) }
        } else {
            Write-AuditLog "Running tenant-level checks (Sections 2, 3, 5, 6, 7, 8)..." -Level INFO
            try {
                $tenantResults = @(Invoke-Section2TenantChecks) + @(Invoke-Section3TenantChecks) + @(Invoke-Section5TenantChecks) + @(Invoke-Section6TenantChecks) + @(Invoke-Section7TenantChecks) + @(Invoke-Section8TenantChecks)
                foreach ($r in $tenantResults) { $allResults.Add($r) }
                if (-not $NoCheckpoint) { Save-TenantCheckpoint -Results $tenantResults }
                Write-AuditLog "Tenant checks: $($tenantResults.Count) results." -Level INFO
            } catch {
                Write-AuditLog "Tenant-level check error: $_" -Level WARNING
                $allResults.Add((New-ErrorResult "TENANT" "Tenant-level checks failed" 1 "0 - Audit Errors" "The tenant-level check run crashed: $($_.Exception.Message). Tenant/Entra controls (Sections 2, 3, 5, 6, 7, 8) were not evaluated." "" ""))
            }
        }
    }

    # ── Per-subscription audit ────────────────────────────────────────────────

    function Invoke-SubscriptionAudit {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification='Parameters used inside scriptblock closures')]
        param([string]$SubId, [string]$SubName, [hashtable]$PrefetchData)

        $subResults = [System.Collections.Generic.List[object]]::new()

        # Ensure the Az context is set to this subscription so PS cmdlets that use
        # the current context (Get-AzLogProfile, Get-AzActivityLogAlert, etc.) target
        # the right subscription.
        # 3>$null suppresses the Az SDK "Unable to acquire token for tenant" warning
        # that fires when the account has access to multiple tenants (expected/harmless).
        # Fail fast on context-switch failure: running checks against a stale/wrong
        # context would silently audit the wrong subscription.
        try {
            $null = Set-AzContext -SubscriptionId $SubId -ErrorAction Stop -WarningAction SilentlyContinue 3>$null
            $ctxSub = [string](Get-AzContext).Subscription.Id
            if ($ctxSub -ne $SubId) { throw "context switch landed on subscription '$ctxSub' instead of '$SubId'" }
        } catch {
            Write-AuditLog "Could not switch Az context to $SubName ($SubId): $_ — skipping subscription." -Level WARNING
            $subResults.Add((New-ErrorResult "CONTEXT" "Azure context switch failed — subscription skipped" 1 "0 - Audit Errors" "Set-AzContext to '$SubId' failed: $($_.Exception.Message). All checks for this subscription were skipped to avoid auditing the wrong subscription." $SubId $SubName))
            return $subResults.ToArray()
        }

        $checkGroups = @(
            @{ Name = "Section 2 (Databricks)"; Sec = "2 - Azure Databricks";       Fn = { Invoke-Section2Checks -SubscriptionId $SubId -SubscriptionName $SubName -PrefetchData $PrefetchData } }
            @{ Name = "Section 5 (Identity)";   Sec = "5 - Identity Services";      Fn = { Invoke-Section5SubscriptionChecks -SubscriptionId $SubId -SubscriptionName $SubName -PrefetchData $PrefetchData } }
            @{ Name = "Section 6 (Monitoring)"; Sec = "6 - Management & Governance"; Fn = { Invoke-Section6Checks -SubscriptionId $SubId -SubscriptionName $SubName -PrefetchData $PrefetchData } }
            @{ Name = "Section 7 (Networking)"; Sec = "7 - Networking Services";    Fn = { Invoke-Section7Checks -SubscriptionId $SubId -SubscriptionName $SubName -PrefetchData $PrefetchData } }
            @{ Name = "Section 8 (Security)";   Sec = "8 - Security Services";      Fn = { Invoke-Section8Checks -SubscriptionId $SubId -SubscriptionName $SubName -PrefetchData $PrefetchData } }
            @{ Name = "Section 9 (Storage)";    Sec = "9 - Storage Services";       Fn = { Invoke-Section9Checks -SubscriptionId $SubId -SubscriptionName $SubName -PrefetchData $PrefetchData } }
        )

        foreach ($group in $checkGroups) {
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            Write-AuditLog "    [$SubName] $($group.Name)..." -Level INFO
            try {
                $groupResults = @(& $group.Fn)
                foreach ($r in $groupResults) {
                    $statusPad = $r.Status.PadRight(8)
                    $res = if ($r.Resource) { " [$($r.Resource)]" } else { "" }
                    $det = ($r.Details -replace "`r?`n", ' ').Trim()
                    if ($det.Length -gt 90) { $det = $det.Substring(0, 90) + '...' }
                    Write-AuditLog "       [$statusPad] $($r.ControlId.PadRight(12))$res $det" -Level VERBOSE
                    $subResults.Add($r)
                }
                $sw.Stop()
                Write-AuditLog "    [$SubName] $($group.Name) done — $($groupResults.Count) result(s) in $($sw.Elapsed.TotalSeconds.ToString('F1'))s" -Level INFO
            } catch {
                Write-AuditLog "$($group.Name) error for ${SubName}: $_" -Level WARNING
                $subResults.Add((New-ErrorResult "GROUP" "$($group.Name) checks failed" 1 $group.Sec "The whole check group crashed: $($_.Exception.Message). Individual controls in this group were not evaluated." $SubId $SubName))
            }
        }

        return $subResults.ToArray()
    }

    # Collect results from checkpoints first
    foreach ($subId in $subIds) {
        if ($checkpoints.ContainsKey($subId)) {
            $cp = $checkpoints[$subId]
            Write-AuditLog "   Using checkpoint for: $($cp.SubscriptionName) ($subId) [$($cp.Timestamp)]" -Level DEBUG
            foreach ($r in @($cp.Results)) { $allResults.Add($r) }
        }
    }

    # Audit remaining subscriptions
    $subsToProcess = @($subIdsToAudit)

    if ($subsToProcess.Count -gt 0) {
        if ($Parallel -le 1 -or $subsToProcess.Count -eq 1) {
            # Sequential execution
            $seqIdx = 0
            foreach ($subId in $subsToProcess) {
                $seqIdx++
                $subName = $subNames[$subId]
                Write-AuditLog "  [$seqIdx/$($subsToProcess.Count)] Starting:  $subName" -Level INFO

                try {
                    $subResults = Invoke-SubscriptionAudit -SubId $subId -SubName $subName -PrefetchData $prefetchData

                    foreach ($r in $subResults) { $allResults.Add($r) }

                    if (-not $NoCheckpoint) {
                        Save-AuditCheckpoint -SubscriptionId $subId -SubscriptionName $subName -Results $subResults
                    }

                    Write-AuditLog "  [$seqIdx/$($subsToProcess.Count)] Completed: $subName — $($subResults.Count) results" -Level INFO
                } catch {
                    Write-AuditLog "Fatal error auditing $subName`: $_" -Level WARNING
                    $allResults.Add((New-ErrorResult "FATAL" "Subscription audit failed" 1 "0 - Audit Errors" "Auditing '$subName' crashed: $($_.Exception.Message)." $subId $subName))
                }
            }
        } else {
            # Adaptive parallel execution — process subscriptions in batches,
            # adjusting concurrency based on throttling signals from Azure.
            $currentParallel = [math]::Min($Parallel, $subsToProcess.Count)
            $resultBag  = [System.Collections.Concurrent.ConcurrentBag[object]]::new()
            $moduleRoot_ = $moduleRoot

            # Pre-build array of [id, name, index] — $using: can't index into hashtables
            $subPairs = @(for ($i = 0; $i -lt $subsToProcess.Count; $i++) {
                [PSCustomObject]@{ Id = $subsToProcess[$i]; Name = $subNames[$subsToProcess[$i]]; Idx = $i + 1 }
            })
            $totalToProcess = $subsToProcess.Count
            $stableBatches  = 0
            $_procRegistry  = $script:_runningProcs

            Write-AuditLog "Running parallel audit ($currentParallel concurrent workers)..." -Level INFO

            # Disable Az context autosave at the process level so the shared on-disk
            # context file (~/.Azure/AzureRmContext.json) is not written between runspaces.
            # Each parallel runspace also calls Disable-AzContextAutosave for itself so
            # that module re-initialisation inside the runspace cannot re-enable autosave
            # and cause in-memory context sharing between workers.
            $null = Disable-AzContextAutosave -Scope Process

            $batchIdx = 0
            $completedCounter = [System.Collections.Concurrent.ConcurrentBag[int]]::new()
            while ($batchIdx -lt $subPairs.Count) {
                $batchSize = [math]::Min($currentParallel, $subPairs.Count - $batchIdx)
                $batch     = @($subPairs[$batchIdx..($batchIdx + $batchSize - 1)])
                $throttleBag = [System.Collections.Concurrent.ConcurrentBag[int]]::new()

                $batch | ForEach-Object -Parallel {
                    $subId         = $_.Id
                    $subName       = $_.Name
                    $subIdx        = $_.Idx
                    $subTotal      = $using:totalToProcess
                    $pd            = $using:prefetchData
                    $modRoot       = $using:moduleRoot_
                    $tenantId_     = $using:tenantId
                    $noCheckpoint  = $using:NoCheckpoint
                    $bag           = $using:resultBag
                    $tBag          = $using:throttleBag
                    $pReg          = $using:_procRegistry
                    $cBag          = $using:completedCounter

                    Write-Host "  [$subIdx/$subTotal] Starting:  $subName" -ForegroundColor DarkCyan

                    # Re-import all module files in the parallel runspace from the
                    # single shared manifest (Private\ModuleManifest.ps1) so this list
                    # can never drift from the module loader. Workers deliberately
                    # dot-source into the runspace session (rather than Import-Module)
                    # so the $script: runtime state set below is visible to every
                    # helper — module-scoped state would not be.
                    . (Join-Path $modRoot "Private\ModuleManifest.ps1")
                    foreach ($f in $script:ModuleFiles) { . (Join-Path $modRoot $f) }

                    # Disable Az context autosave in THIS runspace before setting the context.
                    # The parent-runspace call alone is not sufficient: when Az.Accounts is first
                    # used in a new runspace it re-initialises its module state (resetting the
                    # autosave mode to the default). Without this per-runspace call, all parallel
                    # workers share the same in-memory context object and Set-AzContext in one
                    # worker silently overwrites the context for all others.
                    $null = Disable-AzContextAutosave -Scope Process

                    # Set Az context so PS cmdlets target this subscription.
                    # -Tenant pins the switch to the current tenant so accounts with guest access
                    # to multiple tenants don't silently land on the wrong tenant context.
                    # Fail fast on context-switch failure: running checks against a stale/wrong
                    # context would silently audit the wrong subscription.
                    $ctxError = $null
                    try {
                        $null = Set-AzContext -SubscriptionId $subId -Tenant $tenantId_ -ErrorAction Stop -WarningAction SilentlyContinue 3>$null
                        $ctxSub = [string](Get-AzContext).Subscription.Id
                        if ($ctxSub -ne $subId) { throw "context switch landed on subscription '$ctxSub' instead of '$subId'" }
                    } catch {
                        $ctxError = $_.Exception.Message
                    }

                    # Wire up shared state for adaptive concurrency and Ctrl+C cleanup
                    $script:_throttleBag  = $tBag
                    $script:_runningProcs = $pReg

                    try {
                        if ($ctxError) {
                            [Console]::Error.WriteLine("[PARALLEL-CONTEXT-ERROR] ${subName}: $ctxError — skipping subscription.")
                            $ctxResult = New-ErrorResult "CONTEXT" "Azure context switch failed — subscription skipped" 1 "0 - Audit Errors" "Set-AzContext to '$subId' failed: $ctxError. All checks for this subscription were skipped to avoid auditing the wrong subscription." $subId $subName
                            $bag.Add($ctxResult)
                            $cBag.Add(1)
                            Write-Host "  [$($cBag.Count)/$subTotal] Skipped (context error): $subName" -ForegroundColor Yellow
                            return
                        }

                        $checkGroups = @(
                            @{ Name = "Section 2 (Databricks)"; Sec = "2 - Azure Databricks";       Fn = { Invoke-Section2Checks -SubscriptionId $subId -SubscriptionName $subName -PrefetchData $pd } }
                            @{ Name = "Section 5 (Identity)";   Sec = "5 - Identity Services";      Fn = { Invoke-Section5SubscriptionChecks -SubscriptionId $subId -SubscriptionName $subName -PrefetchData $pd } }
                            @{ Name = "Section 6 (Monitoring)"; Sec = "6 - Management & Governance"; Fn = { Invoke-Section6Checks -SubscriptionId $subId -SubscriptionName $subName -PrefetchData $pd } }
                            @{ Name = "Section 7 (Networking)"; Sec = "7 - Networking Services";    Fn = { Invoke-Section7Checks -SubscriptionId $subId -SubscriptionName $subName -PrefetchData $pd } }
                            @{ Name = "Section 8 (Security)";   Sec = "8 - Security Services";      Fn = { Invoke-Section8Checks -SubscriptionId $subId -SubscriptionName $subName -PrefetchData $pd } }
                            @{ Name = "Section 9 (Storage)";    Sec = "9 - Storage Services";       Fn = { Invoke-Section9Checks -SubscriptionId $subId -SubscriptionName $subName -PrefetchData $pd } }
                        )

                        $subResults = [System.Collections.Generic.List[object]]::new()
                        foreach ($g in $checkGroups) {
                            Write-Host "    [$subName] $($g.Name)..." -ForegroundColor DarkGray
                            $gSw = [System.Diagnostics.Stopwatch]::StartNew()
                            $gCount = 0
                            try {
                                foreach ($r in @(& $g.Fn)) { $subResults.Add($r); $gCount++ }
                            } catch {
                                [Console]::Error.WriteLine("[PARALLEL-CHECK-ERROR] ${subName}: $_")
                                $subResults.Add((New-ErrorResult "GROUP" "$($g.Name) checks failed" 1 $g.Sec "The whole check group crashed: $($_.Exception.Message). Individual controls in this group were not evaluated." $subId $subName))
                            }
                            $gSw.Stop()
                            Write-Host ("    [$subName] $($g.Name) done — $gCount result(s) in $($gSw.Elapsed.TotalSeconds.ToString('F1'))s") -ForegroundColor DarkGray
                        }

                        foreach ($r in $subResults) { $bag.Add($r) }

                        if (-not $noCheckpoint) {
                            Save-AuditCheckpoint -SubscriptionId $subId -SubscriptionName $subName -Results $subResults.ToArray()
                        }

                        $cBag.Add(1)
                        $doneN = $cBag.Count
                        Write-Host "  [$doneN/$subTotal] Completed: $subName — $($subResults.Count) results" -ForegroundColor Green
                    } catch { $null = $_ <# Intentional: per-subscription errors are logged inside; prevent ForEach-Object -Parallel from terminating #> }

                } -ThrottleLimit $batchSize

                # Adaptive concurrency adjustment
                $throttleCount  = $throttleBag.Count
                $remaining      = $subPairs.Count - $batchIdx - $batchSize
                $reduceThreshold = [math]::Max(2, $batchSize)

                if ($throttleCount -ge $reduceThreshold -and $currentParallel -gt 1) {
                    $currentParallel--
                    Write-AuditLog ("Detected $throttleCount throttle retries in batch; " +
                        "reducing workers to $currentParallel") -Level WARNING
                    $stableBatches = 0
                } elseif ($throttleCount -eq 0 -and $currentParallel -lt $Parallel -and $remaining -gt 0) {
                    $stableBatches++
                    if ($stableBatches -ge 2) {
                        $currentParallel++
                        Write-AuditLog ("No throttling for $stableBatches batches; " +
                            "increasing workers to $currentParallel") -Level INFO
                        $stableBatches = 0
                    }
                } else {
                    $stableBatches = 0
                }

                $batchIdx += $batchSize
            }

            foreach ($r in $resultBag) { $allResults.Add($r) }
        }
    }

    $auditStopwatch.Stop()
    $elapsed = $auditStopwatch.Elapsed
    $elapsedStr = if ($elapsed.TotalMinutes -ge 1) { "{0}m {1}s" -f [int][math]::Floor($elapsed.TotalMinutes), $elapsed.Seconds } else { "{0}s" -f $elapsed.TotalSeconds.ToString('F1') }
    Write-AuditLog "Audit complete. $($allResults.Count) total results in $elapsedStr." -Level INFO

    # ── Apply suppressions ────────────────────────────────────────────────────

    $suppressions = @(Get-Suppressions -Path $SuppressionsFile)

    $finalResults = Remove-DuplicateResults -Results $allResults.ToArray()
    $finalResults = @(Invoke-Suppressions -Results $finalResults -Suppressions $suppressions)

    # ── Apply level filter ────────────────────────────────────────────────────

    if ($Level -eq "1") { $finalResults = @($finalResults | Where-Object { $_.Level -eq 1 }) }
    if ($Level -eq "2") { $finalResults = @($finalResults | Where-Object { $_.Level -eq 2 }) }

    # ── Summary to console ────────────────────────────────────────────────────

    $counts = @{ PASS = 0; FAIL = 0; ERROR = 0; INFO = 0; MANUAL = 0; SUPPRESSED = 0 }
    foreach ($r in $finalResults) { if ($counts.ContainsKey($r.Status)) { $counts[$r.Status]++ } }

    $assessed  = $counts.PASS + $counts.FAIL + $counts.ERROR
    $score     = if ($assessed -gt 0) { [math]::Round(100.0 * $counts.PASS / $assessed, 1) } else { 0 }

    Write-Host ""
    Write-Host ("  " + "`u{2501}" * 60) -ForegroundColor DarkGray
    Write-Host ("  COMPLETE — {0} checks  |  {1} subscription(s)  |  `u{23F1} {2}" -f $finalResults.Count, $subIds.Count, $elapsedStr) -ForegroundColor White
    Write-Host ("  Compliance Score : {0}%  ({1} of {2} assessed controls; ERROR counts as failing, excludes INFO/MANUAL/SUPPRESSED)" -f $score, $counts.PASS, $assessed) -ForegroundColor $(if ($score -ge 80) { "Green" } elseif ($score -ge 60) { "Yellow" } else { "Red" })
    Write-Host ("`u{2705} PASS         {0,4}" -f $counts.PASS)       -ForegroundColor Green
    Write-Host ("`u{274C} FAIL         {0,4}" -f $counts.FAIL)       -ForegroundColor Red
    Write-Host ("`u{26A0}`u{FE0F}  ERROR        {0,4}" -f $counts.ERROR)      -ForegroundColor DarkYellow
    Write-Host ("`u{2139}`u{FE0F}  INFO         {0,4}" -f $counts.INFO)       -ForegroundColor Blue
    Write-Host ("`u{1F4CB} MANUAL       {0,4}" -f $counts.MANUAL)     -ForegroundColor DarkMagenta
    Write-Host ("`u{1F507} SUPPRESSED   {0,4}" -f $counts.SUPPRESSED) -ForegroundColor DarkGray
    Write-Host ("  " + "`u{2501}" * 60) -ForegroundColor DarkGray
    Write-Host ""

    # ── Generate HTML report ──────────────────────────────────────────────────

    $scopeLabel = if ($Subscriptions.Count -eq 0) {
        "All subscriptions (tenant-wide)"
    } else {
        "Selected: $(($subObjects | ForEach-Object { $_.name }) -join ', ')"
    }

    # ── Collect identity context for report scope block ──────────────────────
    # Use the Az context variables already captured at startup ($callerName, $tenantId, $callerType)
    $scopeInfo   = @{
        tenant        = $tenantId
        user          = $callerName
        caller_type   = $callerType
        scope_label   = $scopeLabel
        subscriptions = @($subObjects | ForEach-Object { [string]$_.name })
        level_filter  = $Level
    }

    # Subscription → audit timestamp (prefer checkpoint timestamp for resumed subs)
    $nowIso        = Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ'
    $subTimestamps = @{}
    foreach ($subId_ in $subIds) {
        $sname_ = $subNames[$subId_]
        $subTimestamps[$sname_] = if ($checkpoints.ContainsKey($subId_)) { $checkpoints[$subId_].Timestamp } else { $nowIso }
    }

    # Load history and append current run
    $historyPath = Get-HistoryPathFor -OutputPath $Output
    $history     = @(Get-AuditHistory -HistoryPath $historyPath)

    New-CISHtmlReport -Results $finalResults -OutputPath $Output -ScopeLabel $scopeLabel -History $history -ScopeInfo $scopeInfo -SubTimestamps $subTimestamps

    # Append current run to history (only full-tenant runs)
    if ($subIds.Count -gt 1 -or $Subscriptions.Count -eq 0) {
        Add-AuditHistoryEntry -HistoryPath $historyPath -Results $finalResults -SubscriptionIds $subIds
    }

    Write-Host "  Report: $([System.IO.Path]::GetFullPath($Output))" -ForegroundColor Cyan
    Write-Host ""

    # ── Open report in default browser ────────────────────────────────────────
    if (-not $NoOpen) {
        try { Invoke-Item ([System.IO.Path]::GetFullPath($Output)) } catch { $null = $_ }
    }

    # ── Exit code for CI/CD ───────────────────────────────────────────────────
    $finalCode = if ($ExitCode -and ($counts.FAIL + $counts.ERROR) -gt 0) { 2 } else { 0 }
    return New-AuditRunSummary -Code $finalCode -Counts $counts -Score $score `
        -ReportPath ([System.IO.Path]::GetFullPath($Output)) -Results $finalResults `
        -SubscriptionCount $subIds.Count -Elapsed $elapsedStr
}
