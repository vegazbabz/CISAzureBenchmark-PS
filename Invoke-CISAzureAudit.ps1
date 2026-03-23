<#
.SYNOPSIS
    CIS Microsoft Azure Foundations Benchmark Audit Tool — PowerShell Edition

.DESCRIPTION
    Audits Azure subscriptions against the CIS Microsoft Azure Foundations Benchmark v5.0.0.
    Produces an HTML report with per-control PASS/FAIL/ERROR/INFO/MANUAL results.

    Requires:
      - PowerShell 7.0+
      - Azure CLI (az) authenticated via 'az login'
      - Reader role (or higher) on target subscriptions

.PARAMETER Subscriptions
    One or more subscription IDs to audit. Defaults to all accessible subscriptions.

.PARAMETER Output
    Path for the HTML report. Defaults to cis_audit_report.html in the current directory.

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

.PARAMETER Debug
    Enable debug logging.

.PARAMETER ReportOnly
    Regenerate the HTML report from saved checkpoint data without re-running any checks.
    Requires existing checkpoint files in cis_checkpoints/.

.PARAMETER NoOpen
    Do not auto-open the HTML report in the default browser after completion.

.PARAMETER LogFile
    Optional path to write a log file.

.EXAMPLE
    .\Invoke-CISAzureAudit.ps1

.EXAMPLE
    .\Invoke-CISAzureAudit.ps1 -Subscriptions "sub-id-1","sub-id-2" -Output report.html -Parallel 5

.EXAMPLE
    .\Invoke-CISAzureAudit.ps1 -Fresh
#>

[CmdletBinding(PositionalBinding=$false)]
param(
    [string[]]$Subscriptions      = @(),
    [string]  $Output             = "",
    [int]     $Parallel           = 3,
    [switch]  $NoCheckpoint,
    [switch]  $Fresh,
    [switch]  $SkipTenantChecks,
    [switch]  $NoPermissionCheck,
    [ValidateSet("1","2","both")]
    [string]  $Level              = "both",
    [switch]  $DebugMode,
    [switch]  $ReportOnly,
    [switch]  $NoOpen,
    [string]  $LogFile            = "",
    # Catch space-separated subscription names: -Subscriptions "A" "B"
    # PowerShell can't merge named-binding and remaining-binding on the same
    # parameter, so overflow values land here and are merged below.
    [Parameter(ValueFromRemainingArguments=$true)]
    [string[]]$_ExtraSubscriptions = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Merge space-separated overflow subscription names into $Subscriptions.
# With PositionalBinding=$false a named [string[]] param only captures one
# array batch; extra space-separated values land in $_ExtraSubscriptions.
if ($_ExtraSubscriptions.Count -gt 0) {
    $Subscriptions = @(@($Subscriptions) + @($_ExtraSubscriptions)) | Where-Object { $_ }
}

# ── Load all module files ────────────────────────────────────────────────────
# NOTE: dot-source at script level (foreach has no scope boundary);
#       using a wrapper function would confine function definitions to that
#       function's local scope and they would not be visible here.

$moduleRoot = $PSScriptRoot

# Resolve output path relative to the script directory (not the caller's cwd)
if (-not $Output) {
    $Output = Join-Path $PSScriptRoot ("reports\cis_audit_report_" + (Get-Date -Format 'yyyyMMdd_HHmmss') + ".html")
} elseif (-not [System.IO.Path]::IsPathRooted($Output)) {
    $Output = Join-Path $PSScriptRoot $Output
}

# Resolve LogFile path if relative
if ($LogFile -and -not [System.IO.Path]::IsPathRooted($LogFile)) {
    $LogFile = Join-Path $PSScriptRoot $LogFile
}

# Ensure output and log directories exist before any writes happen
foreach ($filePath_ in @($Output, $LogFile) | Where-Object { $_ }) {
    $dir_ = [System.IO.Path]::GetDirectoryName($filePath_)
    if ($dir_ -and -not (Test-Path $dir_)) {
        New-Item -ItemType Directory -Path $dir_ -Force | Out-Null
    }
}

foreach ($__f in @(
    "Private\Config.ps1",
    "Private\Models.ps1",
    "Private\AzureClient.ps1",
    "Private\Helpers.ps1",
    "Private\CheckHelpers.ps1",
    "Private\Identity.ps1",
    "Private\Checkpoint.ps1",
    "Private\History.ps1",
    "Private\Report.ps1",
    "Checks\Section2.ps1",
    "Checks\Section5.ps1",
    "Checks\Section6.ps1",
    "Checks\Section7.ps1",
    "Checks\Section8.ps1",
    "Checks\Section9.ps1"
)) {
    $__full = Join-Path $moduleRoot $__f
    if (-not (Test-Path $__full)) { throw "Missing module file: $__full" }
    . $__full
}
Remove-Variable __f, __full -ErrorAction SilentlyContinue

# ── Apply settings ────────────────────────────────────────────────────────────

$script:DEBUG_MODE   = $DebugMode.IsPresent
$script:VERBOSE_MODE = $DebugMode.IsPresent -or ($VerbosePreference -eq "Continue")

# DebugMode forces sequential so parallel runspaces don't swallow output
if ($DebugMode.IsPresent -and $Parallel -gt 1) {
    $Parallel = 1
    Write-Host "  [DebugMode] Forcing sequential execution for full visibility." -ForegroundColor DarkYellow
}
$script:LOG_FILE     = if ($LogFile) { $LogFile } else { $null }

# ── Banner ────────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "`u{1F512} CIS Azure Foundations Benchmark v$($script:BENCHMARK_VER) — Audit Tool v$($script:CIS_VERSION)" -ForegroundColor Cyan
Write-Host ""

# ── Verify az CLI is available ────────────────────────────────────────────────

$azVerResult = Invoke-AzCli -Arguments @('version') -TimeoutSec 30
if (-not $azVerResult.Success) {
    Write-Host "`u{274C} Azure CLI not found or not working." -ForegroundColor Red
    if ($azVerResult.Error) { Write-Host "  Details: $($azVerResult.Error)" -ForegroundColor Red }
    Write-Host "  Install from: https://docs.microsoft.com/cli/azure/install-azure-cli" -ForegroundColor Red
    exit 1
}
$azCliVersion = if ($azVerResult.Data -and $azVerResult.Data.'azure-cli') { [string]$azVerResult.Data.'azure-cli' } else { '?' }
Write-Host "`u{2705} Azure CLI v$azCliVersion" -ForegroundColor Green

# ── Verify authentication and display identity ────────────────────────────────

$accountCtx = Invoke-AzCli -Arguments @("account", "show") -TimeoutSec 30
if (-not $accountCtx.Success) {
    Write-Host ""
    Write-Host "`u{274C} Not logged in to Azure CLI. Run 'az login' first." -ForegroundColor Red
    exit 1
}
$callerName = [string]$accountCtx.Data.user.name
$callerType = [string]$accountCtx.Data.user.type
$tenantId   = [string]$accountCtx.Data.tenantId
$typeLabel  = switch ($callerType) {
    'servicePrincipal' { 'Service Principal' }
    'user'             { 'User'              }
    default            { $callerType          }
}
Write-Host "`u{2705} Authenticated as: $callerName ($typeLabel)" -ForegroundColor Green
Write-Host "`u{2705} Tenant: $tenantId" -ForegroundColor Green

# ── ReportOnly: regenerate report from checkpoints and exit ───────────────────

if ($ReportOnly) {
    Write-Host ""
    Write-Host "`u{1F4CA} Report-only mode..." -ForegroundColor Cyan

    $checkpoints = Get-AuditCheckpoints
    if ($checkpoints.Count -eq 0) {
        Write-Host "`u{274C} No checkpoint data found in cis_checkpoints/. Run a full audit first." -ForegroundColor Red
        exit 1
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

    # Apply level filter
    if ($Level -eq "1") { $finalResults = @($finalResults | Where-Object { $_.Level -eq 1 }) }
    if ($Level -eq "2") { $finalResults = @($finalResults | Where-Object { $_.Level -eq 2 }) }

    # Summary
    $counts = @{ PASS=0; FAIL=0; ERROR=0; INFO=0; MANUAL=0; SUPPRESSED=0 }
    foreach ($r in $finalResults) { if ($counts.ContainsKey($r.Status)) { $counts[$r.Status]++ } }
    $assessed = $counts.PASS + $counts.FAIL + $counts.ERROR
    $score    = if ($assessed -gt 0) { [math]::Round(100.0 * $counts.PASS / $assessed, 1) } else { 0 }

    Write-Host ""
    Write-Host ("  " + "`u{2501}" * 60) -ForegroundColor DarkGray
    Write-Host ("  COMPLETE — {0} checks  |  {1} subscription(s)" -f $finalResults.Count, $subIds.Count) -ForegroundColor White
    Write-Host ("  Compliance Score : {0}%  (excludes INFO/MANUAL/SUPPRESSED)" -f $score) -ForegroundColor $(if ($score -ge 80) { "Green" } elseif ($score -ge 60) { "Yellow" } else { "Red" })
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
    exit 0
}

# ── Ensure resource-graph extension is present ───────────────────────────────

$rgCheck = Invoke-AzCli -Arguments @("extension", "list", "--query", "[?name=='resource-graph'].name") -TimeoutSec 30
if ($rgCheck.Success -and @($rgCheck.Data | Where-Object { $_ }).Count -gt 0) {
    Write-Host "`u{2705} resource-graph extension ready" -ForegroundColor Green
} else {
    Write-Host "`u{1F4E6} Installing resource-graph extension..." -ForegroundColor DarkYellow
    $rgInstall = Invoke-AzCli -Arguments @("extension", "add", "--name", "resource-graph") -TimeoutSec 120
    if (-not $rgInstall.Success) {
        Write-Host "`u{274C} Could not install resource-graph extension." -ForegroundColor Red
        Write-Host "  Run manually: az extension add --name resource-graph" -ForegroundColor Red
        exit 1
    }
    Write-Host "`u{2705} resource-graph extension installed" -ForegroundColor Green
}
Write-Host ""

# ── Resolve subscription list ─────────────────────────────────────────────────

Write-AuditLog "Resolving subscriptions..." -Level INFO

# Get ALL subscriptions (any state) so we can give accurate diagnostics
$allSubs = @(Get-SubscriptionList)

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
                Write-AuditLog "Subscription '$req' not found or not accessible. Check 'az account list --all'." -Level WARNING
            }
        }
    }

    # Only audit Enabled subscriptions (warn about others above)
    $subObjects = @($subObjects | Where-Object { [string]$_.state -eq 'Enabled' })
}

if ($subObjects.Count -eq 0) {
    Write-Host "No accessible subscriptions found. Check 'az account list' and ensure you are logged in." -ForegroundColor Red
    exit 1
}

$subIds   = @($subObjects | ForEach-Object { $_.id })
$subNames = @{}
foreach ($s in $subObjects) { $subNames[$s.id] = $s.name }

Write-Host ""
Write-Host ("`u{1F4CB} Subscriptions ({0}):" -f $subObjects.Count) -ForegroundColor White
foreach ($s in $subObjects) {
    Write-Host ("   `u{2022} {0}  ({1})" -f ([string]$s.name), ([string]$s.id)) -ForegroundColor DarkGray
}
Write-Host ""

Write-AuditLog "Auditing $($subIds.Count) subscription(s): $($subIds -join ', ')" -Level INFO

# ── Permission preflight ─────────────────────────────────────────────────────

if (-not $NoPermissionCheck) {
    Write-Host "`u{1F510} Checking permissions…" -ForegroundColor DarkGray
    $permCheck = Test-AuditPermissions -SubscriptionIds $subIds -SubNames $subNames

    # Show aggregated role summary (mirrors Python output)
    if ($permCheck.UserId) {
        Write-Host "   User: $callerName\" -ForegroundColor DarkCyan
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

# ── Load checkpoints (auto-resume unless -Fresh or -NoCheckpoint) ─────────────

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
        $skippedNames = @($checkpoints.Keys | ForEach-Object { $subNames[$_] }) | Where-Object { $_ }
        if ($skippedNames.Count -gt 0) {
            Write-AuditLog "`u{23ED}`u{FE0F}  Skipping (already audited): $($skippedNames -join ', ')" -Level INFO
        }
    }
}

# ── Resource Graph prefetch ───────────────────────────────────────────────────

$auditStopwatch = [System.Diagnostics.Stopwatch]::StartNew()

Write-AuditLog "`u{1F4E1} Fetching tenant data via Resource Graph..." -Level INFO

# Only prefetch for subscriptions NOT covered by checkpoints
$subIdsToAudit = @($subIds | Where-Object { -not $checkpoints.ContainsKey($_) })

$prefetchData = @{}   # key -> { sub_id_lower -> [records] }

# ── All subscriptions already audited ─────────────────────────────────────────
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
            $prefetchData[$queryName] = @{}
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
    Write-AuditLog "Prefetch complete. $($prefetchData.Count) resource type(s) cached." -Level INFO
}

# ── Tenant-level checks ───────────────────────────────────────────────────────

$allResults = [System.Collections.Generic.List[object]]::new()

if (-not $SkipTenantChecks) {
    $tenantCheckpoint = Get-TenantCheckpoint
    if ($tenantCheckpoint -and $subIdsToAudit.Count -eq 0) {
        Write-AuditLog "   `u{1F4BE} Loaded tenant checks from checkpoint ($($tenantCheckpoint.Count) results)." -Level INFO
        foreach ($r in $tenantCheckpoint) { $allResults.Add($r) }
    } else {
        Write-AuditLog "Running tenant-level checks (Section 5)..." -Level INFO
        try {
            $tenantResults = @(Invoke-Section5TenantChecks)
            foreach ($r in $tenantResults) { $allResults.Add($r) }
            if (-not $NoCheckpoint) { Save-TenantCheckpoint -Results $tenantResults }
            Write-AuditLog "Tenant checks: $($tenantResults.Count) results." -Level INFO
        } catch {
            Write-AuditLog "Tenant-level check error: $_" -Level WARNING
        }
    }
}

# ── Per-subscription audit ────────────────────────────────────────────────────

function Invoke-SubscriptionAudit {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification='Parameters used inside scriptblock closures')]
    param([string]$SubId, [string]$SubName, [hashtable]$PrefetchData)

    $subResults = [System.Collections.Generic.List[object]]::new()

    $checkGroups = @(
        @{ Name = "Section 2 (Databricks)"; Fn = { Invoke-Section2Checks -SubscriptionId $SubId -SubscriptionName $SubName -PrefetchData $PrefetchData } }
        @{ Name = "Section 5 (Identity)";   Fn = { Invoke-Section5SubscriptionChecks -SubscriptionId $SubId -SubscriptionName $SubName -PrefetchData $PrefetchData } }
        @{ Name = "Section 6 (Monitoring)"; Fn = { Invoke-Section6Checks -SubscriptionId $SubId -SubscriptionName $SubName -PrefetchData $PrefetchData } }
        @{ Name = "Section 7 (Networking)"; Fn = { Invoke-Section7Checks -SubscriptionId $SubId -SubscriptionName $SubName -PrefetchData $PrefetchData } }
        @{ Name = "Section 8 (Security)";   Fn = { Invoke-Section8Checks -SubscriptionId $SubId -SubscriptionName $SubName -PrefetchData $PrefetchData } }
        @{ Name = "Section 9 (Storage)";    Fn = { Invoke-Section9Checks -SubscriptionId $SubId -SubscriptionName $SubName -PrefetchData $PrefetchData } }
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
            Write-AuditLog "    [$SubName] $($group.Name) done — $($groupResults.Count) result(s) in $($sw.Elapsed.TotalSeconds.ToString('F1'))s" -Level DEBUG
        } catch {
            Write-AuditLog "$($group.Name) error for ${SubName}: $_" -Level WARNING
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
            }
        }
    } else {
        # Parallel execution using PS7 ForEach-Object -Parallel
        $throttle   = [math]::Min($Parallel, $subsToProcess.Count)
        $resultBag  = [System.Collections.Concurrent.ConcurrentBag[object]]::new()
        $moduleRoot_ = $moduleRoot

        # Pre-build array of [id, name, index] — $using: can't index into hashtables
        $subPairs = @(for ($i = 0; $i -lt $subsToProcess.Count; $i++) {
            [PSCustomObject]@{ Id = $subsToProcess[$i]; Name = $subNames[$subsToProcess[$i]]; Idx = $i + 1 }
        })
        $totalToProcess = $subsToProcess.Count

        Write-AuditLog "Running parallel audit ($throttle concurrent workers)..." -Level INFO

        $subPairs | ForEach-Object -Parallel {
            $subId         = $_.Id
            $subName       = $_.Name
            $subIdx        = $_.Idx
            $subTotal      = $using:totalToProcess
            $pd            = $using:prefetchData
            $modRoot       = $using:moduleRoot_
            $noCheckpoint  = $using:NoCheckpoint
            $bag           = $using:resultBag

            Write-Host "  [$subIdx/$subTotal] Starting:  $subName" -ForegroundColor DarkCyan

            # Re-import all module files in the parallel runspace
            $files = @(
                "Private\Config.ps1","Private\Models.ps1","Private\AzureClient.ps1",
                "Private\Helpers.ps1","Private\CheckHelpers.ps1","Private\Identity.ps1",
                "Private\Checkpoint.ps1","Private\History.ps1","Private\Report.ps1",
                "Checks\Section2.ps1","Checks\Section5.ps1","Checks\Section6.ps1",
                "Checks\Section7.ps1","Checks\Section8.ps1","Checks\Section9.ps1"
            )
            foreach ($f in $files) { . (Join-Path $modRoot $f) }

            try {
                $checkGroups = @(
                    @{ Name = "Section 2 (Databricks)"; Fn = { Invoke-Section2Checks -SubscriptionId $subId -SubscriptionName $subName -PrefetchData $pd } }
                    @{ Name = "Section 5 (Identity)";   Fn = { Invoke-Section5SubscriptionChecks -SubscriptionId $subId -SubscriptionName $subName -PrefetchData $pd } }
                    @{ Name = "Section 6 (Monitoring)"; Fn = { Invoke-Section6Checks -SubscriptionId $subId -SubscriptionName $subName -PrefetchData $pd } }
                    @{ Name = "Section 7 (Networking)"; Fn = { Invoke-Section7Checks -SubscriptionId $subId -SubscriptionName $subName -PrefetchData $pd } }
                    @{ Name = "Section 8 (Security)";   Fn = { Invoke-Section8Checks -SubscriptionId $subId -SubscriptionName $subName -PrefetchData $pd } }
                    @{ Name = "Section 9 (Storage)";    Fn = { Invoke-Section9Checks -SubscriptionId $subId -SubscriptionName $subName -PrefetchData $pd } }
                )

                $subResults = [System.Collections.Generic.List[object]]::new()
                foreach ($g in $checkGroups) {
                    Write-Host "    [$subName] $($g.Name)..." -ForegroundColor DarkGray
                    try {
                        foreach ($r in @(& $g.Fn)) { $subResults.Add($r) }
                    } catch {
                        [Console]::Error.WriteLine("[PARALLEL-CHECK-ERROR] ${subName}: $_")
                    }
                }

                foreach ($r in $subResults) { $bag.Add($r) }

                if (-not $noCheckpoint) {
                    Save-AuditCheckpoint -SubscriptionId $subId -SubscriptionName $subName -Results $subResults.ToArray()
                }

                Write-Host "  [$subIdx/$subTotal] Completed: $subName — $($subResults.Count) results" -ForegroundColor Green
            } catch { $null = $_ <# Intentional: per-subscription errors are logged inside; prevent ForEach-Object -Parallel from terminating #> }

        } -ThrottleLimit $throttle

        foreach ($r in $resultBag) { $allResults.Add($r) }
    }
}

$auditStopwatch.Stop()
$elapsed = $auditStopwatch.Elapsed
$elapsedStr = if ($elapsed.TotalMinutes -ge 1) { "{0}m {1}s" -f [int][math]::Floor($elapsed.TotalMinutes), $elapsed.Seconds } else { "{0}s" -f $elapsed.TotalSeconds.ToString('F1') }
Write-AuditLog "Audit complete. $($allResults.Count) total results in $elapsedStr." -Level INFO

# ── Apply level filter ────────────────────────────────────────────────────────

$finalResults = Remove-DuplicateResults -Results $allResults.ToArray()
if ($Level -eq "1") { $finalResults = @($finalResults | Where-Object { $_.Level -eq 1 }) }
if ($Level -eq "2") { $finalResults = @($finalResults | Where-Object { $_.Level -eq 2 }) }

# ── Summary to console ────────────────────────────────────────────────────────

$counts = @{ PASS=0; FAIL=0; ERROR=0; INFO=0; MANUAL=0; SUPPRESSED=0 }
foreach ($r in $finalResults) { if ($counts.ContainsKey($r.Status)) { $counts[$r.Status]++ } }

$assessed  = $counts.PASS + $counts.FAIL + $counts.ERROR
$score     = if ($assessed -gt 0) { [math]::Round(100.0 * $counts.PASS / $assessed, 1) } else { 0 }

Write-Host ""
Write-Host ("  " + "`u{2501}" * 60) -ForegroundColor DarkGray
Write-Host ("  COMPLETE — {0} checks  |  {1} subscription(s)  |  `u{23F1} {2}" -f $finalResults.Count, $subIds.Count, $elapsedStr) -ForegroundColor White
Write-Host ("  Compliance Score : {0}%  (excludes INFO/MANUAL/SUPPRESSED)" -f $score) -ForegroundColor $(if ($score -ge 80) { "Green" } elseif ($score -ge 60) { "Yellow" } else { "Red" })
Write-Host ("`u{2705} PASS         {0,4}" -f $counts.PASS)       -ForegroundColor Green
Write-Host ("`u{274C} FAIL         {0,4}" -f $counts.FAIL)       -ForegroundColor Red
Write-Host ("`u{26A0}`u{FE0F}  ERROR        {0,4}" -f $counts.ERROR)      -ForegroundColor DarkYellow
Write-Host ("`u{2139}`u{FE0F}  INFO         {0,4}" -f $counts.INFO)       -ForegroundColor Blue
Write-Host ("`u{1F4CB} MANUAL       {0,4}" -f $counts.MANUAL)     -ForegroundColor DarkMagenta
Write-Host ("`u{1F507} SUPPRESSED   {0,4}" -f $counts.SUPPRESSED) -ForegroundColor DarkGray
Write-Host ("  " + "`u{2501}" * 60) -ForegroundColor DarkGray
Write-Host ""

# ── Generate HTML report ──────────────────────────────────────────────────────

$scopeLabel = if ($Subscriptions.Count -eq 0) {
    "All subscriptions (tenant-wide)"
} else {
    "Selected: $(($subObjects | ForEach-Object { $_.name }) -join ', ')"
}

# ── Collect identity context for report scope block ─────────────────────────
# $accountCtx was collected at startup (az account show); reuse it here.
$scopeInfo   = @{
    tenant       = if ($accountCtx.Success -and $accountCtx.Data.tenantId) { [string]$accountCtx.Data.tenantId } else { '' }
    user         = if ($accountCtx.Success -and $accountCtx.Data.user)     { [string]$accountCtx.Data.user.name } else { '' }
    caller_type  = if ($accountCtx.Success -and $accountCtx.Data.user)     { [string]$accountCtx.Data.user.type } else { '' }
    scope_label  = $scopeLabel
    subscriptions = @($subObjects | ForEach-Object { [string]$_.name })
    level_filter = $Level
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

# ── Open report in default browser ─────────────────────────────────────────────
if (-not $NoOpen) {
    try { Invoke-Item ([System.IO.Path]::GetFullPath($Output)) } catch { $null = $_ }
}
