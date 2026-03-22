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

.PARAMETER Resume
    Resume from saved checkpoints (skip already-audited subscriptions).

.PARAMETER SkipTenantChecks
    Skip tenant-level checks (Section 5: 5.1.1, 5.1.2, etc.).

.PARAMETER NoPermissionCheck
    Skip preflight permission verification.

.PARAMETER Level
    Only include Level 1, Level 2, or both (default: both).

.PARAMETER Debug
    Enable debug logging.

.PARAMETER LogFile
    Optional path to write a log file.

.EXAMPLE
    .\Invoke-CISAzureAudit.ps1

.EXAMPLE
    .\Invoke-CISAzureAudit.ps1 -Subscriptions "sub-id-1","sub-id-2" -Output report.html -Parallel 5

.EXAMPLE
    .\Invoke-CISAzureAudit.ps1 -Resume
#>

[CmdletBinding(PositionalBinding=$false)]
param(
    [string[]]$Subscriptions      = @(),
    [string]  $Output             = "",
    [int]     $Parallel           = 3,
    [switch]  $NoCheckpoint,
    [switch]  $Resume,
    [switch]  $SkipTenantChecks,
    [switch]  $NoPermissionCheck,
    [ValidateSet("1","2","both")]
    [string]  $Level              = "both",
    [switch]  $DebugMode,
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
Write-Host "  CIS Azure Benchmark Audit — PowerShell Edition" -ForegroundColor Cyan
Write-Host "  Benchmark: CIS Microsoft Azure Foundations Benchmark v$($script:BENCHMARK_VER)" -ForegroundColor DarkCyan
Write-Host "  Tool:      v$($script:CIS_VERSION)" -ForegroundColor DarkCyan
Write-Host ""

# ── Verify az CLI is available ────────────────────────────────────────────────

$azVerResult = Invoke-AzCli -Arguments @('version') -TimeoutSec 30
if (-not $azVerResult.Success) {
    Write-Host "  ERROR: Azure CLI not found or not working." -ForegroundColor Red
    if ($azVerResult.Error) { Write-Host "  Details: $($azVerResult.Error)" -ForegroundColor Red }
    Write-Host "  Install from: https://docs.microsoft.com/cli/azure/install-azure-cli" -ForegroundColor Red
    exit 1
}
$azCliVersion = if ($azVerResult.Data -and $azVerResult.Data.'azure-cli') { [string]$azVerResult.Data.'azure-cli' } else { '?' }
Write-Host "  Azure CLI:        v$azCliVersion" -ForegroundColor DarkGray

# ── Verify authentication and display identity ────────────────────────────────

$accountCtx = Invoke-AzCli -Arguments @("account", "show") -TimeoutSec 30
if (-not $accountCtx.Success) {
    Write-Host ""
    Write-Host "  ERROR: Not logged in to Azure CLI. Run 'az login' first." -ForegroundColor Red
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
Write-Host "  Authenticated as: $callerName  ($typeLabel)" -ForegroundColor Green
Write-Host "  Tenant ID:        $tenantId" -ForegroundColor DarkGray

# ── Ensure resource-graph extension is present ───────────────────────────────

$rgCheck = Invoke-AzCli -Arguments @("extension", "list", "--query", "[?name=='resource-graph'].name") -TimeoutSec 30
if ($rgCheck.Success -and @($rgCheck.Data | Where-Object { $_ }).Count -gt 0) {
    Write-Host "  resource-graph:   ready" -ForegroundColor DarkGray
} else {
    Write-Host "  resource-graph:   installing extension..." -ForegroundColor DarkYellow
    $rgInstall = Invoke-AzCli -Arguments @("extension", "add", "--name", "resource-graph") -TimeoutSec 120
    if (-not $rgInstall.Success) {
        Write-Host "  ERROR: Could not install resource-graph extension." -ForegroundColor Red
        Write-Host "  Run manually: az extension add --name resource-graph" -ForegroundColor Red
        exit 1
    }
    Write-Host "  resource-graph:   installed" -ForegroundColor Green
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

Write-Host ("  Subscriptions ({0}):" -f $subObjects.Count) -ForegroundColor White
foreach ($s in $subObjects) {
    Write-Host ("    • {0}  ({1})" -f ([string]$s.name), ([string]$s.id)) -ForegroundColor DarkGray
}
Write-Host ""

Write-AuditLog "Auditing $($subIds.Count) subscription(s): $($subIds -join ', ')" -Level INFO

# ── Permission preflight ─────────────────────────────────────────────────────

if (-not $NoPermissionCheck) {
    Write-Host "  Permission preflight..." -ForegroundColor White
    $permCheck = Test-AuditPermissions -SubscriptionIds $subIds -SubNames $subNames
    if ($permCheck.Warnings.Count -gt 0) {
        foreach ($w in $permCheck.Warnings) {
            Write-Host "  WARNING: $w" -ForegroundColor DarkYellow
            Write-AuditLog $w -Level WARNING
        }
        Write-Host "  Some permissions could not be verified — the audit will continue but some checks may show ERROR." -ForegroundColor DarkYellow
    } else {
        Write-Host "  Permission check passed." -ForegroundColor Green
    }
    Write-Host ""
}

# ── Load checkpoints if resuming ──────────────────────────────────────────────

$checkpoints = @{}
if ($Resume -and -not $NoCheckpoint) {
    $checkpoints = Get-AuditCheckpoints
    $resumedCount = $checkpoints.Count
    if ($resumedCount -gt 0) {
        Write-AuditLog "Resuming from $resumedCount checkpoint(s)." -Level INFO
    }
}

# ── Resource Graph prefetch ───────────────────────────────────────────────────

Write-AuditLog "Prefetching resource data via Azure Resource Graph..." -Level INFO

# Only prefetch for subscriptions NOT covered by checkpoints
$subIdsToAudit = @($subIds | Where-Object { -not $checkpoints.ContainsKey($_) })

$prefetchData = @{}   # key -> { sub_id_lower -> [records] }

if ($subIdsToAudit.Count -gt 0) {
    foreach ($queryName in $script:GRAPH_QUERIES.Keys) {
        Write-AuditLog "  Prefetch: $queryName..." -Level DEBUG
        $r = Invoke-AzGraphQuery -Query $script:GRAPH_QUERIES[$queryName] -SubscriptionIds $subIdsToAudit

        if (-not $r.Success) {
            Write-AuditLog "Resource Graph query '$queryName' failed: $($r.Error)" -Level WARNING
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
        Write-AuditLog "    ${queryName}: $totalRecords record(s) across $($final.Keys.Count) subscription(s)" -Level VERBOSE
    }
    Write-AuditLog "Prefetch complete. $($prefetchData.Count) resource type(s) cached." -Level INFO
}

# ── Tenant-level checks ───────────────────────────────────────────────────────

$allResults = [System.Collections.Generic.List[object]]::new()

if (-not $SkipTenantChecks) {
    Write-AuditLog "Running tenant-level checks (Section 5)..." -Level INFO
    try {
        $tenantResults = @(Invoke-Section5TenantChecks)
        foreach ($r in $tenantResults) { $allResults.Add($r) }
        Write-AuditLog "Tenant checks: $($tenantResults.Count) results." -Level INFO
    } catch {
        Write-AuditLog "Tenant-level check error: $_" -Level WARNING
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
        Write-AuditLog "  -> $($group.Name)" -Level DEBUG
        try {
            $groupResults = @(& $group.Fn)
            foreach ($r in $groupResults) {
                $statusPad = $r.Status.PadRight(8)
                $res = if ($r.Resource) { " [$($r.Resource)]" } else { "" }
                $det = ($r.Details -replace "`r?`n", ' ').Trim()
                if ($det.Length -gt 90) { $det = $det.Substring(0, 90) + '...' }
                Write-AuditLog "     [$statusPad] $($r.ControlId.PadRight(12))$res $det" -Level VERBOSE
                $subResults.Add($r)
            }
            $sw.Stop()
            Write-AuditLog "     $($group.Name) done — $($groupResults.Count) result(s) in $($sw.Elapsed.TotalSeconds.ToString('F1'))s" -Level DEBUG
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
        Write-AuditLog "Using checkpoint for: $($cp.SubscriptionName) ($subId) [$($cp.Timestamp)]" -Level INFO
        foreach ($r in @($cp.Results)) { $allResults.Add($r) }
    }
}

# Audit remaining subscriptions
$subsToProcess = @($subIdsToAudit)

if ($subsToProcess.Count -gt 0) {
    if ($Parallel -le 1 -or $subsToProcess.Count -eq 1) {
        # Sequential execution
        foreach ($subId in $subsToProcess) {
            $subName = $subNames[$subId]
            Write-AuditLog "Auditing: $subName ($subId)" -Level INFO

            try {
                $subResults = Invoke-SubscriptionAudit -SubId $subId -SubName $subName -PrefetchData $prefetchData

                foreach ($r in $subResults) { $allResults.Add($r) }

                if (-not $NoCheckpoint) {
                    Save-AuditCheckpoint -SubscriptionId $subId -SubscriptionName $subName -Results $subResults
                }

                Write-AuditLog "  Done: $subName — $($subResults.Count) results" -Level INFO
            } catch {
                Write-AuditLog "Fatal error auditing $subName`: $_" -Level WARNING
            }
        }
    } else {
        # Parallel execution using PS7 ForEach-Object -Parallel
        $throttle   = [math]::Min($Parallel, $subsToProcess.Count)
        $resultBag  = [System.Collections.Concurrent.ConcurrentBag[object]]::new()
        $moduleRoot_ = $moduleRoot

        # Pre-build array of [id, name] pairs — $using: can't index into hashtables
        $subPairs = @($subsToProcess | ForEach-Object { [PSCustomObject]@{ Id = $_; Name = $subNames[$_] } })

        Write-AuditLog "Running parallel audit ($throttle concurrent workers)..." -Level INFO

        $subPairs | ForEach-Object -Parallel {
            $subId         = $_.Id
            $subName       = $_.Name
            $pd            = $using:prefetchData
            $modRoot       = $using:moduleRoot_
            $noCheckpoint  = $using:NoCheckpoint
            $bag           = $using:resultBag

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
                    @{ Fn = { Invoke-Section2Checks -SubscriptionId $subId -SubscriptionName $subName -PrefetchData $pd } }
                    @{ Fn = { Invoke-Section5SubscriptionChecks -SubscriptionId $subId -SubscriptionName $subName -PrefetchData $pd } }
                    @{ Fn = { Invoke-Section6Checks -SubscriptionId $subId -SubscriptionName $subName -PrefetchData $pd } }
                    @{ Fn = { Invoke-Section7Checks -SubscriptionId $subId -SubscriptionName $subName -PrefetchData $pd } }
                    @{ Fn = { Invoke-Section8Checks -SubscriptionId $subId -SubscriptionName $subName -PrefetchData $pd } }
                    @{ Fn = { Invoke-Section9Checks -SubscriptionId $subId -SubscriptionName $subName -PrefetchData $pd } }
                )

                $subResults = [System.Collections.Generic.List[object]]::new()
                foreach ($g in $checkGroups) {
                    try {
                        foreach ($r in @(& $g.Fn)) { $subResults.Add($r) }
                    } catch {
                        # Log to stderr — visible in the parent host when -DebugMode is on
                        [Console]::Error.WriteLine("[PARALLEL-CHECK-ERROR] ${subName}: $_")
                    }
                }

                foreach ($r in $subResults) { $bag.Add($r) }

                if (-not $noCheckpoint) {
                    Save-AuditCheckpoint -SubscriptionId $subId -SubscriptionName $subName -Results $subResults.ToArray()
                }
            } catch { $null = $_ <# Intentional: per-subscription errors are logged inside; prevent ForEach-Object -Parallel from terminating #> }

        } -ThrottleLimit $throttle

        foreach ($r in $resultBag) { $allResults.Add($r) }
    }
}

Write-AuditLog "Audit complete. $($allResults.Count) total results." -Level INFO

# ── Apply level filter ────────────────────────────────────────────────────────

$finalResults = @($allResults)
if ($Level -eq "1") { $finalResults = @($finalResults | Where-Object { $_.Level -eq 1 }) }
if ($Level -eq "2") { $finalResults = @($finalResults | Where-Object { $_.Level -eq 2 }) }

# ── Summary to console ────────────────────────────────────────────────────────

$counts = @{ PASS=0; FAIL=0; ERROR=0; INFO=0; MANUAL=0; SUPPRESSED=0 }
foreach ($r in $finalResults) { if ($counts.ContainsKey($r.Status)) { $counts[$r.Status]++ } }

$assessed  = $counts.PASS + $counts.FAIL + $counts.ERROR
$score     = if ($assessed -gt 0) { [math]::Round(100.0 * $counts.PASS / $assessed, 1) } else { 0 }

Write-Host ""
Write-Host "  Results Summary" -ForegroundColor White
Write-Host "  ──────────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host ("  Compliance Score  : {0}% ({1} of {2} assessed controls)" -f $score, $counts.PASS, $assessed) -ForegroundColor $(if ($score -ge 80) { "Green" } elseif ($score -ge 60) { "Yellow" } else { "Red" })
Write-Host ("  PASS              : {0}" -f $counts.PASS)       -ForegroundColor Green
Write-Host ("  FAIL              : {0}" -f $counts.FAIL)       -ForegroundColor Red
Write-Host ("  ERROR             : {0}" -f $counts.ERROR)      -ForegroundColor DarkYellow
Write-Host ("  INFO / N/A        : {0}" -f $counts.INFO)       -ForegroundColor Blue
Write-Host ("  MANUAL            : {0}" -f $counts.MANUAL)     -ForegroundColor DarkMagenta
Write-Host ("  SUPPRESSED        : {0}" -f $counts.SUPPRESSED) -ForegroundColor DarkGray
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
