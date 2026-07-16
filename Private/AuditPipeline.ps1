# Audit pipeline stages shared by the orchestrator's code paths.
#
# The report/summary tail (dedupe -> suppressions -> level filter -> score ->
# console summary -> HTML report -> history -> exit code) used to exist twice in
# Public\Invoke-CISAzureAudit.ps1 — once for the full run and once for -ReportOnly —
# and the two copies had already drifted in small ways. Both paths now call
# Complete-AuditRun.

function New-AuditRunSummary {
    <#
    .SYNOPSIS
    Uniform result contract for every orchestrator code path (setup failure,
    ReportOnly, full run).
    #>
    param(
        [int]$Code,
        [string]$Reason = "",
        [hashtable]$Counts = $null,
        $Score = $null,
        [string]$ReportPath = "",
        [AllowEmptyCollection()][object[]]$Results = @(),
        [int]$SubscriptionCount = 0,
        [string]$Elapsed = ""
    )
    [PSCustomObject]@{
        PSTypeName        = 'CISAzureFoundationsBenchmark.AuditSummary'
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

function Complete-AuditRun {
    <#
    .SYNOPSIS
    Final pipeline stage: turn raw results into the report and the typed summary.

    .DESCRIPTION
    Deduplicates, applies suppressions and the level filter, computes the score,
    prints the console summary, writes the HTML/JSON/CSV/SARIF report, optionally
    appends the run to history, opens the report, and returns the AuditSummary.
    Used by both the full-run and -ReportOnly paths of Invoke-CISAzureAudit.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Results,
        [Parameter(Mandatory)][string]$OutputPath,
        [Parameter(Mandatory)][string]$SuppressionsFile,
        [Parameter(Mandatory)][string]$Level,
        [Parameter(Mandatory)][string]$ScopeLabel,
        [Parameter(Mandatory)][string]$Tenant,
        [Parameter(Mandatory)][string]$CallerName,
        [Parameter(Mandatory)][string]$CallerType,
        [AllowEmptyCollection()][string[]]$SubscriptionNames = @(),
        [hashtable]$SubTimestamps = @{},
        [int]$SubscriptionCount = 0,
        [switch]$AppendHistory,
        [AllowEmptyCollection()][string[]]$HistorySubscriptionIds = @(),
        [string]$ElapsedLabel = "",
        [string]$CompareWith = "",
        [switch]$SetExitCode,
        [switch]$NoOpen
    )

    # ── Dedupe, suppressions, level filter ────────────────────────────────────
    $suppressions = @(Get-Suppressions -Path $SuppressionsFile)
    $finalResults = Remove-DuplicateResults -Results $Results
    $finalResults = @(Invoke-Suppressions -Results $finalResults -Suppressions $suppressions)

    if ($Level -eq "1") { $finalResults = @($finalResults | Where-Object { $_.Level -eq 1 }) }
    if ($Level -eq "2") { $finalResults = @($finalResults | Where-Object { $_.Level -eq 2 }) }

    # ── Score & console summary ───────────────────────────────────────────────
    $counts   = Get-AuditCounts -Results $finalResults
    $assessed = Get-AssessedCount -Counts $counts
    $score    = Get-AuditScore -Counts $counts

    $completeLine = "  COMPLETE — {0} checks  |  {1} subscription(s)" -f $finalResults.Count, $SubscriptionCount
    if ($ElapsedLabel) { $completeLine += "  |  `u{23F1} $ElapsedLabel" }

    Write-Host ""
    Write-Host ("  " + "`u{2501}" * 60) -ForegroundColor DarkGray
    Write-Host $completeLine -ForegroundColor White
    Write-Host ("  Compliance Score : {0}%  ({1} of {2} assessed controls; ERROR counts as failing, excludes INFO/MANUAL/SUPPRESSED)" -f $score, $counts.PASS, $assessed) -ForegroundColor $(if ($score -ge 80) { "Green" } elseif ($score -ge 60) { "Yellow" } else { "Red" })
    Write-Host ("`u{2705} PASS         {0,4}" -f $counts.PASS)       -ForegroundColor Green
    Write-Host ("`u{274C} FAIL         {0,4}" -f $counts.FAIL)       -ForegroundColor Red
    Write-Host ("`u{26A0}`u{FE0F}  ERROR        {0,4}" -f $counts.ERROR)      -ForegroundColor DarkYellow
    Write-Host ("`u{2139}`u{FE0F}  INFO         {0,4}" -f $counts.INFO)       -ForegroundColor Blue
    Write-Host ("`u{1F4CB} MANUAL       {0,4}" -f $counts.MANUAL)     -ForegroundColor DarkMagenta
    Write-Host ("`u{1F507} SUPPRESSED   {0,4}" -f $counts.SUPPRESSED) -ForegroundColor DarkGray
    Write-Host ("  " + "`u{2501}" * 60) -ForegroundColor DarkGray
    Write-Host ""

    # ── Run-to-run diff (optional) ────────────────────────────────────────────
    $diff = $null
    if ($CompareWith) {
        $baselinePath = if ($CompareWith -eq 'auto') { Find-PreviousReportJson -OutputPath $OutputPath } else { $CompareWith }
        if ($baselinePath -and (Test-Path $baselinePath)) {
            try {
                $prev = @(Get-Content $baselinePath -Raw -Encoding UTF8 | ConvertFrom-Json -Depth 5)
                $diff = Get-RunDiff -CurrentResults $finalResults -PreviousResults $prev
                $diffPath = [System.IO.Path]::ChangeExtension($OutputPath, '.diff.json')
                Write-RunDiffJson -Diff $diff -BaselinePath $baselinePath -OutputPath $diffPath
                Write-Host ("  Diff vs {0}: {1} regression(s), {2} improvement(s), {3} new, {4} removed  `u{2192} {5}" -f `
                    (Split-Path $baselinePath -Leaf), $diff.Regressions.Count, $diff.Improvements.Count, `
                    $diff.New.Count, $diff.Removed.Count, (Split-Path $diffPath -Leaf)) -ForegroundColor Cyan
            } catch {
                Write-AuditLog "Could not diff against '$baselinePath': $_" -Level WARNING
                $diff = $null
            }
        } else {
            Write-AuditLog "CompareWith baseline not found ($CompareWith) — skipping run diff." -Level WARNING
        }
    }

    # ── Report + history ──────────────────────────────────────────────────────
    $scopeInfo = @{
        tenant        = $Tenant
        user          = $CallerName
        caller_type   = $CallerType
        scope_label   = $ScopeLabel
        subscriptions = @($SubscriptionNames)
        level_filter  = $Level
    }

    $historyPath = Get-HistoryPathFor -OutputPath $OutputPath
    $history     = @(Get-AuditHistory -HistoryPath $historyPath)

    New-CISHtmlReport -Results $finalResults -OutputPath $OutputPath -ScopeLabel $ScopeLabel -History $history -ScopeInfo $scopeInfo -SubTimestamps $SubTimestamps -Diff $diff

    if ($AppendHistory) {
        Add-AuditHistoryEntry -HistoryPath $historyPath -Results $finalResults -SubscriptionIds $HistorySubscriptionIds
    }

    Write-Host "  Report: $([System.IO.Path]::GetFullPath($OutputPath))" -ForegroundColor Cyan
    Write-Host ""
    if (-not $NoOpen) {
        try { Invoke-Item ([System.IO.Path]::GetFullPath($OutputPath)) } catch { $null = $_ }
    }

    # ── Exit code & summary ───────────────────────────────────────────────────
    $code = if ($SetExitCode -and ($counts.FAIL + $counts.ERROR) -gt 0) { 2 } else { 0 }
    New-AuditRunSummary -Code $code -Counts $counts -Score $score `
        -ReportPath ([System.IO.Path]::GetFullPath($OutputPath)) -Results $finalResults `
        -SubscriptionCount $SubscriptionCount -Elapsed $ElapsedLabel
}
