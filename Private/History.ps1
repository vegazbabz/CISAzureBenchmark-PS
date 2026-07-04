# Compliance trend tracking — persists summary of each full audit run

$script:MAX_HISTORY = 30

function Get-AuditHistory {
    <#
    .SYNOPSIS
    Load run history from the JSON history file.
    Returns array of history entries (newest last).
    #>
    param([string]$HistoryPath)

    if (-not (Test-Path $HistoryPath)) { return @() }
    try {
        $raw = Get-Content $HistoryPath -Encoding UTF8 -Raw
        return @(($raw | ConvertFrom-Json -Depth 10))
    } catch {
        Write-AuditLog "Could not load run history: $_" -Level WARNING
        return @()
    }
}

function Add-AuditHistoryEntry {
    <#
    .SYNOPSIS
    Append a summary of the current run to the history file.
    Trims history to MAX_HISTORY entries.
    #>
    param(
        [string]$HistoryPath,
        [object[]]$Results,
        [string[]]$SubscriptionIds
    )

    $existing = [System.Collections.Generic.List[object]]::new()
    foreach ($e in (Get-AuditHistory -HistoryPath $HistoryPath)) { $existing.Add($e) }

    $counts = @{ PASS = 0; FAIL = 0; ERROR = 0; INFO = 0; MANUAL = 0; SUPPRESSED = 0 }
    foreach ($r in $Results) {
        if ($counts.ContainsKey($r.Status)) { $counts[$r.Status]++ }
    }

    $assessed = $counts.PASS + $counts.FAIL + $counts.ERROR
    $score    = if ($assessed -gt 0) { [math]::Round(100.0 * $counts.PASS / $assessed, 1) } else { 0 }

    $entry = [PSCustomObject]@{
        timestamp     = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
        version       = $script:CIS_VERSION
        score         = $score
        pass          = $counts.PASS
        fail          = $counts.FAIL
        error         = $counts.ERROR
        info          = $counts.INFO
        manual        = $counts.MANUAL
        suppressed    = $counts.SUPPRESSED
        total         = $Results.Count
        subscriptions = $SubscriptionIds.Count
    }

    $existing.Add($entry)
    while ($existing.Count -gt $script:MAX_HISTORY) { $existing.RemoveAt(0) }

    $tmpPath = "$HistoryPath.tmp"
    # -InputObject keeps a single-entry history serialized as a JSON array
    ConvertTo-Json -InputObject @($existing) -Depth 5 | Set-Content -Path $tmpPath -Encoding UTF8
    Move-Item -Path $tmpPath -Destination $HistoryPath -Force
}

function Get-HistoryPathFor {
    <#
    .SYNOPSIS
    Return the history file path co-located with the HTML output file.
    #>
    param([string]$OutputPath)
    $dir  = Split-Path $OutputPath -Parent
    $name = "cis_run_history.json"
    if ($dir) { Join-Path $dir $name } else { $name }
}
