# Scoring — the single source of the compliance-score policy.
#
# The rule (PASS / (PASS+FAIL+ERROR); ERROR counts as failing; INFO/MANUAL/SUPPRESSED
# excluded) is enforced here and nowhere else. Console summary, HTML report, run
# history, and the exit code all call these functions, so the score can never drift
# between outputs.

function Get-AuditCounts {
    <#
    .SYNOPSIS
    Count results per status. Returns a hashtable keyed PASS/FAIL/ERROR/INFO/MANUAL/
    SUPPRESSED; unknown statuses are ignored.
    #>
    param([AllowEmptyCollection()][object[]]$Results = @())

    $counts = @{ PASS = 0; FAIL = 0; ERROR = 0; INFO = 0; MANUAL = 0; SUPPRESSED = 0 }
    foreach ($r in $Results) {
        if ($counts.ContainsKey($r.Status)) { $counts[$r.Status]++ }
    }
    return $counts
}

function Get-AssessedCount {
    <#
    .SYNOPSIS
    Number of scored controls: PASS + FAIL + ERROR (INFO/MANUAL/SUPPRESSED excluded).
    Accepts any hashtable with those keys, so per-level breakdowns work too.
    #>
    param([Parameter(Mandatory)][hashtable]$Counts)

    return [int]$Counts.PASS + [int]$Counts.FAIL + [int]$Counts.ERROR
}

function Get-AuditScore {
    <#
    .SYNOPSIS
    Compliance score as a percentage rounded to one decimal: 100 * PASS / assessed.
    Returns 0 when nothing was assessed.
    #>
    param([Parameter(Mandatory)][hashtable]$Counts)

    $assessed = Get-AssessedCount -Counts $Counts
    if ($assessed -eq 0) { return 0 }
    return [math]::Round(100.0 * $Counts.PASS / $assessed, 1)
}
