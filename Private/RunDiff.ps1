# Run-to-run diff — compares the current results against a previous run's JSON
# report so the report answers *what* changed, not just that the score moved.
# Keying: control + subscription name + resource (same identity the JSON export
# and SARIF fingerprints use).

function Find-PreviousReportJson {
    <#
    .SYNOPSIS
    Locate the most recent report JSON in the output directory ('auto' baseline).
    Excludes the current run's own JSON, run history, diff outputs and suppressions.
    #>
    param([Parameter(Mandatory)][string]$OutputPath)

    $fullOut     = [System.IO.Path]::GetFullPath($OutputPath)
    $dir         = Split-Path $fullOut -Parent
    $currentJson = [System.IO.Path]::ChangeExtension($fullOut, '.json')

    $candidates = @(Get-ChildItem -Path $dir -Filter '*.json' -File -ErrorAction SilentlyContinue |
        Where-Object {
            $_.FullName -ne $currentJson -and
            $_.Name -ne 'cis_run_history.json' -and
            $_.Name -notlike '*.diff.json' -and
            $_.Name -notlike 'suppressions.json*'
        } |
        Sort-Object LastWriteTimeUtc -Descending)

    if ($candidates.Count -gt 0) { return $candidates[0].FullName }
    return $null
}

function Get-DiffEntryValue {
    # Tolerant property read for parsed-JSON baseline entries (missing key -> '').
    param([Parameter(Mandatory)][object]$Entry, [Parameter(Mandatory)][string]$Name)
    $p = $Entry.PSObject.Properties[$Name]
    if ($p -and $null -ne $p.Value) { [string]$p.Value } else { '' }
}

function Get-RunDiff {
    <#
    .SYNOPSIS
    Classify changes between the current results and a previous run's exported
    JSON results (array of { control, title, level, subscription, resource,
    status, details }).

    .DESCRIPTION
    Categories (FAIL and ERROR both count as failing, matching the score):
      Regressions  — present in both runs; was not failing, now FAIL/ERROR
      Improvements — present in both runs; was FAIL/ERROR, now not failing
      New          — result key only in the current run
      Removed      — result key only in the previous run
    Status changes between neutral states (e.g. MANUAL to INFO) and FAIL/ERROR
    swaps are not reported — the finding neither appeared nor went away.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$CurrentResults,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$PreviousResults
    )

    $bad = @($script:FAIL, $script:ERR)

    function New-DiffEntry {
        param([string]$Control, [string]$Title, [int]$Level, [string]$Subscription,
              [string]$Resource, [string]$Status, [string]$Details, [string]$PreviousStatus)
        [PSCustomObject][ordered]@{
            control        = $Control
            title          = $Title
            level          = $Level
            subscription   = $Subscription
            resource       = $Resource
            status         = $Status
            previousStatus = $PreviousStatus
            details        = $Details
        }
    }

    $curMap = [ordered]@{}
    foreach ($r in $CurrentResults) {
        $key = '{0}|{1}|{2}' -f $r.ControlId, $r.SubscriptionName, $r.Resource
        if (-not $curMap.Contains($key)) { $curMap[$key] = $r }
    }

    $prevMap = [ordered]@{}
    foreach ($p in $PreviousResults) {
        $key = '{0}|{1}|{2}' -f (Get-DiffEntryValue -Entry $p -Name 'control'), (Get-DiffEntryValue -Entry $p -Name 'subscription'), (Get-DiffEntryValue -Entry $p -Name 'resource')
        if (-not $prevMap.Contains($key)) { $prevMap[$key] = $p }
    }

    $regressions  = [System.Collections.Generic.List[object]]::new()
    $improvements = [System.Collections.Generic.List[object]]::new()
    $new          = [System.Collections.Generic.List[object]]::new()
    $removed      = [System.Collections.Generic.List[object]]::new()

    foreach ($key in $curMap.Keys) {
        $r = $curMap[$key]
        $prevStatus = if ($prevMap.Contains($key)) { Get-DiffEntryValue -Entry $prevMap[$key] -Name 'status' } else { $null }
        $entry = New-DiffEntry -Control $r.ControlId -Title $r.Title -Level ([int]$r.Level) `
            -Subscription ([string]$r.SubscriptionName) -Resource ([string]$r.Resource) `
            -Status $r.Status -Details ([string]$r.Details) -PreviousStatus ([string]$prevStatus)

        if ($null -eq $prevStatus) {
            $new.Add($entry)
        } elseif ($prevStatus -notin $bad -and $r.Status -in $bad) {
            $regressions.Add($entry)
        } elseif ($prevStatus -in $bad -and $r.Status -notin $bad) {
            $improvements.Add($entry)
        }
    }

    foreach ($key in $prevMap.Keys) {
        if ($curMap.Contains($key)) { continue }
        $p = $prevMap[$key]
        $lvl = 0; $null = [int]::TryParse((Get-DiffEntryValue -Entry $p -Name 'level'), [ref]$lvl)
        $removed.Add((New-DiffEntry -Control (Get-DiffEntryValue -Entry $p -Name 'control') `
            -Title (Get-DiffEntryValue -Entry $p -Name 'title') -Level $lvl `
            -Subscription (Get-DiffEntryValue -Entry $p -Name 'subscription') -Resource (Get-DiffEntryValue -Entry $p -Name 'resource') `
            -Status '' -Details (Get-DiffEntryValue -Entry $p -Name 'details') `
            -PreviousStatus (Get-DiffEntryValue -Entry $p -Name 'status')))
    }

    [PSCustomObject]@{
        Regressions  = @($regressions)
        Improvements = @($improvements)
        New          = @($new)
        Removed      = @($removed)
    }
}

function Write-RunDiffJson {
    <#
    .SYNOPSIS
    Write the diff to <report>.diff.json (BOM-less UTF-8, like the JSON report).
    #>
    param(
        [Parameter(Mandatory)][object]$Diff,
        [Parameter(Mandatory)][string]$BaselinePath,
        [Parameter(Mandatory)][string]$OutputPath
    )

    $payload = [ordered]@{
        baseline     = [System.IO.Path]::GetFullPath($BaselinePath)
        generated    = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
        counts       = [ordered]@{
            regressions  = $Diff.Regressions.Count
            improvements = $Diff.Improvements.Count
            new          = $Diff.New.Count
            removed      = $Diff.Removed.Count
        }
        regressions  = @($Diff.Regressions)
        improvements = @($Diff.Improvements)
        new          = @($Diff.New)
        removed      = @($Diff.Removed)
    }
    $jsonText = ConvertTo-Json -InputObject $payload -Depth 5
    [System.IO.File]::WriteAllText($OutputPath, $jsonText, [System.Text.UTF8Encoding]::new($false))
}
