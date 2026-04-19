# Suppressions — accepted risk management for audit findings
#
# Loads suppressions.json and applies SUPPRESSED status to matching FAIL/ERROR
# results at report-generation time. Checkpoints are never modified — the raw
# FAIL is always preserved on disk, so removing a suppression and re-running
# -ReportOnly immediately reinstates the finding.
#
# Suppression file format (suppressions.json):
#
# [
#   {
#     "control_id":    "7.1",
#     "resource":      "jumphost-nsg",
#     "subscription":  "Production",
#     "justification": "Intentional RDP jump host — restricted by Azure Firewall",
#     "expires":       "2026-12-31"
#   }
# ]
#
# Matching rules:
#   control_id   — required; exact match
#   resource     — optional; if omitted, matches any resource for that control
#   subscription — optional; if omitted, matches across all subscriptions
#   Only FAIL and ERROR results can be suppressed
#
# Expiry rules:
#   expires is required — prevents suppressions from becoming permanent
#   Maximum 1 year from today; anything longer is capped with a warning
#   Expired entries are skipped and logged

# Maximum allowed suppression duration in days
$script:MAX_SUPPRESSION_DAYS = 365

function Get-Suppressions {
    <#
    .SYNOPSIS
    Load, validate, and return active suppressions from a JSON file.
    #>
    param([string]$Path = "suppressions.json")

    if (-not (Test-Path $Path)) { return @() }

    try {
        $raw  = Get-Content $Path -Raw -Encoding UTF8
        $data = ConvertFrom-Json -InputObject $raw -Depth 10
    } catch {
        Write-AuditLog "Suppression file '$Path' is not valid JSON: $_" -Level WARNING
        return @()
    }

    # Accept both flat array [{...}] and wrapped { "suppressions": [{...}] }
    # ConvertFrom-Json unwraps single-element arrays, so use @() to re-wrap.
    $entries = if ($data -is [array]) {
        $data
    } elseif ($data.PSObject.Properties['suppressions']) {
        @($data.suppressions)
    } elseif ($data.PSObject.Properties['control_id']) {
        # Single-element flat array was unwrapped by ConvertFrom-Json
        @($data)
    } else {
        @()
    }
    if (-not $entries -or $entries.Count -eq 0) {
        Write-AuditLog "Suppression file '$Path' has no entries." -Level INFO
        return @()
    }

    $today   = [datetime]::Today
    $maxDate = $today.AddDays($script:MAX_SUPPRESSION_DAYS)
    $valid   = [System.Collections.Generic.List[object]]::new()

    for ($i = 0; $i -lt $entries.Count; $i++) {
        $entry = $entries[$i]
        $num   = $i + 1

        # Validate required fields — use PSObject.Properties to avoid
        # PropertyNotFoundException under Set-StrictMode -Version Latest
        $missing = $false
        foreach ($field in @('control_id', 'justification', 'expires')) {
            if (-not $entry.PSObject.Properties[$field] -or -not $entry.$field) {
                Write-AuditLog "Suppression #$num in '$Path' is missing required field '$field' — skipped." -Level WARNING
                $missing = $true
                break
            }
        }
        if ($missing) { continue }

        # Parse expiry date
        try {
            $expires = [datetime]::ParseExact([string]$entry.expires, 'yyyy-MM-dd', $null)
        } catch {
            Write-AuditLog "Suppression #$num (control $($entry.control_id)): invalid expires '$($entry.expires)' — expected YYYY-MM-DD. Skipped." -Level WARNING
            continue
        }

        # Skip expired
        if ($expires -lt $today) {
            $resLabel = if ($entry.PSObject.Properties['resource'] -and $entry.resource) { $entry.resource } else { '*' }
            Write-AuditLog "Suppression #$num (control $($entry.control_id), resource '$resLabel') expired $($expires.ToString('yyyy-MM-dd')) — finding will show as FAIL/ERROR." -Level WARNING
            continue
        }

        # Cap at 1 year
        if ($expires -gt $maxDate) {
            Write-AuditLog "Suppression #$num (control $($entry.control_id)): expiry $($expires.ToString('yyyy-MM-dd')) exceeds 1-year maximum — capped at $($maxDate.ToString('yyyy-MM-dd'))." -Level WARNING
            $expires = $maxDate
        }

        $valid.Add([PSCustomObject]@{
            ControlId     = [string]$entry.control_id
            Resource      = if ($entry.PSObject.Properties['resource'] -and $entry.resource)         { [string]$entry.resource }     else { $null }
            Subscription  = if ($entry.PSObject.Properties['subscription'] -and $entry.subscription) { [string]$entry.subscription } else { $null }
            Justification = [string]$entry.justification
            Expires       = $expires
        })
    }

    Write-AuditLog "`u{1F507} Loaded $($valid.Count) active suppression(s) from $Path" -Level INFO
    return $valid.ToArray()
}

function Invoke-Suppressions {
    <#
    .SYNOPSIS
    Return a new array of results with SUPPRESSED status applied where matched.
    Only FAIL and ERROR results are candidates.
    #>
    param(
        [Parameter(Mandatory)][object[]]$Results,
        [object[]]$Suppressions = @()
    )

    if (-not $Suppressions -or $Suppressions.Count -eq 0) { return $Results }

    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($r in $Results) {
        if ($r.Status -ne $script:FAIL -and $r.Status -ne $script:ERR) {
            $out.Add($r)
            continue
        }

        $match = Find-SuppressionMatch -Result $r -Suppressions $Suppressions
        if ($match) {
            $out.Add([PSCustomObject]@{
                ControlId        = $r.ControlId
                Title            = $r.Title
                Level            = $r.Level
                Section          = $r.Section
                Status           = $script:SUPPRESSED
                Details          = "$($r.Details)  [Accepted risk: $($match.Justification) — expires $($match.Expires.ToString('yyyy-MM-dd'))]"
                Remediation      = $r.Remediation
                SubscriptionId   = $r.SubscriptionId
                SubscriptionName = $r.SubscriptionName
                Resource         = $r.Resource
            })
        } else {
            $out.Add($r)
        }
    }

    return $out.ToArray()
}

function Find-SuppressionMatch {
    <#
    .SYNOPSIS
    Return the first suppression that matches a result, or $null.
    #>
    param(
        [Parameter(Mandatory)][object]$Result,
        [Parameter(Mandatory)][object[]]$Suppressions
    )

    foreach ($sup in $Suppressions) {
        if ($Result.ControlId -ne $sup.ControlId) { continue }
        if ($sup.Resource -and $sup.Resource -ine $Result.Resource) { continue }
        if ($sup.Subscription -and $sup.Subscription -ine $Result.SubscriptionName) { continue }
        return $sup
    }
    return $null
}

function Show-Suppressions {
    <#
    .SYNOPSIS
    Print all active suppressions in a readable table.
    #>
    param(
        [object[]]$Suppressions,
        [string]$Path = "suppressions.json"
    )

    if (-not $Suppressions -or $Suppressions.Count -eq 0) {
        Write-Host "No active suppressions in $Path."
        return
    }

    $today = [datetime]::Today
    Write-Host "`nActive suppressions from ${Path}:`n"
    Write-Host ("  {0,-10}  {1,-25}  {2,-20}  {3,-14}  {4}" -f "Control", "Resource", "Subscription", "Expires", "Justification")
    Write-Host ("  " + "-" * 100)
    foreach ($sup in $Suppressions) {
        $daysLeft  = ($sup.Expires - $today).Days
        $expiryStr = "$($sup.Expires.ToString('yyyy-MM-dd')) (${daysLeft}d left)"
        $resource  = if ($sup.Resource)    { $sup.Resource }    else { "*" }
        $sub       = if ($sup.Subscription) { $sup.Subscription } else { "*" }
        $justif    = if ($sup.Justification.Length -gt 70) { $sup.Justification.Substring(0, 70) } else { $sup.Justification }
        Write-Host ("  {0,-10}  {1,-25}  {2,-20}  {3,-14}  {4}" -f $sup.ControlId, $resource, $sub, $expiryStr, $justif)
    }
    Write-Host ""
}
