# Logging, console output, and NSG/port helpers

function Write-AuditLog {
    <#
    .SYNOPSIS
    Write a timestamped log line to the console (and optionally to a log file).
    DEBUG/VERBOSE lines are suppressed unless the corresponding mode flag is set.
    #>
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet("INFO","WARNING","ERROR","DEBUG","VERBOSE")][string]$Level = "INFO"
    )

    $ts   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$ts] [$Level] $Message"

    switch ($Level) {
        "ERROR"   { Write-Host $line -ForegroundColor Red }
        "WARNING" { Write-Host $line -ForegroundColor Yellow }
        "DEBUG"   { if ($script:DEBUG_MODE)   { Write-Host $line -ForegroundColor Cyan } }
        "VERBOSE" { if ($script:VERBOSE_MODE) { Write-Host $line -ForegroundColor DarkGray } }
        default   { Write-Host $line }
    }

    if ($script:LOG_FILE) {
        Add-Content -Path $script:LOG_FILE -Value $line -Encoding UTF8
    }
}

# ── Port helpers ─────────────────────────────────────────────────────────────

function Remove-DuplicateResults {
    <#
    .SYNOPSIS
    Remove identical duplicate results while preserving order.
    Duplicates can arise from Azure Resource Graph pagination quirks.
    #>
    param([object[]]$Results)
    $seen = @{}
    $out  = [System.Collections.Generic.List[object]]::new()
    foreach ($r in $Results) {
        $key = "{0}|{1}|{2}|{3}|{4}" -f $r.ControlId, $r.SubscriptionId, $r.Resource, $r.Status, $r.Details
        if (-not $seen.ContainsKey($key)) {
            $seen[$key] = $true
            $out.Add($r)
        }
    }
    return $out.ToArray()
}

function Test-PortInRange {
    <#
    .SYNOPSIS
    Return $true if $Port matches the given NSG port spec.
    Handles: "*", "22", "1024-65535"
    #>
    param([string]$PortSpec, [int]$Port)

    if ($PortSpec -eq '*')                       { return $true }
    if ($PortSpec -match '^\d+$')                { return ([int]$PortSpec -eq $Port) }
    if ($PortSpec -match '^(\d+)-(\d+)$') {
        return ([int]$Matches[1] -le $Port -and $Port -le [int]$Matches[2])
    }
    return $false
}

# ── NSG helpers ──────────────────────────────────────────────────────────────

function Get-NsgBadRules {
    <#
    .SYNOPSIS
    Find NSG rules that Allow Inbound TCP traffic from internet on the specified ports.
    Returns array of non-compliant rule names.

    Handles both Resource Graph format (flat, top-level properties) and
    az CLI format (nested under .properties).
    #>
    param(
        [object[]]$Rules,
        [int[]]$Ports,
        [string[]]$Protocols = @("TCP", "Tcp", "*")
    )

    if (-not $Rules -or $Rules.Count -eq 0) { return @() }

    $badRules = [System.Collections.Generic.List[string]]::new()

    foreach ($rule in $Rules) {
        # Support both flat (Resource Graph) and nested (az CLI) shapes
        $props = if ($rule.PSObject.Properties['properties']) { $rule.properties } else { $rule }

        $access    = [string]($props.PSObject.Properties['access']?.Value)
        $direction = [string]($props.PSObject.Properties['direction']?.Value)
        $proto     = [string]($props.PSObject.Properties['protocol']?.Value)

        if ($access -ne 'Allow')      { continue }
        if ($direction -ne 'Inbound') { continue }

        # Normalise both singular and plural source address fields into one list
        $srcAddrs = [System.Collections.Generic.List[string]]::new()
        $sap = [string]($props.PSObject.Properties['sourceAddressPrefix']?.Value)
        if ($sap) { $srcAddrs.Add($sap) }
        $sapProp = $props.PSObject.Properties['sourceAddressPrefixes']
        if ($sapProp -and $sapProp.Value) {
            foreach ($sa in $sapProp.Value) { if ($sa) { $srcAddrs.Add([string]$sa) } }
        }
        $isInternet = $false
        foreach ($sa in $srcAddrs) {
            if ($script:INTERNET_SRCS -contains $sa.ToLower()) { $isInternet = $true; break }
        }
        if (-not $isInternet) { continue }

        $protoUpper = if ($proto) { $proto.ToUpper() } else { '' }
        if ($protoUpper -ne '*' -and $Protocols -notcontains $proto -and $Protocols -notcontains $protoUpper) { continue }

        # Collect all destination port ranges
        $portRanges = [System.Collections.Generic.List[string]]::new()
        $dprProp = $props.PSObject.Properties['destinationPortRange']
        if ($dprProp -and $dprProp.Value -and [string]$dprProp.Value) {
            $portRanges.Add([string]$dprProp.Value)
        }
        $dprsProp = $props.PSObject.Properties['destinationPortRanges']
        if ($dprsProp -and $dprsProp.Value) {
            foreach ($pr in $dprsProp.Value) {
                if ($pr) { $portRanges.Add([string]$pr) }
            }
        }

        $matched = $false
        foreach ($portRange in $portRanges) {
            if ($matched) { break }
            foreach ($targetPort in $Ports) {
                if (Test-PortInRange -PortSpec $portRange -Port $targetPort) {
                    $matched = $true; break
                }
            }
        }

        if ($matched) {
            $ruleName = if ($rule.name) { [string]$rule.name } else { "unknown-rule" }
            if ($badRules -notcontains $ruleName) { $badRules.Add($ruleName) }
        }
    }

    return $badRules.ToArray()
}

function Get-NsgUdpBadRules {
    <#
    .SYNOPSIS
    Find NSG rules that Allow Inbound UDP from internet (any port).
    #>
    param([object[]]$Rules)

    if (-not $Rules -or $Rules.Count -eq 0) { return @() }

    $badRules = [System.Collections.Generic.List[string]]::new()

    foreach ($rule in $Rules) {
        $props = if ($rule.PSObject.Properties['properties']) { $rule.properties } else { $rule }

        $access    = [string]($props.PSObject.Properties['access']?.Value)
        $direction = [string]($props.PSObject.Properties['direction']?.Value)
        $proto     = [string]($props.PSObject.Properties['protocol']?.Value)

        if ($access -ne 'Allow')      { continue }
        if ($direction -ne 'Inbound') { continue }

        # Normalise both singular and plural source address fields into one list
        $srcAddrs = [System.Collections.Generic.List[string]]::new()
        $sap = [string]($props.PSObject.Properties['sourceAddressPrefix']?.Value)
        if ($sap) { $srcAddrs.Add($sap) }
        $sapProp = $props.PSObject.Properties['sourceAddressPrefixes']
        if ($sapProp -and $sapProp.Value) {
            foreach ($sa in $sapProp.Value) { if ($sa) { $srcAddrs.Add([string]$sa) } }
        }
        $isInternet = $false
        foreach ($sa in $srcAddrs) {
            if ($script:INTERNET_SRCS -contains $sa.ToLower()) { $isInternet = $true; break }
        }
        if (-not $isInternet) { continue }

        $protoUpper = if ($proto) { $proto.ToUpper() } else { '' }
        if ($protoUpper -ne 'UDP' -and $protoUpper -ne '*') { continue }

        $ruleName = if ($rule.name) { [string]$rule.name } else { "unknown-rule" }
        if ($badRules -notcontains $ruleName) { $badRules.Add($ruleName) }
    }

    return $badRules.ToArray()
}

# ── Sort helpers ─────────────────────────────────────────────────────────────

function Get-ControlSortKey {
    <#
    .SYNOPSIS
    Convert "9.3.10" to a sortable string "009.003.010" for correct numeric ordering.
    #>
    param([string]$ControlId)
    ($ControlId -split '\.' | ForEach-Object { $_.PadLeft(3, '0') }) -join '.'
}
