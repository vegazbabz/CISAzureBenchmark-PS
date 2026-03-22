# Logging, console output, and NSG/port helpers

function Write-AuditLog {
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

function Write-AuditProgress {
    param([string]$Message)
    Write-Host "`r$Message" -NoNewline -ForegroundColor DarkCyan
}

# ── Port helpers ─────────────────────────────────────────────────────────────

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

        $access    = [string]$props.access
        $direction = [string]$props.direction
        $srcAddr   = [string]$props.sourceAddressPrefix
        $proto     = [string]$props.protocol

        if ($access -ne 'Allow')   { continue }
        if ($direction -ne 'Inbound') { continue }
        if ($script:INTERNET_SRCS -notcontains $srcAddr.ToLower()) { continue }

        $protoUpper = $proto.ToUpper()
        if ($protoUpper -ne '*' -and $Protocols -notcontains $proto -and $Protocols -notcontains $protoUpper) { continue }

        # Collect all destination port ranges
        $portRanges = [System.Collections.Generic.List[string]]::new()
        if ($props.destinationPortRange -and [string]$props.destinationPortRange) {
            $portRanges.Add([string]$props.destinationPortRange)
        }
        if ($props.destinationPortRanges) {
            foreach ($pr in $props.destinationPortRanges) {
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

        $access    = [string]$props.access
        $direction = [string]$props.direction
        $srcAddr   = [string]$props.sourceAddressPrefix
        $proto     = [string]$props.protocol

        if ($access -ne 'Allow')   { continue }
        if ($direction -ne 'Inbound') { continue }
        if ($script:INTERNET_SRCS -notcontains $srcAddr.ToLower()) { continue }

        $protoUpper = $proto.ToUpper()
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
