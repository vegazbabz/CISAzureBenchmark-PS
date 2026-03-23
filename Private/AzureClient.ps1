# Azure CLI subprocess layer
# Uses PowerShell's & operator, which correctly handles az.cmd on Windows

# Detect az executable (az.cmd on Windows, az on Linux/macOS)
$script:AZ_CMD = if ($IsWindows -or ($env:OS -eq 'Windows_NT')) { "az.cmd" } else { "az" }

function Test-TransientError {
    <#
    .SYNOPSIS
    Return $true if an error message indicates a transient/retriable failure.
    #>
    param([string]$Message)
    return ($Message -imatch 'TooManyRequests|\(429\)|rate limit|throttl|\(500\)|\(502\)|\(503\)|InternalServerError|BadGateway|ServiceUnavailable|ECONNRESET|connection was reset|temporarily unavailable')
}

function Invoke-AzCli {
    <#
    .SYNOPSIS
    Run an az CLI command and return a result object.
    Retries transient failures (429/500/502/503) with exponential backoff.

    .OUTPUTS
    PSCustomObject with: .Success [bool], .Data [object], .Error [string], .ExitCode [int]
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'TimeoutSec', Justification='Reserved for future async/timeout support')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$Arguments,
        [string]$SubscriptionId = "",
        [int]$TimeoutSec = 60,   # reserved; not enforced in synchronous mode
        [int]$MaxRetries = 3
    )

    $cmdArgs = [System.Collections.Generic.List[string]]::new()
    foreach ($a in $Arguments) { $cmdArgs.Add($a) }

    if ($SubscriptionId) {
        # Append rather than prepend: some command groups (e.g. az security)
        # do not accept --subscription as a global parameter before the subcommand.
        $cmdArgs.Add("--subscription")
        $cmdArgs.Add($SubscriptionId)
    }

    # Ensure JSON output unless caller already specified -o / --output
    if ($cmdArgs -notcontains "--output" -and $cmdArgs -notcontains "-o") {
        $cmdArgs.Add("--output")
        $cmdArgs.Add("json")
    }

    $attempt = 0
    while ($true) {
        $attempt++
        try {
            Write-AuditLog "  az $($cmdArgs -join ' ')" -Level VERBOSE

            # & handles .cmd files correctly on Windows; 2>&1 merges stderr into output
            $output    = & $script:AZ_CMD @($cmdArgs.ToArray()) 2>&1
            $exitCode  = $LASTEXITCODE

            # Split: strings are stdout, ErrorRecord objects are stderr lines
            $stdoutLines = @($output | Where-Object { $_ -is [string] })
            $stderrLines = @($output | Where-Object { $_ -isnot [string] } | ForEach-Object { "$_" })

            if ($exitCode -ne 0) {
                $errMsg = if ($stderrLines) { $stderrLines -join ' ' } else { $stdoutLines -join ' ' }
                $errMsg = ($errMsg -replace '\r?\n', ' ').Trim()

                # Retry on transient failures
                if ($attempt -le $MaxRetries -and (Test-TransientError $errMsg)) {
                    $baseDelay = [math]::Pow(2, $attempt)  # 2, 4, 8 seconds
                    $jitter    = Get-Random -Minimum 0.0 -Maximum 1.0
                    $delaySec  = $baseDelay + $jitter
                    Write-AuditLog "  Transient error (attempt $attempt/$MaxRetries): $($errMsg.Substring(0, [math]::Min(80, $errMsg.Length)))… — retrying in $([math]::Round($delaySec, 1))s" -Level VERBOSE
                    Start-Sleep -Milliseconds ([int]($delaySec * 1000))
                    continue
                }

                Write-AuditLog "  az exit=$exitCode — $($errMsg.Substring(0, [math]::Min(120, $errMsg.Length)))" -Level VERBOSE
                return [PSCustomObject]@{ Success = $false; Data = $null; Error = $errMsg; ExitCode = $exitCode }
            }

            $stdout = ($stdoutLines -join "`n").Trim()

            if (-not $stdout) {
                return [PSCustomObject]@{ Success = $true; Data = $null; Error = $null; ExitCode = 0 }
            }

            try {
                $parsed = $stdout | ConvertFrom-Json -Depth 30
                return [PSCustomObject]@{ Success = $true; Data = $parsed; Error = $null; ExitCode = 0 }
            } catch {
                return [PSCustomObject]@{ Success = $false; Data = $null; Error = "JSON parse error: $_"; ExitCode = 0 }
            }

        } catch {
            # PowerShell exception (e.g. az.cmd not found) — not retriable
            return [PSCustomObject]@{ Success = $false; Data = $null; Error = $_.Exception.Message; ExitCode = -1 }
        }
    }
}

function Invoke-AzGraphQuery {
    <#
    .SYNOPSIS
    Execute a Resource Graph Kusto query, paginating through all results.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Query,
        [string[]]$SubscriptionIds = @(),
        [int]$TimeoutSec = 180
    )

    # Append a KQL subscription filter so pagination tokens don't traverse the
    # entire tenant. Resource Graph shards span the whole tenant even when
    # --subscriptions is specified, causing excessive cross-tenant page fetches.
    # The query must be on ONE line — az graph query -q stops at the first newline.
    $scopedQuery = $Query -replace '\r?\n', ' ' -replace '\s{2,}', ' '
    if ($SubscriptionIds.Count -gt 0) {
        $quotedIds = ($SubscriptionIds | ForEach-Object { "'$_'" }) -join ", "
        $scopedQuery = "$scopedQuery | where subscriptionId in ($quotedIds)"
    }

    $baseArgs = [System.Collections.Generic.List[string]]@(
        "graph", "query", "-q", $scopedQuery, "--first", "1000"
    )
    if ($SubscriptionIds.Count -gt 0) {
        $baseArgs.Add("--subscriptions")
        foreach ($s in $SubscriptionIds) { $baseArgs.Add($s) }
    }

    $allData   = [System.Collections.Generic.List[object]]::new()
    $skipToken = $null

    do {
        $pageArgs = [System.Collections.Generic.List[string]]::new($baseArgs)
        if ($skipToken) {
            $pageArgs.Add("--skip-token")
            $pageArgs.Add($skipToken)
        }

        $result = Invoke-AzCli -Arguments $pageArgs.ToArray() -TimeoutSec $TimeoutSec

        if (-not $result.Success) {
            return [PSCustomObject]@{ Success = $false; Data = @(); Error = $result.Error }
        }

        if ($result.Data -and $result.Data.PSObject.Properties['data']) {
            foreach ($item in $result.Data.data) { $allData.Add($item) }
        }

        # az graph query returns snake_case: skip_token / total_records (not camelCase)
        $skipToken = $null
        if ($result.Data -and $result.Data.PSObject.Properties['skip_token']) {
            $skipToken = $result.Data.skip_token
            $total = if ($result.Data.PSObject.Properties['total_records']) { $result.Data.total_records } else { '?' }
            Write-AuditLog "    Paginating: $($allData.Count)/$total records fetched so far..." -Level DEBUG
        }

    } while ($skipToken)

    return [PSCustomObject]@{ Success = $true; Data = $allData.ToArray(); Error = $null }
}

function Invoke-AzRest {
    <#
    .SYNOPSIS
    Call an ARM or Microsoft Graph REST endpoint via az rest.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Uri,
        [string]$Method     = "GET",
        [int]$TimeoutSec    = 60
    )
    $cliArgs = @("rest", "--method", $Method, "--uri", $Uri)
    # Explicitly set --resource for Microsoft Graph URLs so az rest acquires the
    # correct token even when the default az login session has no Graph scope.
    if ($Uri -match '^https://graph\.microsoft\.com/') {
        $cliArgs += @("--resource", "https://graph.microsoft.com")
    }
    Invoke-AzCli -Arguments $cliArgs -TimeoutSec $TimeoutSec
}

function Invoke-AzRestPaged {
    <#
    .SYNOPSIS
    Call a paged ARM/Graph REST endpoint and accumulate all .value[] entries.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Uri,
        [int]$TimeoutSec = 60
    )

    $all     = [System.Collections.Generic.List[object]]::new()
    $nextUri = $Uri

    while ($nextUri) {
        $result = Invoke-AzRest -Uri $nextUri -TimeoutSec $TimeoutSec
        if (-not $result.Success) {
            return [PSCustomObject]@{ Success = $false; Data = @(); Error = $result.Error }
        }
        if ($result.Data -and $result.Data.PSObject.Properties['value']) {
            foreach ($item in $result.Data.value) { $all.Add($item) }
        }
        $nextUri = $null
        if ($result.Data -and $result.Data.PSObject.Properties['nextLink']) {
            $nextUri = $result.Data.nextLink
        }
    }

    return [PSCustomObject]@{ Success = $true; Data = $all.ToArray(); Error = $null }
}

# ── Error classifiers ────────────────────────────────────────────────────────

function Test-FirewallError {
    param([string]$Message)
    foreach ($t in @("firewall", "network acl", "network access", "vnet rule", "public network access is disabled",
                     "failed to resolve", "getaddrinfo failed", "JSON is invalid")) {
        if ($Message -imatch [regex]::Escape($t)) { return $true }
    }
    return $false
}

function Test-AuthzError {
    param([string]$Message)
    foreach ($t in @("authorizationfailed", "does not have authorization", "is not authorized", "forbidden", "access denied")) {
        if ($Message -imatch $t) { return $true }
    }
    return $false
}

function Test-NotApplicableError {
    param([string]$Message)
    foreach ($t in @("featurenotsupportedforaccount", "not supported for this account type", "blobserviceproperties")) {
        if ($Message -imatch $t) { return $true }
    }
    return $false
}
