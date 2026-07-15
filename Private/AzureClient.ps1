# Azure API client layer
#
# All data access goes through Az PowerShell cmdlets: Resource Graph
# (Search-AzGraph) and ARM / Microsoft Graph REST (Invoke-AzRestMethod), wrapped
# with Invoke-WithRetry for transient-failure backoff. No Azure CLI subprocess is
# spawned — the tool has no `az` dependency.

# Shared throttle counter — set to a ConcurrentBag by the caller when adaptive
# concurrency is active.  Each transient retry adds an entry.
$script:_throttleBag = $null

# Process registry for Ctrl+C cleanup — set to a ConcurrentDictionary by the
# caller so all runspaces share the same instance.
$script:_runningProcs = $null

function Test-TransientError {
    <#
    .SYNOPSIS
    Return $true if an error message indicates a transient/retriable failure.
    #>
    param([string]$Message)
    # Parenthesised codes (\(429\) etc.) catch our own thrown messages and Az's
    # "...: 429 (Too Many Requests)" phrasing; the bare \b429\b and "Too Many
    # Requests" tokens catch Search-AzGraph / ARM throttle exceptions that omit
    # the parentheses. 500/502/503 are matched by name (InternalServerError etc.)
    # to avoid false positives on unrelated messages that merely contain "500".
    return ($Message -imatch 'TooManyRequests|Too Many Requests|\b429\b|\(429\)|rate limit|throttl|\(500\)|\(502\)|\(503\)|InternalServerError|BadGateway|ServiceUnavailable|ECONNRESET|connection was reset|temporarily unavailable')
}

function Invoke-WithRetry {
    <#
    .SYNOPSIS
    Invoke a scriptblock, retrying transient failures with jittered exponential backoff.

    .DESCRIPTION
    Runs $ScriptBlock and returns its output. If it throws an error classified as
    transient by Test-TransientError (429/5xx/network reset), waits 2^attempt
    seconds plus 0–1s jitter and retries, up to $MaxRetries times. Each transient
    retry adds an entry to $script:_throttleBag (when the caller has wired one up)
    so the orchestrator's adaptive-concurrency loop can react. Non-transient errors
    are re-thrown immediately without retry.

    .OUTPUTS
    Whatever $ScriptBlock returns.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [int]$MaxRetries = 3,
        [string]$OperationName = "operation"
    )

    $attempt = 0
    while ($true) {
        $attempt++
        try {
            return & $ScriptBlock
        } catch {
            $msg = $_.Exception.Message
            if ($attempt -le $MaxRetries -and (Test-TransientError $msg)) {
                if ($script:_throttleBag) { $script:_throttleBag.Add(1) }
                $baseDelay = [math]::Pow(2, $attempt)  # 2, 4, 8 seconds
                $jitter    = Get-Random -Minimum 0.0 -Maximum 1.0
                $delaySec  = $baseDelay + $jitter
                $snippet   = $msg.Substring(0, [math]::Min(80, $msg.Length))
                Write-AuditLog "  Transient error in ${OperationName} (attempt $attempt/$MaxRetries): $snippet — retrying in $([math]::Round($delaySec, 1))s" -Level VERBOSE
                Start-Sleep -Milliseconds ([int]($delaySec * 1000))
                continue
            }
            throw
        }
    }
}

function Invoke-AzGraphQuery {
    <#
    .SYNOPSIS
    Execute a Resource Graph Kusto query, paginating through all results.
    Uses the Az.ResourceGraph module (Search-AzGraph) instead of az CLI subprocess.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Query,
        [string[]]$SubscriptionIds = @()
    )

    try {
        $allData    = [System.Collections.Generic.List[object]]::new()
        $cleanQuery = $Query -replace '\r?\n', ' ' -replace '\s{2,}', ' '
        $params     = @{ Query = $cleanQuery; First = 1000 }
        if ($SubscriptionIds.Count -gt 0) { $params['Subscription'] = $SubscriptionIds }

        $response = Invoke-WithRetry -OperationName "Resource Graph query" -ScriptBlock { Search-AzGraph @params }
        foreach ($item in $response) { $allData.Add($item) }

        while ($response.SkipToken) {
            Write-AuditLog "    Paginating Resource Graph: $($allData.Count) records so far..." -Level DEBUG
            $skipToken = $response.SkipToken
            $response = Invoke-WithRetry -OperationName "Resource Graph page" -ScriptBlock { Search-AzGraph @params -SkipToken $skipToken }
            foreach ($item in $response) { $allData.Add($item) }
        }

        return [PSCustomObject]@{ Success = $true; Data = $allData.ToArray(); Error = $null }
    } catch {
        return [PSCustomObject]@{ Success = $false; Data = @(); Error = $_.Exception.Message }
    }
}

function Invoke-ArmRest {
    <#
    .SYNOPSIS
    Call an ARM or Microsoft Graph REST endpoint via Invoke-AzRestMethod.
    Returns the same {Success, Data, Error, ExitCode} shape as before.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Uri/Method are used inside the Invoke-WithRetry scriptblock closure')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Uri,
        [string]$Method = "GET"
    )
    try {
        $response = Invoke-WithRetry -OperationName "REST $Method" -ScriptBlock {
            $r = Invoke-AzRestMethod -Uri $Uri -Method $Method -ErrorAction Stop
            # Invoke-AzRestMethod returns transient HTTP codes without throwing, so
            # surface them as a transient error (parenthesised code matches
            # Test-TransientError) to trigger Invoke-WithRetry's backoff.
            if ($r.StatusCode -in 429, 500, 502, 503) {
                throw "Transient HTTP status ($($r.StatusCode))"
            }
            $r
        }

        if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 300) {
            if (-not $response.Content) {
                return [PSCustomObject]@{ Success = $true; Data = $null; Error = $null; ExitCode = 0 }
            }
            try {
                $data = $response.Content | ConvertFrom-Json -Depth 30
                return [PSCustomObject]@{ Success = $true; Data = $data; Error = $null; ExitCode = 0 }
            } catch {
                return [PSCustomObject]@{ Success = $false; Data = $null; Error = "JSON parse error: $_"; ExitCode = 0 }
            }
        } else {
            $errMsg = "HTTP $($response.StatusCode)"
            try {
                $errObj = $response.Content | ConvertFrom-Json
                $inner  = $errObj.error.message ?? $errObj.message
                if ($inner) { $errMsg = [string]$inner }
            } catch {}
            return [PSCustomObject]@{ Success = $false; Data = $null; Error = $errMsg; ExitCode = $response.StatusCode }
        }
    } catch {
        return [PSCustomObject]@{ Success = $false; Data = $null; Error = $_.Exception.Message; ExitCode = -1 }
    }
}

function Invoke-AzRestPaged {
    <#
    .SYNOPSIS
    Call a paged ARM/Graph REST endpoint and accumulate all .value[] entries.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Uri
    )

    $all     = [System.Collections.Generic.List[object]]::new()
    $nextUri = $Uri

    while ($nextUri) {
        $result = Invoke-ArmRest -Uri $nextUri
        if (-not $result.Success) {
            return [PSCustomObject]@{ Success = $false; Data = @(); Error = $result.Error }
        }
        if ($result.Data -and $result.Data.PSObject.Properties['value']) {
            foreach ($item in $result.Data.value) { $all.Add($item) }
        }
        # ARM uses 'nextLink'; Microsoft Graph uses '@odata.nextLink'
        $nextUri = $null
        foreach ($linkProp in 'nextLink', '@odata.nextLink') {
            if ($result.Data -and $result.Data.PSObject.Properties[$linkProp] -and $result.Data.$linkProp) {
                $nextUri = [string]$result.Data.$linkProp
                break
            }
        }
    }

    return [PSCustomObject]@{ Success = $true; Data = $all.ToArray(); Error = $null }
}

# ── Error classifiers ────────────────────────────────────────────────────────
# These are used by check functions (mainly Section8/Section9) to produce
# targeted remediation messages instead of raw exception text.
# For display-facing error messages, use Format-AzErrorMessage in CheckHelpers.ps1.

function Test-FirewallError {
    param([string]$Message)
    foreach ($t in @("firewall", "network acl", "network access", "vnet rule", "public network access is disabled",
                     "failed to resolve", "getaddrinfo failed",
                     "client address is not authorized", "is not a trusted service")) {
        if ($Message -imatch [regex]::Escape($t)) { return $true }
    }
    return $false
}

function Test-AuthzError {
    param([string]$Message)
    # Firewall messages can contain authz phrasing (Key Vault: "Client address is
    # not authorized and caller is not a trusted service") — firewall wins.
    if (Test-FirewallError $Message) { return $false }
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
