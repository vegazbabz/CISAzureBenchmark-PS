# Azure CLI subprocess layer
# Uses System.Diagnostics.Process for timeout enforcement and stdout/stderr capture
#
# NOTE: Invoke-AzCli is no longer called by the default audit flow — all check sections
# and the permission preflight (Identity.ps1) now use Az PowerShell cmdlets directly.
# The function is kept here as an available utility in case ad-hoc CLI calls are needed.

# On Windows, az is installed as az.cmd — must be launched via cmd.exe /c
# for the batch file's environment setup to work with System.Diagnostics.Process.
$script:IS_WINDOWS = $IsWindows -or ($env:OS -eq 'Windows_NT')

# Used by Identity.ps1 in ForEach-Object -Parallel where Invoke-AzCli is unavailable
$script:AZ_CMD = if ($script:IS_WINDOWS) { "az.cmd" } else { "az" }

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

function Invoke-AzCli {
    <#
    .SYNOPSIS
    Run an az CLI command and return a result object.
    Retries transient failures (429/500/502/503) with exponential backoff.

    .OUTPUTS
    PSCustomObject with: .Success [bool], .Data [object], .Error [string], .ExitCode [int]
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification='All parameters used in retry loop')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$Arguments,
        [string]$SubscriptionId = "",
        [int]$TimeoutSec = 60,
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

            # Use System.Diagnostics.Process for timeout enforcement
            $argStr = ($cmdArgs.ToArray() | ForEach-Object {
                if ($_ -match '[\s"]') { '"{0}"' -f ($_ -replace '"', '\"') } else { $_ }
            }) -join ' '

            $psi = [System.Diagnostics.ProcessStartInfo]::new()
            if ($script:IS_WINDOWS) {
                # az.cmd must be launched through cmd.exe for its batch-file
                # environment setup (Python path etc.) to work correctly.
                $psi.FileName  = 'cmd.exe'
                $psi.Arguments = "/c az $argStr"
            } else {
                $psi.FileName  = 'az'
                $psi.Arguments = $argStr
            }
            $psi.UseShellExecute        = $false
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError  = $true
            $psi.CreateNoWindow         = $true

            $proc = [System.Diagnostics.Process]::new()
            $proc.StartInfo = $psi

            $proc.Start() | Out-Null

            # Track for Ctrl+C cleanup
            $procId = $proc.Id
            if ($script:_runningProcs) { $script:_runningProcs.TryAdd($procId, $proc) | Out-Null }

            $stdoutTask = $proc.StandardOutput.ReadToEndAsync()
            $stderrTask = $proc.StandardError.ReadToEndAsync()

            $completed = $proc.WaitForExit($TimeoutSec * 1000)

            if (-not $completed) {
                # Kill the process tree — on Windows, cmd.exe may have child
                # processes (python.exe for az) that Kill() alone won't reach.
                try {
                    if ($script:IS_WINDOWS) {
                        $null = Start-Process -FilePath 'taskkill.exe' -ArgumentList "/PID $($proc.Id) /T /F" -NoNewWindow -Wait -PassThru 2>$null
                    } else {
                        $proc.Kill($true)  # $true = kill entire process tree (.NET 5+)
                    }
                } catch { <# already exited #> }
                if ($script:_runningProcs) { $script:_runningProcs.TryRemove($procId, [ref]$null) | Out-Null }
                $proc.Dispose()
                $errMsg = "Command timed out after ${TimeoutSec}s: az $($cmdArgs -join ' ')"
                Write-AuditLog "  $errMsg" -Level VERBOSE

                if ($attempt -le $MaxRetries) {
                    if ($script:_throttleBag) { $script:_throttleBag.Add(1) }
                    $baseDelay = [math]::Pow(2, $attempt)
                    $jitter    = Get-Random -Minimum 0.0 -Maximum 1.0
                    $delaySec  = $baseDelay + $jitter
                    Write-AuditLog "  Timeout (attempt $attempt/$MaxRetries) — retrying in $([math]::Round($delaySec, 1))s" -Level VERBOSE
                    Start-Sleep -Milliseconds ([int]($delaySec * 1000))
                    continue
                }
                return [PSCustomObject]@{ Success = $false; Data = $null; Error = $errMsg; ExitCode = -1 }
            }

            # Ensure async reads complete
            [void]$stdoutTask.Wait(5000)
            [void]$stderrTask.Wait(5000)

            $stdoutStr = $stdoutTask.Result
            $stderrStr = $stderrTask.Result
            $exitCode  = $proc.ExitCode
            if ($script:_runningProcs) { $script:_runningProcs.TryRemove($procId, [ref]$null) | Out-Null }
            $proc.Dispose()

            if ($exitCode -ne 0) {
                $errMsg = if ($stderrStr.Trim()) { $stderrStr.Trim() } else { $stdoutStr.Trim() }
                $errMsg = ($errMsg -replace '\r?\n', ' ').Trim()

                # Retry on transient failures
                if ($attempt -le $MaxRetries -and (Test-TransientError $errMsg)) {
                    if ($script:_throttleBag) { $script:_throttleBag.Add(1) }
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

            $stdout = $stdoutStr.Trim()

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
        $nextUri = $null
        if ($result.Data -and $result.Data.PSObject.Properties['nextLink']) {
            $nextUri = $result.Data.nextLink
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
                     "failed to resolve", "getaddrinfo failed")) {
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
