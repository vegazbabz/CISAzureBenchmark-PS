# Per-subscription and tenant checkpoint save/load
# Enables resume of interrupted audits

$script:TENANT_CHECKPOINT_FILE = "_tenant.json"

function Save-TenantCheckpoint {
    <#
    .SYNOPSIS
    Persist tenant-level (Section 5) results to disk.
    #>
    param([object[]]$Results)

    $dir = $script:CHECKPOINT_DIR
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }

    $path    = Join-Path $dir $script:TENANT_CHECKPOINT_FILE
    $tmpPath = "$path.tmp"

    $data = [ordered]@{
        tool_version      = $script:CIS_VERSION
        benchmark_version = $script:BENCHMARK_VER
        timestamp         = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
        status            = "completed"
        results           = @($Results | ForEach-Object {
            [ordered]@{
                control_id        = $_.ControlId
                title             = $_.Title
                level             = $_.Level
                section           = $_.Section
                status            = $_.Status
                details           = $_.Details
                remediation       = $_.Remediation
                subscription_id   = $_.SubscriptionId
                subscription_name = $_.SubscriptionName
                resource          = $_.Resource
            }
        })
    }

    $json = $data | ConvertTo-Json -Depth 10
    Set-Content -Path $tmpPath -Value $json -Encoding UTF8
    Move-Item -Path $tmpPath -Destination $path -Force

    Write-AuditLog "Tenant checkpoint saved: $path ($($Results.Count) results)" -Level DEBUG
}

function Get-TenantCheckpoint {
    <#
    .SYNOPSIS
    Load tenant-level results from checkpoint.
    Returns $null if no valid checkpoint exists (caller should re-run live).
    #>
    $dir = $script:CHECKPOINT_DIR
    $path = Join-Path $dir $script:TENANT_CHECKPOINT_FILE
    if (-not (Test-Path $path)) { return $null }

    try {
        $data = Get-Content $path -Encoding UTF8 -Raw | ConvertFrom-Json -Depth 20
    } catch {
        Write-AuditLog "Could not read tenant checkpoint: $_" -Level WARNING
        return $null
    }

    if ($data.tool_version -ne $script:CIS_VERSION) {
        Write-AuditLog "Tenant checkpoint was written by v$($data.tool_version) (current: v$($script:CIS_VERSION)) — re-running." -Level WARNING
        return $null
    }

    $results = @($data.results | ForEach-Object {
        New-CISResult `
            -ControlId        ([string]$_.control_id) `
            -Title            ([string]$_.title) `
            -Level            ([int]$_.level) `
            -Section          ([string]$_.section) `
            -Status           ([string]$_.status) `
            -Details          ([string]$_.details) `
            -Remediation      ([string]$_.remediation) `
            -SubscriptionId   ([string]$_.subscription_id) `
            -SubscriptionName ([string]$_.subscription_name) `
            -Resource         ([string]$_.resource)
    })

    return $results
}

function Save-AuditCheckpoint {
    <#
    .SYNOPSIS
    Atomically persist per-subscription results to disk.
    #>
    param(
        [string]$SubscriptionId,
        [string]$SubscriptionName,
        [object[]]$Results,
        [string]$Status = "completed"
    )

    $dir = $script:CHECKPOINT_DIR
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }

    $safeName = $SubscriptionId -replace '[^a-zA-Z0-9\-]', '_'
    $path     = Join-Path $dir "$safeName.json"
    $tmpPath  = "$path.tmp"

    $data = [ordered]@{
        tool_version      = $script:CIS_VERSION
        benchmark_version = $script:BENCHMARK_VER
        timestamp         = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
        subscription_id   = $SubscriptionId
        subscription_name = $SubscriptionName
        status            = $Status
        results           = @($Results | ForEach-Object {
            [ordered]@{
                control_id        = $_.ControlId
                title             = $_.Title
                level             = $_.Level
                section           = $_.Section
                status            = $_.Status
                details           = $_.Details
                remediation       = $_.Remediation
                subscription_id   = $_.SubscriptionId
                subscription_name = $_.SubscriptionName
                resource          = $_.Resource
            }
        })
    }

    $json = $data | ConvertTo-Json -Depth 10
    Set-Content -Path $tmpPath -Value $json -Encoding UTF8
    Move-Item -Path $tmpPath -Destination $path -Force

    Write-AuditLog "Checkpoint: $path ($($Results.Count) results)" -Level DEBUG
}

function Get-AuditCheckpoints {
    <#
    .SYNOPSIS
    Load all completed checkpoints from disk.
    Returns hashtable: subscription_id -> @{ Results, SubscriptionName, Timestamp }
    #>
    $dir = $script:CHECKPOINT_DIR
    if (-not (Test-Path $dir)) { return @{} }

    $checkpoints = @{}

    foreach ($file in Get-ChildItem -Path $dir -Filter "*.json") {
        if ($file.Name -eq $script:TENANT_CHECKPOINT_FILE) { continue }
        try {
            $data = Get-Content $file.FullName -Encoding UTF8 -Raw | ConvertFrom-Json -Depth 20

            if ($data.status -ne "completed") { continue }

            # Discard checkpoints written by a different version of the tool.
            # Control titles, remediation text, and detail strings change between
            # versions. Loading stale data produces misleading report output.
            if ([string]$data.tool_version -ne $script:CIS_VERSION) {
                Write-AuditLog "Checkpoint $($file.Name) was written by v$($data.tool_version) (current: v$($script:CIS_VERSION)) — re-running." -Level WARNING
                continue
            }

            $results = @($data.results | ForEach-Object {
                New-CISResult `
                    -ControlId        ([string]$_.control_id) `
                    -Title            ([string]$_.title) `
                    -Level            ([int]$_.level) `
                    -Section          ([string]$_.section) `
                    -Status           ([string]$_.status) `
                    -Details          ([string]$_.details) `
                    -Remediation      ([string]$_.remediation) `
                    -SubscriptionId   ([string]$_.subscription_id) `
                    -SubscriptionName ([string]$_.subscription_name) `
                    -Resource         ([string]$_.resource)
            })

            $checkpoints[$data.subscription_id] = @{
                Results          = $results
                SubscriptionName = [string]$data.subscription_name
                Timestamp        = [string]$data.timestamp
            }
        } catch {
            Write-AuditLog "Skipping corrupt checkpoint $($file.Name): $_" -Level WARNING
        }
    }

    return $checkpoints
}

function Remove-AuditCheckpoints {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification='Internal audit helper; confirmation prompts would break non-interactive CI runs.')]
    param([string[]]$SubscriptionIds = @())

    $dir = $script:CHECKPOINT_DIR
    if (-not (Test-Path $dir)) { return }

    if ($SubscriptionIds.Count -eq 0) {
        Remove-Item -Path (Join-Path $dir "*.json") -Force -ErrorAction SilentlyContinue
    } else {
        foreach ($sid in $SubscriptionIds) {
            $safeName = $sid -replace '[^a-zA-Z0-9\-]', '_'
            $path     = Join-Path $dir "$safeName.json"
            if (Test-Path $path) { Remove-Item $path -Force }
        }
    }
}
