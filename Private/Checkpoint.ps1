# Per-subscription checkpoint save/load
# Enables resume of interrupted audits

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
        timestamp         = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
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
        try {
            $data = Get-Content $file.FullName -Encoding UTF8 -Raw | ConvertFrom-Json -Depth 20

            if ($data.status -ne "completed") { continue }

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
