#Requires -Version 7.0
<#
.SYNOPSIS
    Validates the inline JavaScript inside the generated HTML report.
.DESCRIPTION
    The HTML report is a self-contained single file — its JavaScript is inline and
    never executed by any tooling before a user opens the report in a browser, so a
    syntax error introduced while editing Private/Report.ps1 would ship silently.

    This script guards against that:
      1. Generates a report to a temp path with synthetic results covering all six
         statuses plus history (exercises the trend-chart code path).
      2. Extracts every <script>...</script> block to a .js file.
      3. Structural assertions: at least two blocks, none empty.
      4. Runs `node --check` on each block when a Node.js runtime is available.

    Without Node the syntax check is skipped with a warning (exit 0) so local runs
    don't require it. CI passes -RequireJsEngine to make a missing runtime a failure.
.PARAMETER RequireJsEngine
    Fail (exit 1) if no Node.js runtime is available instead of skipping the check.
.EXAMPLE
    ./scripts/Test-ReportScript.ps1
.EXAMPLE
    ./scripts/Test-ReportScript.ps1 -RequireJsEngine   # CI
#>
[CmdletBinding()]
param(
    [switch]$RequireJsEngine
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Load project functions ────────────────────────────────────────────────────
$root = Split-Path $PSScriptRoot -Parent
foreach ($f in Get-ChildItem "$root/Private/*.ps1") { . $f.FullName }

# ── Synthetic results — one of every status, multiple subscriptions ──────────
$results = @(
    New-CISResult -ControlId '9.3.4' -Title 'Secure transfer required' -Level 1 -Section '9 - Storage' `
        -Status $script:PASS -Details 'HTTPS-only: True' `
        -SubscriptionId 'sub1' -SubscriptionName 'Production' -Resource 'stprod01'
    New-CISResult -ControlId '7.1' -Title 'RDP not open to internet' -Level 1 -Section '7 - Networking' `
        -Status $script:FAIL -Details "Rule 'allow-rdp' permits 3389 from *" -Remediation 'Restrict NSG source' `
        -SubscriptionId 'sub1' -SubscriptionName 'Production' -Resource 'nsg-mgmt'
    New-CISResult -ControlId '7.2' -Title 'SSH not open to internet' -Level 1 -Section '7 - Networking' `
        -Status $script:PASS -SubscriptionId 'sub2' -SubscriptionName 'Staging' -Resource 'nsg-app'
    New-ErrorResult -ControlId '8.3.1' -Title 'Key expiration set' -Level 1 -Section '8 - Security' `
        -Message 'AuthorizationFailed: no data plane access' `
        -SubscriptionId 'sub2' -SubscriptionName 'Staging' -Resource 'kv-stag'
    New-InfoResult -ControlId '9.2.1' -Title 'Blob soft delete' -Level 1 -Section '9 - Storage' `
        -Message 'ADLS Gen2 - not applicable' `
        -SubscriptionId 'sub1' -SubscriptionName 'Production' -Resource 'stadls01'
    New-ManualResult -ControlId '3.1.1' -Title 'MFA for privileged VM access' -Level 2 -Section '3 - Compute' `
        -Message 'Requires manual review'
    New-CISResult -ControlId '7.3' -Title 'UDP restricted' -Level 1 -Section '7 - Networking' `
        -Status $script:SUPPRESSED -Details 'Open UDP  [Accepted risk: game server - expires 2027-01-01]' `
        -SubscriptionId 'sub1' -SubscriptionName 'Production' -Resource 'nsg-game'
)

# History with two entries so the trend-chart branch renders
$history = @(
    [PSCustomObject]@{ timestamp = '2026-06-01T00:00:00Z'; score = 72.5; pass = 29; fail = 11; error = 2 }
    [PSCustomObject]@{ timestamp = '2026-07-01T00:00:00Z'; score = 80.0; pass = 32; fail = 8;  error = 1 }
)

$scopeInfo = @{
    tenant        = '00000000-0000-0000-0000-000000000000'
    user          = 'report-js-check'
    caller_type   = 'User'
    scope_label   = 'JS validation run'
    subscriptions = @('Production', 'Staging')
    level_filter  = 'both'
}

# Synthetic run diff so the "Changes vs previous run" block renders
$previous = @(
    [PSCustomObject]@{ control = '9.3.4'; title = 'Secure transfer required'; level = 1; subscription = 'Production'; resource = 'stprod01'; status = 'FAIL'; details = 'HTTPS-only: False' }
    [PSCustomObject]@{ control = '7.2'; title = 'SSH not open to internet'; level = 1; subscription = 'Staging'; resource = 'nsg-app'; status = 'PASS'; details = '' }
    [PSCustomObject]@{ control = '6.4'; title = 'Retired control'; level = 1; subscription = 'Production'; resource = ''; status = 'PASS'; details = 'gone in current run' }
)
$diff = Get-RunDiff -CurrentResults $results -PreviousResults $previous

# ── Generate to a temp path ───────────────────────────────────────────────────
$tmpDir  = Join-Path ([System.IO.Path]::GetTempPath()) ("cis_report_js_" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmpDir | Out-Null
$outPath = Join-Path $tmpDir 'report.html'

try {
    New-CISHtmlReport -Results $results -OutputPath $outPath -ScopeLabel 'JS validation run' `
        -History $history -ScopeInfo $scopeInfo `
        -SubTimestamps @{ Production = '2026-07-01T00:00:00Z'; Staging = '2026-07-01T00:00:00Z' } `
        -Diff $diff

    if (-not (Test-Path $outPath)) { throw "Report was not generated at $outPath" }
    $html = Get-Content $outPath -Raw

    if ($html -notmatch 'Changes vs previous run') {
        throw 'Diff section did not render — expected "Changes vs previous run" in the report.'
    }

    # ── Extract every inline <script> block ───────────────────────────────────
    $blocks = [regex]::Matches($html, '(?s)<script>(.*?)</script>')
    Write-Host "Extracted $($blocks.Count) inline <script> block(s) from generated report."

    if ($blocks.Count -lt 2) {
        throw "Expected at least 2 inline <script> blocks, found $($blocks.Count) — report template structure changed?"
    }

    $jsFiles = [System.Collections.Generic.List[string]]::new()
    for ($i = 0; $i -lt $blocks.Count; $i++) {
        $js = $blocks[$i].Groups[1].Value
        if (-not $js.Trim()) { throw "Inline <script> block #$($i + 1) is empty." }
        $jsPath = Join-Path $tmpDir "block$($i + 1).js"
        Set-Content -Path $jsPath -Value $js -Encoding UTF8
        $jsFiles.Add($jsPath)
    }

    # ── Syntax-check with node when available ─────────────────────────────────
    $node = Get-Command node -ErrorAction SilentlyContinue
    if (-not $node) {
        if ($RequireJsEngine) {
            Write-Host 'FAIL: Node.js is required (-RequireJsEngine) but was not found on PATH.' -ForegroundColor Red
            exit 1
        }
        Write-Host 'WARN: Node.js not found — JS syntax check skipped (structure checks passed). Install Node or rely on CI.' -ForegroundColor Yellow
        exit 0
    }

    $failed = 0
    foreach ($jsPath in $jsFiles) {
        & $node.Source --check $jsPath 2>&1 | ForEach-Object { Write-Host "  $_" }
        if ($LASTEXITCODE -ne 0) {
            Write-Host "FAIL: node --check failed for $(Split-Path $jsPath -Leaf)" -ForegroundColor Red
            $failed++
        } else {
            Write-Host "OK: $(Split-Path $jsPath -Leaf) parses cleanly." -ForegroundColor Green
        }
    }

    if ($failed -gt 0) { exit 1 }
    Write-Host 'Report inline JavaScript: all blocks parse cleanly.' -ForegroundColor Green
    exit 0
} finally {
    Remove-Item -Recurse -Force $tmpDir -ErrorAction SilentlyContinue
}
