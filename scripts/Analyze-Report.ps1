#Requires -Version 7.0
[CmdletBinding()]
param(
    # Path to the HTML report file.  Defaults to the most recently modified
    # cis_audit_report_*.html in the .\reports\ folder when omitted.
    [string]$Path
)

Add-Type -AssemblyName System.Web

if (-not $Path) {
    $latest = Get-ChildItem ".\reports\cis_audit_report_*.html" -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending |
                Select-Object -First 1
    if (-not $latest) {
        Write-Host "No report files found in .\reports\. Use -Path to specify the report file." -ForegroundColor Red
        exit 1
    }
    $Path = $latest.FullName
    Write-Host "Using: $Path" -ForegroundColor DarkGray
}

if (-not (Test-Path $Path)) {
    Write-Host "Report file not found: $Path" -ForegroundColor Red
    exit 1
}

$content = Get-Content $Path -Raw -Encoding UTF8

$rows = [regex]::Matches($content, '<tr[^>]+data-status="FAIL"[^>]*>(.*?)</tr>', 'Singleline')
Write-Host "=== FAIL Results ($($rows.Count)) ===" -ForegroundColor Red

$results = foreach ($row in $rows) {
    $html = $row.Value
    $ctrl = [regex]::Match($html, '<code>(.*?)</code>').Groups[1].Value
    $sec  = [regex]::Match($html, 'data-sec-name="([^"]+)"').Groups[1].Value
    $det  = [regex]::Match($html, '</span></td><td>(.*?)</td></tr>', 'Singleline').Groups[1].Value -replace '<[^>]+>',''
    $sub  = [regex]::Match($html, 'data-sub="([^"]*)"').Groups[1].Value
    if (-not $sub) { $sub = 'Tenant' }
    [PSCustomObject]@{
        Control = $ctrl
        Section = ($sec -replace '.* - ','')
        Sub = $sub
        Detail = ([System.Web.HttpUtility]::HtmlDecode($det) -replace '\s+',' ').Trim()
    }
}

# Group by section - show non-Storage first
$results | Group-Object Section | Sort-Object Name | ForEach-Object {
    # Storage excluded from sectional output — per-account volume (24 checks × N accounts)
    # would flood the console. The total FAIL count above already includes all Storage results.
    if ($_.Name -match 'Storage') { return }
    Write-Host "`n=== $($_.Name) ($($_.Count) FAILs) ===" -ForegroundColor Yellow
    $_.Group | Sort-Object Control | ForEach-Object {
        Write-Host "  $($_.Control) [$($_.Sub)]" -ForegroundColor Cyan
        Write-Host "    $($_.Detail.Substring(0, [Math]::Min(250, $_.Detail.Length)))"
    }
}
