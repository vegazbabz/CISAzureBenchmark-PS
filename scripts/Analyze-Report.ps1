#Requires -Version 7.0
Add-Type -AssemblyName System.Web

$reportPath = ".\reports\cis_audit_report_20260418_175152.html"
$content = Get-Content $reportPath -Raw -Encoding UTF8

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
    if ($_.Name -match 'Storage') { return }
    Write-Host "`n=== $($_.Name) ($($_.Count) FAILs) ===" -ForegroundColor Yellow
    $_.Group | Sort-Object Control | ForEach-Object {
        Write-Host "  $($_.Control) [$($_.Sub)]" -ForegroundColor Cyan
        Write-Host "    $($_.Detail.Substring(0, [Math]::Min(250, $_.Detail.Length)))"
    }
}
