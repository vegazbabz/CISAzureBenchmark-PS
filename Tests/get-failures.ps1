Import-Module Pester -Force
$r = Invoke-Pester -Path .\Tests\Checks.Tests.ps1 -Output None -PassThru
$r.Failed | ForEach-Object {
    Write-Host "FAIL: $($_.Name)"
    $_.ErrorRecord | ForEach-Object { Write-Host "  $($_.Exception.Message.Split([Environment]::NewLine)[0])" }
}
Write-Host "Total: $($r.Failed.Count) failed, $($r.Passed.Count) passed"
