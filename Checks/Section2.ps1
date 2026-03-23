# Section 2 — Azure Databricks
# CIS Microsoft Azure Foundations Benchmark v5.0.0

function Invoke-Section2Checks {
    [CmdletBinding()]
    param(
        [string]$SubscriptionId,
        [string]$SubscriptionName,
        [hashtable]$PrefetchData
    )

    $results  = [System.Collections.Generic.List[object]]::new()
    $sec      = "2 - Azure Databricks"
    $workspaces = @(Get-PrefetchData -PrefetchData $PrefetchData -Key "databricks" -SubscriptionId $SubscriptionId)
    $sid        = $SubscriptionId
    $sname      = $SubscriptionName

    if ($workspaces.Count -eq 0) {
        $results.Add((New-InfoResult "2.1.2"  "Ensure That NSGs Are Configured for Azure Databricks Subnets" 1 $sec "No Databricks workspaces found." $sid $sname))
        $results.Add((New-InfoResult "2.1.7"  "Ensure That Azure Databricks Workspace Has Logging Enabled" 2 $sec "No Databricks workspaces found." $sid $sname))
        $results.Add((New-InfoResult "2.1.9"  "Ensure That Azure Databricks Workspace Has 'No Public IP' Enabled" 2 $sec "No Databricks workspaces found." $sid $sname))
        $results.Add((New-InfoResult "2.1.10" "Ensure That Azure Databricks Workspace Has Public Network Access Disabled" 2 $sec "No Databricks workspaces found." $sid $sname))
        $results.Add((New-InfoResult "2.1.11" "Ensure That Azure Databricks Workspace Uses Private Endpoints" 2 $sec "No Databricks workspaces found." $sid $sname))
        return $results.ToArray()
    }

    foreach ($ws in $workspaces) {
        $name = [string]$ws.name

        # 2.1.2 — NSGs configured on Databricks custom VNet subnets (Level 1)
        $subnets = @(Get-PrefetchData -PrefetchData $PrefetchData -Key "subnets" -SubscriptionId $sid)
        $vnetId  = [string]($ws.PSObject.Properties['vnetId']?.Value)
        if (-not $vnetId) {
            $results.Add((New-InfoResult "2.1.2" "Ensure That NSGs Are Configured for Azure Databricks Subnets" 1 $sec "Workspace '$name': no custom VNet (managed VNet in use — Azure manages NSGs)." $sid $sname $name))
        } else {
            $vnetName  = $vnetId.Split('/')[-1]
            $dbSubnets = @($subnets | Where-Object {
                [string]$_.vnetName -ieq $vnetName -and [string]$_.subnetName -match '(?i)databricks'
            })
            if ($dbSubnets.Count -eq 0) {
                $results.Add((New-InfoResult "2.1.2" "Ensure That NSGs Are Configured for Azure Databricks Subnets" 1 $sec "Workspace '$name': could not identify Databricks subnets in VNet '$vnetName'." $sid $sname $name))
            } else {
                $missing = @($dbSubnets | Where-Object { [string]$_.hasNsg -notmatch '(?i)^true$' } | ForEach-Object { [string]$_.subnetName })
                $pass    = $missing.Count -eq 0
                $results.Add((New-CISResult `
                    -ControlId "2.1.2" `
                    -Title "Ensure That NSGs Are Configured for Azure Databricks Subnets" `
                    -Level 1 -Section $sec `
                    -Status $(if ($pass) { $script:PASS } else { $script:FAIL }) `
                    -Details $(if ($pass) { "Workspace '$name': all Databricks subnets have NSGs." } else { "Workspace '$name': subnets without NSG: $($missing -join ', ')" }) `
                    -Remediation $(if (-not $pass) { "Associate NSGs with the public and private Databricks subnets in VNet '$vnetName'." } else { "" }) `
                    -SubscriptionId $sid -SubscriptionName $sname -Resource $name))
            }
        }

        # 2.1.7 — Diagnostic logging
        try {
            $r = Invoke-AzCli -Arguments @(
                "monitor", "diagnostic-settings", "list",
                "--resource", $ws.id
            ) -TimeoutSec $script:TIMEOUTS.default

            $hasLogs = $r.Success -and $r.Data -and ($r.Data | Measure-Object).Count -gt 0
            $results.Add((New-CISResult `
                -ControlId "2.1.7" `
                -Title "Ensure That Azure Databricks Workspace Has Logging Enabled" `
                -Level 2 -Section $sec `
                -Status $(if ($hasLogs) { $script:PASS } else { $script:FAIL }) `
                -Details $(if ($hasLogs) { "Diagnostic settings configured." } else { "No diagnostic settings found on workspace." }) `
                -Remediation $(if (-not $hasLogs) { "Azure Portal > Databricks > $name > Diagnostic Settings > Add diagnostic setting" } else { "" }) `
                -SubscriptionId $sid -SubscriptionName $sname -Resource $name))
        } catch {
            $results.Add((New-ErrorResult "2.1.7" "Ensure That Azure Databricks Workspace Has Logging Enabled" 2 $sec $_.Exception.Message $sid $sname $name))
        }

        # 2.1.9 — No public IP
        $noPublicIp = [string]($ws.PSObject.Properties['noPublicIp']?.Value)
        $noPublicIpEnabled = $noPublicIp -eq "true" -or $noPublicIp -eq "True"
        $results.Add((New-CISResult `
            -ControlId "2.1.9" `
            -Title "Ensure That Azure Databricks Workspace Has 'No Public IP' Enabled" `
            -Level 2 -Section $sec `
            -Status $(if ($noPublicIpEnabled) { $script:PASS } else { $script:FAIL }) `
            -Details $(if ($noPublicIpEnabled) { "No Public IP is enabled." } else { "No Public IP is not enabled." }) `
            -Remediation $(if (-not $noPublicIpEnabled) { "Portal > Databricks > $name > Networking > Enable No Public IP" } else { "" }) `
            -SubscriptionId $sid -SubscriptionName $sname -Resource $name))

        # 2.1.10 — Public network access disabled
        $pubAccess = [string]($ws.PSObject.Properties['publicAccess']?.Value)
        $pubDisabled = $pubAccess -eq "Disabled"
        $results.Add((New-CISResult `
            -ControlId "2.1.10" `
            -Title "Ensure That Azure Databricks Workspace Has Public Network Access Disabled" `
            -Level 2 -Section $sec `
            -Status $(if ($pubDisabled) { $script:PASS } else { $script:FAIL }) `
            -Details $(if ($pubDisabled) { "Public network access is disabled." } else { "Public network access is enabled (value: $pubAccess)." }) `
            -Remediation $(if (-not $pubDisabled) { "Portal > Databricks > $name > Networking > Disable public network access" } else { "" }) `
            -SubscriptionId $sid -SubscriptionName $sname -Resource $name))

        # 2.1.11 — Private endpoints
        $privateEps = [int]($ws.PSObject.Properties['privateEps']?.Value)
        $hasPrivateEps = $privateEps -gt 0
        $results.Add((New-CISResult `
            -ControlId "2.1.11" `
            -Title "Ensure That Azure Databricks Workspace Uses Private Endpoints" `
            -Level 2 -Section $sec `
            -Status $(if ($hasPrivateEps) { $script:PASS } else { $script:FAIL }) `
            -Details $(if ($hasPrivateEps) { "$privateEps private endpoint(s) configured." } else { "No private endpoints configured." }) `
            -Remediation $(if (-not $hasPrivateEps) { "Portal > Databricks > $name > Networking > Private Endpoint Connections > Add" } else { "" }) `
            -SubscriptionId $sid -SubscriptionName $sname -Resource $name))
    }

    return $results.ToArray()
}
