# Section 2 — Azure Databricks
# CIS Microsoft Azure Foundations Benchmark v6.0.0

function Invoke-Section2Checks {
    [CmdletBinding()]
    param(
        [string]$SubscriptionId,
        [string]$SubscriptionName,
        [hashtable]$PrefetchData
    )

    $results  = [System.Collections.Generic.List[object]]::new()
    $workspaces = @(Get-PrefetchData -PrefetchData $PrefetchData -Key "databricks" -SubscriptionId $SubscriptionId)
    $sid        = $SubscriptionId
    $sname      = $SubscriptionName

    $wsControlIds = @("2.1.1","2.1.2","2.1.7","2.1.9","2.1.10","2.1.11")

    # Prefetch failure — emit ERROR (never a false INFO) for all dependent controls
    $wsErr = Get-PrefetchError -PrefetchData $PrefetchData -Key "databricks"
    if ($wsErr) {
        foreach ($cid in $wsControlIds) {
            $results.Add((New-ErrorResult $cid "Databricks prefetch failed: $wsErr" $sid $sname))
        }
        return $results.ToArray()
    }

    if ($workspaces.Count -eq 0) {
        foreach ($cid in $wsControlIds) {
            $results.Add((New-InfoResult $cid "No Databricks workspaces found." $sid $sname))
        }
        return $results.ToArray()
    }

    foreach ($ws in $workspaces) {
        $name = [string]$ws.name

        # 2.1.2 — NSGs configured on Databricks custom VNet subnets (Level 1)
        $subnets = @(Get-PrefetchData -PrefetchData $PrefetchData -Key "subnets" -SubscriptionId $sid)
        $vnetId  = [string]($ws.PSObject.Properties['vnetId']?.Value)

        # 2.1.1 — Databricks deployed in a customer-managed VNet (vnetId present = custom VNet)
        $hasCustomVnet = [bool]$vnetId
        $results.Add((New-CISResult `
            -ControlId "2.1.1" `
            -Status $(if ($hasCustomVnet) { $script:PASS } else { $script:FAIL }) `
            -Details $(if ($hasCustomVnet) { "Workspace '$name': deployed into customer-managed VNet '$($vnetId.Split('/')[-1])'." } else { "Workspace '$name': uses the Azure-managed VNet (not a customer-managed VNet)." }) `
            -Remediation $(if (-not $hasCustomVnet) { "Redeploy the Databricks workspace with VNet injection into a customer-managed virtual network." } else { "" }) `
            -SubscriptionId $sid -SubscriptionName $sname -Resource $name))

        if (-not $vnetId) {
            $results.Add((New-InfoResult "2.1.2" "Workspace '$name': no custom VNet (managed VNet in use — Azure manages NSGs)." $sid $sname $name))
        } elseif (Get-PrefetchError -PrefetchData $PrefetchData -Key "subnets") {
            $results.Add((New-ErrorResult "2.1.2" "Subnet prefetch failed: $(Get-PrefetchError -PrefetchData $PrefetchData -Key 'subnets')" $sid $sname $name))
        } else {
            $vnetName  = $vnetId.Split('/')[-1]
            $dbSubnets = @($subnets | Where-Object {
                [string]$_.vnetName -ieq $vnetName -and [string]$_.subnetName -match '(?i)databricks'
            })
            if ($dbSubnets.Count -eq 0) {
                $results.Add((New-InfoResult "2.1.2" "Workspace '$name': could not identify Databricks subnets in VNet '$vnetName'." $sid $sname $name))
            } else {
                $missing = @($dbSubnets | Where-Object { [string]$_.hasNsg -notmatch '(?i)^true$' } | ForEach-Object { [string]$_.subnetName })
                $pass    = $missing.Count -eq 0
                $results.Add((New-CISResult `
                    -ControlId "2.1.2" `
                    -Status $(if ($pass) { $script:PASS } else { $script:FAIL }) `
                    -Details $(if ($pass) { "Workspace '$name': all Databricks subnets have NSGs." } else { "Workspace '$name': subnets without NSG: $($missing -join ', ')" }) `
                    -Remediation $(if (-not $pass) { "Associate NSGs with the public and private Databricks subnets in VNet '$vnetName'." } else { "" }) `
                    -SubscriptionId $sid -SubscriptionName $sname -Resource $name))
            }
        }

        # 2.1.7 — Diagnostic logging
        try {
            $settings = @(Get-AzDiagnosticSetting -ResourceId $ws.id -ErrorAction Stop)
            $hasLogs  = $settings.Count -gt 0
            $results.Add((New-CISResult `
                -ControlId "2.1.7" `
                -Status $(if ($hasLogs) { $script:PASS } else { $script:FAIL }) `
                -Details $(if ($hasLogs) { "Diagnostic settings configured." } else { "No diagnostic settings found on workspace." }) `
                -Remediation $(if (-not $hasLogs) { "Azure Portal > Databricks > $name > Diagnostic Settings > Add diagnostic setting" } else { "" }) `
                -SubscriptionId $sid -SubscriptionName $sname -Resource $name))
        } catch {
            $results.Add((New-ErrorResult "2.1.7" $_.Exception.Message $sid $sname $name))
        }

        # 2.1.9 — No public IP
        $noPublicIp = [string]($ws.PSObject.Properties['noPublicIp']?.Value)
        $noPublicIpEnabled = $noPublicIp -eq "true" -or $noPublicIp -eq "True"
        $results.Add((New-CISResult `
            -ControlId "2.1.9" `
            -Status $(if ($noPublicIpEnabled) { $script:PASS } else { $script:FAIL }) `
            -Details $(if ($noPublicIpEnabled) { "No Public IP is enabled." } else { "No Public IP is not enabled." }) `
            -Remediation $(if (-not $noPublicIpEnabled) { "Portal > Databricks > $name > Networking > Enable No Public IP" } else { "" }) `
            -SubscriptionId $sid -SubscriptionName $sname -Resource $name))

        # 2.1.10 — Public network access disabled
        $pubAccess = [string]($ws.PSObject.Properties['publicAccess']?.Value)
        $pubDisabled = $pubAccess -eq "Disabled"
        $results.Add((New-CISResult `
            -ControlId "2.1.10" `
            -Status $(if ($pubDisabled) { $script:PASS } else { $script:FAIL }) `
            -Details $(if ($pubDisabled) { "Public network access is disabled." } else { "Public network access is enabled (value: $pubAccess)." }) `
            -Remediation $(if (-not $pubDisabled) { "Portal > Databricks > $name > Networking > Disable public network access" } else { "" }) `
            -SubscriptionId $sid -SubscriptionName $sname -Resource $name))

        # 2.1.11 — Private endpoints
        $privateEps = [int]($ws.PSObject.Properties['privateEps']?.Value)
        $hasPrivateEps = $privateEps -gt 0
        $results.Add((New-CISResult `
            -ControlId "2.1.11" `
            -Status $(if ($hasPrivateEps) { $script:PASS } else { $script:FAIL }) `
            -Details $(if ($hasPrivateEps) { "$privateEps private endpoint(s) configured." } else { "No private endpoints configured." }) `
            -Remediation $(if (-not $hasPrivateEps) { "Portal > Databricks > $name > Networking > Private Endpoint Connections > Add" } else { "" }) `
            -SubscriptionId $sid -SubscriptionName $sname -Resource $name))
    }

    return $results.ToArray()
}

function Invoke-Section2TenantChecks {
    <#
    .SYNOPSIS
    Section 2 (Databricks) controls v6 defines as Manual — surfaced once so the
    report mirrors the benchmark's control set.
    #>
    $manual = @(
        @{ Id="2.1.3";  Msg="Manual verification required — confirm encryption of traffic between Databricks cluster worker nodes is enabled (Premium tier; cluster configuration)." }
        @{ Id="2.1.4";  Msg="Manual verification required — confirm SCIM provisioning syncs users and groups from Microsoft Entra ID to the Databricks workspace." }
        @{ Id="2.1.5";  Msg="Manual verification required — confirm Unity Catalog is configured for centralized governance of the Databricks workspace." }
        @{ Id="2.1.6";  Msg="Manual verification required — confirm Personal Access Token usage is restricted and token expiry is enforced in the workspace admin settings." }
        @{ Id="2.1.8";  Msg="Manual verification required — confirm critical Databricks data (DBFS root, managed services) is encrypted with customer-managed keys." }
        @{ Id="2.1.12"; Msg="Manual verification required — confirm Databricks workspace groups and their memberships are reviewed on a regular basis." }
    )

    $results = [System.Collections.Generic.List[object]]::new()
    foreach ($m in $manual) {
        $results.Add((New-ManualResult $m.Id $m.Msg))
    }
    return $results.ToArray()
}
