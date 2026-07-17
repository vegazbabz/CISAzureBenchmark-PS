# SARIF 2.1.0 export — lets CI upload findings to GitHub code scanning
# (github/codeql-action/upload-sarif) and Defender for DevOps.

function New-CISSarifReport {
    <#
    .SYNOPSIS
    Write audit results as a SARIF 2.1.0 log.
    Mapping: FAIL -> level 'error', ERROR -> level 'warning' (unauditable is still a
    finding — mirrors the score treating ERROR as failing), SUPPRESSED -> level 'note'
    with a SARIF suppression object (GitHub shows these as dismissed, not open alerts).
    PASS/INFO/MANUAL are omitted — SARIF results represent findings, not inventory.
    Returns the path written.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Results,
        [Parameter(Mandatory)][string]$OutputPath
    )

    $included = @($Results | Where-Object { $_.Status -in @($script:FAIL, $script:ERR, $script:SUPPRESSED) })

    # One SARIF rule per control that produced a finding, in first-seen order
    $ruleIndex = @{}   # ControlId -> index into $rules
    $rules     = [System.Collections.Generic.List[object]]::new()
    foreach ($r in $included) {
        if ($ruleIndex.ContainsKey($r.ControlId)) { continue }
        $ruleIndex[$r.ControlId] = $rules.Count
        $help = if ($r.Remediation) { [string]$r.Remediation } else { [string]$r.Title }
        $rules.Add([ordered]@{
            id               = [string]$r.ControlId
            name             = "CIS$(([string]$r.ControlId) -replace '\.', '_')"
            shortDescription = @{ text = [string]$r.Title }
            help             = @{ text = $help }
            properties       = [ordered]@{
                section  = [string]$r.Section
                cisLevel = [int]$r.Level
            }
        })
    }

    $sarifResults = [System.Collections.Generic.List[object]]::new()
    foreach ($r in $included) {
        $level = switch ($r.Status) {
            $script:FAIL       { 'error' }
            $script:ERR        { 'warning' }
            $script:SUPPRESSED { 'note' }
        }
        $msg = if ($r.Details) { [string]$r.Details } else { [string]$r.Title }

        # GitHub code scanning requires a physical location; Azure findings have no
        # source file, so use a stable pseudo-path: azure/<subscription>/<resource>.
        $segments = @('azure')
        $segments += if ($r.SubscriptionId) { [string]$r.SubscriptionId } else { 'tenant' }
        if ($r.Resource) { $segments += [string]$r.Resource }
        $uri = ($segments | ForEach-Object { [uri]::EscapeDataString($_) }) -join '/'

        $logicalName = if ($r.Resource) { [string]$r.Resource }
                       elseif ($r.SubscriptionName) { [string]$r.SubscriptionName }
                       else { 'tenant' }

        $result = [ordered]@{
            ruleId              = [string]$r.ControlId
            ruleIndex           = [int]$ruleIndex[$r.ControlId]
            level               = $level
            message             = @{ text = $msg }
            locations           = @(
                [ordered]@{
                    physicalLocation = [ordered]@{
                        artifactLocation = @{ uri = $uri }
                        region           = @{ startLine = 1 }
                    }
                    logicalLocations = @(
                        [ordered]@{
                            name               = $logicalName
                            fullyQualifiedName = "$(if ($r.SubscriptionName) { $r.SubscriptionName } else { 'tenant' })/$logicalName"
                            kind               = 'resource'
                        }
                    )
                }
            )
            # Stable alert identity across runs: control + subscription + resource
            partialFingerprints = @{
                cisResultKey = "$($r.ControlId)|$($r.SubscriptionId)|$($r.Resource)"
            }
        }
        if ($r.Status -eq $script:SUPPRESSED) {
            # Details carries the accepted-risk justification appended by Invoke-Suppressions
            $result['suppressions'] = @(
                [ordered]@{ kind = 'external'; justification = [string]$r.Details }
            )
        }
        $sarifResults.Add($result)
    }

    $sarif = [ordered]@{
        '$schema' = 'https://json.schemastore.org/sarif-2.1.0.json'
        version   = '2.1.0'
        runs      = @(
            [ordered]@{
                tool    = @{
                    driver = [ordered]@{
                        name            = 'CISAzureFoundationsBenchmark'
                        informationUri  = 'https://github.com/vegazbabz/CISAzureBenchmark-PS'
                        version         = [string]$script:CIS_VERSION
                        semanticVersion = [string]$script:CIS_VERSION
                        rules           = @($rules)
                        properties      = @{ benchmarkVersion = [string]$script:BENCHMARK_VER }
                    }
                }
                results = @($sarifResults)
            }
        )
    }

    $json = ConvertTo-Json -InputObject $sarif -Depth 12
    # BOM-less UTF-8 — some SARIF consumers reject a byte-order mark
    [System.IO.File]::WriteAllText($OutputPath, $json, [System.Text.UTF8Encoding]::new($false))
    return $OutputPath
}
