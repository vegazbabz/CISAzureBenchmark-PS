# Helper functions used by all check implementations

function New-GraphPermissionMessage {
    <#
    .SYNOPSIS
    Standard error message for checks that require a Graph API application permission
    the az CLI cannot acquire.
    #>
    param(
        [Parameter(Mandatory)][string]$Permission,
        [string]$ManualCheck
    )
    $msg = "Requires '$Permission' permission. The audit identity's token cannot acquire this scope. Fix: create an app registration with $Permission (application permission) > Grant admin consent > authenticate with Connect-AzAccount -ServicePrincipal or az login --service-principal."
    if ($ManualCheck) { $msg += " Manual check: $ManualCheck" }
    return $msg
}

function Get-PrefetchData {
    <#
    .SYNOPSIS
    O(1) lookup into prefetched Resource Graph data indexed by key + subscription ID.
    Returns array of records (or empty array if not found).
    #>
    param(
        [hashtable]$PrefetchData,
        [string]$Key,
        [string]$SubscriptionId
    )

    if (-not $PrefetchData.ContainsKey($Key)) { return @() }
    $bySubscription = $PrefetchData[$Key]
    if ($bySubscription.ContainsKey('__error')) { return @() }
    $sidLower = $SubscriptionId.ToLower()
    if (-not $bySubscription.ContainsKey($sidLower)) { return @() }
    $items = $bySubscription[$sidLower]
    if ($null -eq $items) { return @() }
    return @($items)
}

function Get-PrefetchError {
    <#
    .SYNOPSIS
    Return the prefetch failure message for a key, or $null if the prefetch succeeded.
    Checks must surface a non-null result as ERROR (never PASS/INFO) so unreadable
    data is not mistaken for an empty, compliant environment.
    #>
    param(
        [hashtable]$PrefetchData,
        [string]$Key
    )

    if (-not $PrefetchData -or -not $PrefetchData.ContainsKey($Key)) { return $null }
    $bySubscription = $PrefetchData[$Key]
    if ($bySubscription -is [hashtable] -and $bySubscription.ContainsKey('__error')) {
        return [string]$bySubscription['__error']
    }
    return $null
}

function Format-AzErrorMessage {
    <#
    .SYNOPSIS
    Translate raw Azure CLI / Graph API error messages into human-readable descriptions.
    #>
    param([string]$Message)

    # If the caller already provided specific permission guidance, don't overwrite it.
    if ($Message -imatch 'requires .+application permission') {
        return $Message
    }

    # Graph API auth errors — must precede the generic auth pattern so callers that
    # prefix messages with "Graph API error:" get Entra-specific guidance instead of
    # the ARM "Grant Reader role on subscription" advice.
    if ($Message -imatch 'graph' -and $Message -imatch 'AuthorizationFailed|does not have authorization|is not authorized|forbidden|Access denied|does not have.*permission|Insufficient privileges|scopes are missing') {
        return "Microsoft Graph API permission denied. Required scopes are missing from the token. Ensure the audit identity has the correct Graph API delegated or application permissions. Try: Connect-AzAccount to re-authenticate, or use a service principal with the required Graph API permissions."
    }
    if ($Message -imatch 'graph.*error|reports.*permission|beta.*reports') {
        return "Microsoft Graph API error — the audit identity may lack the required Graph API permission for this endpoint."
    }
    if ($Message -imatch 'AuthorizationFailed|does not have authorization|is not authorized|forbidden|Access denied|does not have.*permission') {
        return "Insufficient permissions — the audit identity lacks Reader access to this resource. Grant Reader role on the subscription or resource."
    }
    if ($Message -imatch 'firewall|network acl|network rule|public network access is disabled|not accessible from the current network') {
        return "Network access blocked — resource has firewall rules that prevent the audit from reading it. Add the audit machine's IP to the resource firewall allowlist."
    }
    if ($Message -imatch 'FeatureNotSupportedForAccountType|not supported for this account type|BlobServiceProperties|feature.*not.*supported') {
        return "Feature not supported for this resource type — control is not applicable to this tier or kind."
    }
    if ($Message -imatch 'ResourceNotFound|\(404\)|was not found|does not exist') {
        return "Resource not found — it may have been deleted or the resource type is not deployed in this subscription."
    }
    if ($Message -imatch 'TooManyRequests|\(429\)|rate limit|throttl') {
        return "API rate limit reached — too many requests. Re-run the audit or reduce parallelism with -Parallel 1."
    }
    if ($Message -imatch 'ConnectionError|Failed to establish|unable to connect|Name or service not known') {
        return "Network connectivity error — could not reach Azure API endpoint. Check internet access and proxy settings."
    }
    if ($Message -imatch 'JSON parse error') {
        return "Unexpected API response format — the Azure CLI returned data that could not be parsed."
    }

    # Return truncated original if no pattern matched
    if ($Message.Length -gt 220) { return $Message.Substring(0, 220) + "…" }
    return $Message
}

function New-ErrorResult {
    <#
    .SYNOPSIS
    Shorthand factory for ERROR results. Passes the message through Format-AzErrorMessage
    so raw API error strings are translated into human-readable guidance.
    Title/Level/Section come from the control catalog unless explicitly overridden.
    #>
    param(
        [Parameter(Mandatory, Position = 0)][string]$ControlId,
        [Parameter(Position = 1)][string]$Message,
        [Parameter(Position = 2)][string]$SubscriptionId   = "",
        [Parameter(Position = 3)][string]$SubscriptionName = "",
        [Parameter(Position = 4)][string]$Resource         = "",
        [string]$Title   = "",
        [int]$Level      = 0,
        [string]$Section = ""
    )
    $msg = Format-AzErrorMessage -Message $Message
    New-CISResult -ControlId $ControlId -Title $Title -Level $Level -Section $Section `
        -Status $script:ERR -Details $msg `
        -SubscriptionId $SubscriptionId -SubscriptionName $SubscriptionName -Resource $Resource
}

function New-InfoResult {
    <#
    .SYNOPSIS
    Shorthand factory for INFO results (non-assessed — resource not present or not applicable).
    Title/Level/Section come from the control catalog unless explicitly overridden.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification='Factory function that constructs and returns an object; does not modify system state.')]
    param(
        [Parameter(Mandatory, Position = 0)][string]$ControlId,
        [Parameter(Position = 1)][string]$Message,
        [Parameter(Position = 2)][string]$SubscriptionId   = "",
        [Parameter(Position = 3)][string]$SubscriptionName = "",
        [Parameter(Position = 4)][string]$Resource         = "",
        [string]$Title   = "",
        [int]$Level      = 0,
        [string]$Section = ""
    )
    New-CISResult -ControlId $ControlId -Title $Title -Level $Level -Section $Section `
        -Status $script:INFO -Details $Message `
        -SubscriptionId $SubscriptionId -SubscriptionName $SubscriptionName -Resource $Resource
}

function New-ManualResult {
    <#
    .SYNOPSIS
    Shorthand factory for MANUAL results — controls that cannot be automated and require
    a human reviewer to verify compliance in the portal.
    Title/Level/Section come from the control catalog unless explicitly overridden.
    #>
    param(
        [Parameter(Mandatory, Position = 0)][string]$ControlId,
        [Parameter(Position = 1)][string]$Message,
        [string]$Title   = "",
        [int]$Level      = 0,
        [string]$Section = ""
    )
    New-CISResult -ControlId $ControlId -Title $Title -Level $Level -Section $Section `
        -Status $script:MANUAL -Details $Message
}

function Add-ClassifiedErrorSet {
    <#
    .SYNOPSIS
    Classify one data-plane read failure and emit the same outcome for every control
    that depended on that read.

    .DESCRIPTION
    Sections 8 and 9 repeated a four-branch catch block (not-applicable / authorization /
    firewall / raw fallback) per check — ~11 near-identical copies. This function owns the
    classification once: not-applicable produces INFO (only when -NotApplicableMessage is
    given), authorization and firewall produce ERROR with the caller's remediation text,
    anything else produces ERROR with the raw message. Control titles/levels/sections come
    from the catalog.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification='Appends to the provided in-memory result list; does not modify system state.')]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$Results,
        [Parameter(Mandatory)][string[]]$ControlIds,
        [Parameter(Mandatory)][string]$Message,
        [string]$NotApplicableMessage = "",
        [string]$AuthzMessage         = "Insufficient permissions to read this resource.",
        [string]$FirewallMessage      = "A firewall or network configuration is blocking access from the audit machine.",
        [string]$SubscriptionId       = "",
        [string]$SubscriptionName     = "",
        [string]$Resource             = ""
    )

    foreach ($cid in $ControlIds) {
        $emit = @{ ControlId = $cid; SubscriptionId = $SubscriptionId; SubscriptionName = $SubscriptionName; Resource = $Resource }
        if ($NotApplicableMessage -and (Test-NotApplicableError $Message)) {
            $Results.Add((New-InfoResult @emit -Message $NotApplicableMessage))
        } elseif (Test-AuthzError $Message) {
            $Results.Add((New-ErrorResult @emit -Message $AuthzMessage))
        } elseif (Test-FirewallError $Message) {
            $Results.Add((New-ErrorResult @emit -Message $FirewallMessage))
        } else {
            $Results.Add((New-ErrorResult @emit -Message $Message))
        }
    }
}
