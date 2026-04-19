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
    $msg = "Requires '$Permission' permission. The az CLI app cannot acquire this scope (Microsoft limitation). Fix: create an app registration with $Permission (application permission) > Grant admin consent > az login --service-principal."
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
    $sidLower = $SubscriptionId.ToLower()
    if (-not $bySubscription.ContainsKey($sidLower)) { return @() }
    $items = $bySubscription[$sidLower]
    if ($null -eq $items) { return @() }
    return @($items)
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
        return "Microsoft Graph API permission denied. Required scopes are missing from the token. Ensure the audit identity has the correct Graph API delegated or application permissions. Try: az login --scope https://graph.microsoft.com/.default"
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
    #>
    param(
        [string]$ControlId,
        [string]$Title,
        [int]$Level,
        [string]$Section,
        [string]$Message,
        [string]$SubscriptionId   = "",
        [string]$SubscriptionName = "",
        [string]$Resource         = ""
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
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification='Factory function that constructs and returns an object; does not modify system state.')]
    param(
        [string]$ControlId,
        [string]$Title,
        [int]$Level,
        [string]$Section,
        [string]$Message,
        [string]$SubscriptionId   = "",
        [string]$SubscriptionName = "",
        [string]$Resource         = ""
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
    #>
    param(
        [string]$ControlId,
        [string]$Title,
        [int]$Level,
        [string]$Section,
        [string]$Message
    )
    New-CISResult -ControlId $ControlId -Title $Title -Level $Level -Section $Section `
        -Status $script:MANUAL -Details $Message
}
