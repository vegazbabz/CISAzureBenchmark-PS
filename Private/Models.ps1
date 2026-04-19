# CIS result model — one instance per resource per control

function New-CISResult {
    <#
    .SYNOPSIS
    Create a single CIS audit result object.
    This is the core result model — every check emits one or more of these.
    Status must be one of: PASS, FAIL, ERROR, INFO, MANUAL, SUPPRESSED.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification='Factory function that constructs and returns an object; does not modify system state.')]
    param(
        [Parameter(Mandatory)][string]$ControlId,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][int]$Level,
        [Parameter(Mandatory)][string]$Section,
        [Parameter(Mandatory)][string]$Status,
        [string]$Details          = "",
        [string]$Remediation      = "",
        [string]$SubscriptionId   = "",
        [string]$SubscriptionName = "",
        [string]$Resource         = ""
    )

    [PSCustomObject]@{
        ControlId        = $ControlId
        Title            = $Title
        Level            = $Level
        Section          = $Section
        Status           = $Status
        Details          = $Details
        Remediation      = $Remediation
        SubscriptionId   = $SubscriptionId
        SubscriptionName = $SubscriptionName
        Resource         = $Resource
    }
}
