# CIS result model — one instance per resource per control

function New-CISResult {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification='Factory function that constructs and returns an object; does not modify system state.')]
    [CmdletBinding()]
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
