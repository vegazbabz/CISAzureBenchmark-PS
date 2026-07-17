# CIS result model — one instance per resource per control

function New-CISResult {
    <#
    .SYNOPSIS
    Create a single CIS audit result object.
    This is the core result model — every check emits one or more of these.
    Status must be one of: PASS, FAIL, ERROR, INFO, MANUAL, SUPPRESSED.
    Title/Level/Section are resolved from the control catalog (Private\Controls.ps1)
    when omitted — checks normally pass only the control id.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification='Factory function that constructs and returns an object; does not modify system state.')]
    param(
        [Parameter(Mandatory)][string]$ControlId,
        [string]$Title            = "",
        [int]$Level               = 0,
        [string]$Section          = "",
        [Parameter(Mandatory)][string]$Status,
        [string]$Details          = "",
        [string]$Remediation      = "",
        [string]$SubscriptionId   = "",
        [string]$SubscriptionName = "",
        [string]$Resource         = ""
    )

    if (-not $Title -or $Level -eq 0 -or -not $Section) {
        $meta = Get-ControlMeta -ControlId $ControlId
        if (-not $Title)   { $Title   = $meta.Title }
        if ($Level -eq 0)  { $Level   = $meta.Level }
        if (-not $Section) { $Section = $meta.Section }
    }

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
