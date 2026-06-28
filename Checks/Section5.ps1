# Section 5 — Identity Services
# CIS Microsoft Azure Foundations Benchmark v6.0.0

# ── Tenant-level checks (run once, not per subscription) ─────────────────────

function Invoke-Check5_1_1 {
    # Security defaults enabled OR Conditional Access in use
    $cid = "5.1.1"; $title = "Ensure that 'security defaults' is Enabled in Microsoft Entra ID"; $level = 1; $sec = "5 - Identity Services"

    $url = "https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy"
    $r   = Invoke-ArmRest -Uri $url

    if (-not $r.Success) {
        return New-ErrorResult $cid $title $level $sec (New-GraphPermissionMessage -Permission 'Policy.Read.All' -ManualCheck 'Entra ID > Properties > Manage Security Defaults.')
    }

    $enabled = [string]$r.Data.isEnabled -eq "True" -or [string]$r.Data.isEnabled -eq "true"

    # If security defaults off, check for Conditional Access policies (acceptable alternative)
    if (-not $enabled) {
        $caResult = Invoke-ArmRest -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
        $caEnabled = $caResult.Success -and $caResult.Data -and $caResult.Data.value -and ($caResult.Data.value | Measure-Object).Count -gt 0
        if ($caEnabled) {
            return New-CISResult $cid $title $level $sec $script:PASS `
                -Details "Security defaults off but Conditional Access policies exist ($( ($caResult.Data.value | Measure-Object).Count) policies). Acceptable alternative."
        }
    }

    New-CISResult $cid $title $level $sec `
        -Status $(if ($enabled) { $script:PASS } else { $script:FAIL }) `
        -Details $(if ($enabled) { "Security defaults are enabled." } else { "Security defaults are disabled and no Conditional Access policies found." }) `
        -Remediation $(if (-not $enabled) { "Entra ID > Properties > Manage Security Defaults > Enable security defaults" } else { "" })
}

function Invoke-Check5_1_2 {
    # Manual — device registration MFA setting lives in the Entra portal and has no
    # stable Graph endpoint for read.
    $cid = "5.1.2"; $title = "Ensure that 'Require Multifactor Authentication to register or join devices with Microsoft Entra' is set to 'Yes'"; $level = 1; $sec = "5 - Identity Services"
    New-ManualResult $cid $title $level $sec `
        "Manual verification required — Microsoft Entra ID > Devices > Device settings > ensure 'Require Multifactor Authentication to register or join devices with Microsoft Entra' is set to 'Yes'."
}

function Invoke-Check5_1_3 {
    # MFA registered for ALL users — uses the current userRegistrationDetails endpoint.
    # The older credentialUserRegistrationDetails endpoint is deprecated and does not paginate.
    $cid = "5.1.3"; $title = "Ensure that 'multifactor authentication' is 'enabled' For All Users"; $level = 1; $sec = "5 - Identity Services"

    $url = "https://graph.microsoft.com/beta/reports/authenticationMethods/userRegistrationDetails"
    $r   = Invoke-AzRestPaged -Uri $url

    if (-not $r.Success) {
        return New-ErrorResult $cid $title $level $sec (New-GraphPermissionMessage -Permission 'UserAuthenticationMethod.Read.All (or Reports.Read.All)')
    }

    $users = @($r.Data)
    $noMfa = @($users | Where-Object { [string]$_.isMfaRegistered -ne 'True' -and [string]$_.isMfaRegistered -ne 'true' })
    $noMfaCount = $noMfa.Count

    if ($noMfaCount -eq 0) {
        return New-CISResult $cid $title $level $sec $script:PASS -Details "All $($users.Count) user(s) have MFA registered."
    }

    $sample = ($noMfa | Select-Object -First 5 | ForEach-Object { [string]$_.userPrincipalName }) -join ', '
    New-CISResult $cid $title $level $sec $script:FAIL `
        -Details "$noMfaCount user(s) without MFA registered (of $($users.Count) total). Sample: $sample" `
        -Remediation "Entra ID > Security > Conditional Access (or per-user MFA) > Require MFA for all users."
}

function Invoke-Check5_1_4 {
    $cid = "5.1.4"; $title = "Ensure that 'Allow users to remember multifactor authentication on devices they trust' is Disabled"; $level = 1; $sec = "5 - Identity Services"
    New-ManualResult $cid $title $level $sec `
        "Manual verification required — setting is in the deprecated Per-user MFA portal. Disable 'Allow users to remember MFA on trusted devices', or migrate to Conditional Access sign-in frequency policies."
}

function Invoke-Check5_3_1 {
    $cid = "5.3.1"; $title = "Ensure that Azure Admin Accounts Are Not Used for Daily Operations"; $level = 1; $sec = "5 - Identity Services"
    New-ManualResult $cid $title $level $sec `
        "Manual verification required — confirm that privileged (admin) accounts are dedicated to administration and are not used for daily/non-privileged activities (email, web browsing, etc.)."
}

function Invoke-Check5_3_2 {
    $cid = "5.3.2"; $title = "Ensure that Guest Users are Reviewed on a Regular Basis"; $level = 1; $sec = "5 - Identity Services"
    New-ManualResult $cid $title $level $sec `
        "Manual verification required — Entra ID > Users > filter User type = Guest; review guest accounts regularly and remove those no longer required (or use Access Reviews)."
}

function Invoke-Check5_3_4 {
    $cid = "5.3.4"; $title = "Ensure that All 'Privileged' Role Assignments are Periodically Reviewed"; $level = 1; $sec = "5 - Identity Services"
    New-ManualResult $cid $title $level $sec `
        "Manual verification required — review privileged role assignments periodically (Entra ID > Roles and administrators, or PIM Access Reviews) and remove unnecessary assignments."
}

function Invoke-Check5_3_5 {
    $cid = "5.3.5"; $title = "Ensure Disabled User Accounts do not Have Read, Write, or Owner Permissions"; $level = 1; $sec = "5 - Identity Services"
    New-ManualResult $cid $title $level $sec `
        "Manual verification required — identify disabled (blocked sign-in) accounts and ensure they hold no Read, Write, or Owner role assignments on Azure resources."
}

function Invoke-Check5_3_6 {
    $cid = "5.3.6"; $title = "Ensure 'Tenant Creator' Role Assignments are Periodically Reviewed"; $level = 1; $sec = "5 - Identity Services"
    New-ManualResult $cid $title $level $sec `
        "Manual verification required — review members of the 'Tenant Creator' role periodically and remove assignments that are no longer required."
}

function Invoke-Check5_3_7 {
    $cid = "5.3.7"; $title = "Ensure All Non-privileged Role Assignments are Periodically Reviewed"; $level = 1; $sec = "5 - Identity Services"
    New-ManualResult $cid $title $level $sec `
        "Manual verification required — periodically review non-privileged role assignments (Access Reviews) and remove access that is no longer required."
}

function Invoke-Check5_5 {
    $cid = "5.5"; $title = "Ensure that a Custom Role is Assigned Permissions for Administering Resource Locks"; $level = 2; $sec = "5 - Identity Services"
    New-ManualResult $cid $title $level $sec `
        "Manual verification required — confirm a custom role exists granting Microsoft.Authorization/locks/* and is assigned to the appropriate principals for managing resource locks."
}

function Invoke-Check5_6 {
    $cid = "5.6"; $title = "Ensure that 'Subscription leaving Microsoft Entra tenant' and 'Subscription entering Microsoft Entra tenant' is set to 'Permit no one'"; $level = 2; $sec = "5 - Identity Services"
    New-ManualResult $cid $title $level $sec `
        "Manual verification required — Entra ID > Manage Tenants (Subscription policies) > set 'Subscription leaving Microsoft Entra tenant' and 'Subscription entering Microsoft Entra tenant' to 'Permit no one'."
}

# ── Per-subscription checks ──────────────────────────────────────────────────

function Invoke-Check5_3_3 {
    param([string]$SubscriptionId, [string]$SubscriptionName, [hashtable]$PrefetchData)
    $cid = "5.3.3"; $title = "Ensure That Use of the 'User Access Administrator' Role is Restricted"; $level = 1; $sec = "5 - Identity Services"
    $sid = $SubscriptionId; $sname = $SubscriptionName

    $roles = @(Get-PrefetchData -PrefetchData $PrefetchData -Key "roles" -SubscriptionId $sid)
    $uaaAssignments = @($roles | Where-Object {
        [string]$_.roleDefinitionId -match $script:ROLE_UAA -and
        [string]$_.scope -match "^/subscriptions/[^/]+$"
    })

    if ($uaaAssignments.Count -eq 0) {
        return New-CISResult $cid $title $level $sec $script:PASS `
            -Details "No User Access Administrator assignments at subscription scope." `
            -SubscriptionId $sid -SubscriptionName $sname
    }

    $names = ($uaaAssignments | ForEach-Object {
        $pn = [string]$_.principalName
        $pi = [string]$_.principalId
        if ($pn) { "$pn ($pi)" } else { $pi }
    }) -join ", "
    New-CISResult $cid $title $level $sec $script:FAIL `
        -Details "User Access Administrator assigned at subscription scope to: $names" `
        -Remediation "IAM > Role assignments > Remove UAA role from subscription scope; use resource-group scope or PIM time-bound assignments instead." `
        -SubscriptionId $sid -SubscriptionName $sname
}

function Invoke-Check5_4 {
    param([string]$SubscriptionId, [string]$SubscriptionName)
    $cid = "5.4"; $title = "Ensure that No Custom Subscription Administrator Roles Exist"; $level = 1; $sec = "5 - Identity Services"
    $sid = $SubscriptionId; $sname = $SubscriptionName

    try {
        $customOwners = @(
            Get-AzRoleDefinition -Custom -Scope "/subscriptions/$sid" -ErrorAction Stop |
            Where-Object { $_.Actions -contains '*' } |
            ForEach-Object { [PSCustomObject]@{ name = $_.Name } }
        )
    } catch {
        return New-ErrorResult $cid $title $level $sec $_.Exception.Message $sid $sname
    }

    if ($customOwners.Count -eq 0) {
        return New-CISResult $cid $title $level $sec $script:PASS `
            -Details "No custom roles with wildcard (*) permissions found." `
            -SubscriptionId $sid -SubscriptionName $sname
    }

    $names = ($customOwners | ForEach-Object { $_.name }) -join ", "
    New-CISResult $cid $title $level $sec $script:FAIL `
        -Details "Custom role(s) with Administrator-level (wildcard *) permissions: $names" `
        -Remediation "IAM > Roles > Review and remove custom roles with wildcard (*) actions assignable at subscription scope." `
        -SubscriptionId $sid -SubscriptionName $sname
}

function Invoke-Check5_7 {
    param([string]$SubscriptionId, [string]$SubscriptionName, [hashtable]$PrefetchData)
    $cid = "5.7"; $title = "Ensure there are between 2 and 3 Subscription Owners"; $level = 1; $sec = "5 - Identity Services"
    $sid = $SubscriptionId; $sname = $SubscriptionName

    $roles = @(Get-PrefetchData -PrefetchData $PrefetchData -Key "roles" -SubscriptionId $sid)
    # Only count Owner assignments directly at the subscription scope — not inherited from management groups.
    $ownerAssignments = @($roles | Where-Object {
        [string]$_.roleDefinitionId -match $script:ROLE_OWNER -and
        [string]$_.scope -match "^/subscriptions/[^/]+$"
    })
    $count = $ownerAssignments.Count

    $pass = $count -ge 2 -and $count -le 3
    New-CISResult $cid $title $level $sec `
        -Status $(if ($pass) { $script:PASS } else { $script:FAIL }) `
        -Details "Found $count subscription Owner(s) at subscription scope. CIS recommends between 2 and 3." `
        -Remediation $(if (-not $pass) { "IAM > Role assignments > Adjust Owner assignments to be between 2 and 3 at subscription scope." } else { "" }) `
        -SubscriptionId $sid -SubscriptionName $sname
}

function Invoke-Section5TenantChecks {
    <#
    .SYNOPSIS
    Run all tenant-level Section 5 checks (called once before subscription loop).
    #>
    $results = [System.Collections.Generic.List[object]]::new()
    $checks  = @(
        @{ Id = '5.1.1'; Fn = { Invoke-Check5_1_1 } }
        @{ Id = '5.1.2'; Fn = { Invoke-Check5_1_2 } }
        @{ Id = '5.1.3'; Fn = { Invoke-Check5_1_3 } }
        @{ Id = '5.1.4'; Fn = { Invoke-Check5_1_4 } }
        @{ Id = '5.3.1'; Fn = { Invoke-Check5_3_1 } }
        @{ Id = '5.3.2'; Fn = { Invoke-Check5_3_2 } }
        @{ Id = '5.3.4'; Fn = { Invoke-Check5_3_4 } }
        @{ Id = '5.3.5'; Fn = { Invoke-Check5_3_5 } }
        @{ Id = '5.3.6'; Fn = { Invoke-Check5_3_6 } }
        @{ Id = '5.3.7'; Fn = { Invoke-Check5_3_7 } }
        @{ Id = '5.5';   Fn = { Invoke-Check5_5   } }
        @{ Id = '5.6';   Fn = { Invoke-Check5_6   } }
    )
    foreach ($check in $checks) {
        try {
            $r = & $check.Fn
            $results.Add($r)
            $icon = switch ($r.Status) {
                'PASS'   { "`u{2705}" }  # ✅
                'FAIL'   { "`u{274C}" }  # ❌
                'ERROR'  { "`u{26A0}`u{FE0F}" }  # ⚠️
                'INFO'   { "`u{2139}`u{FE0F}" }  # ℹ️
                'MANUAL' { "`u{1F4CB}" }  # 📋
                default  { "?" }
            }
            Write-AuditLog "    $($check.Id.PadRight(10)) $icon  $($r.Status)" -Level INFO
        } catch {
            Write-AuditLog "    $($check.Id.PadRight(10)) `u{26A0}`u{FE0F}  ERROR" -Level WARNING
        }
    }
    return $results.ToArray()
}

function Invoke-Section5SubscriptionChecks {
    [CmdletBinding()]
    param(
        [string]$SubscriptionId,
        [string]$SubscriptionName,
        [hashtable]$PrefetchData
    )

    $results = [System.Collections.Generic.List[object]]::new()

    try { $results.Add((Invoke-Check5_3_3 -SubscriptionId $SubscriptionId -SubscriptionName $SubscriptionName -PrefetchData $PrefetchData)) } catch { Write-AuditLog "5.3.3 error: $_" -Level WARNING }
    try { $results.Add((Invoke-Check5_4   -SubscriptionId $SubscriptionId -SubscriptionName $SubscriptionName)) } catch { Write-AuditLog "5.4 error: $_" -Level WARNING }
    try { $results.Add((Invoke-Check5_7   -SubscriptionId $SubscriptionId -SubscriptionName $SubscriptionName -PrefetchData $PrefetchData)) } catch { Write-AuditLog "5.7 error: $_" -Level WARNING }

    return $results.ToArray()
}
