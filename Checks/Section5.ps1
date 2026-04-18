# Section 5 — Identity Services
# CIS Microsoft Azure Foundations Benchmark v5.0.0

# ── Tenant-level checks (run once, not per subscription) ─────────────────────

function Invoke-Check5_1_1 {
    # Security defaults enabled OR Conditional Access in use
    $cid = "5.1.1"; $title = "Ensure Security Defaults Are Enabled on Microsoft Entra ID"; $level = 1; $sec = "5 - Identity Services"

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
    # MFA registration report via Graph beta — uses the current userRegistrationDetails endpoint.
    # The older credentialUserRegistrationDetails endpoint is deprecated and does not paginate.
    $cid = "5.1.2"; $title = "Ensure MFA Is Enabled for All Users in Administrative Roles"; $level = 1; $sec = "5 - Identity Services"

    $url = "https://graph.microsoft.com/beta/reports/authenticationMethods/userRegistrationDetails"
    $r   = Invoke-AzRestPaged -Uri $url

    if (-not $r.Success) {
        return New-ErrorResult $cid $title $level $sec (New-GraphPermissionMessage -Permission 'UserAuthenticationMethod.Read.All (or Reports.Read.All)')
    }

    $users      = @($r.Data)
    # Filter to users assigned to at least one admin role — the isAdmin field is
    # populated by the userRegistrationDetails endpoint and reflects membership
    # in any Azure AD directory role.
    $adminUsers  = @($users | Where-Object { [string]$_.isAdmin -eq 'True' -or [string]$_.isAdmin -eq 'true' })
    $noMfa       = @($adminUsers | Where-Object { [string]$_.isMfaRegistered -ne 'True' -and [string]$_.isMfaRegistered -ne 'true' })
    $noMfaCount  = $noMfa.Count

    if ($noMfaCount -eq 0) {
        return New-CISResult $cid $title $level $sec $script:PASS -Details "All $($adminUsers.Count) admin user(s) (of $($users.Count) total) have MFA registered."
    }

    $sample = ($noMfa | Select-Object -First 5 | ForEach-Object { [string]$_.userPrincipalName }) -join ', '
    New-CISResult $cid $title $level $sec $script:FAIL `
        -Details "$noMfaCount admin user(s) without MFA registered (of $($adminUsers.Count) admin users, $($users.Count) total). Sample: $sample" `
        -Remediation "Entra ID > Per-user MFA or Conditional Access > Require MFA for all administrative roles."
}

function Invoke-Check5_1_3 {
    $cid = "5.1.3"; $title = "Ensure That 'Remember Multi-Factor Authentication on Trusted Devices' Is Disabled"; $level = 1; $sec = "5 - Identity Services"
    New-CISResult $cid $title $level $sec $script:MANUAL `
        -Details "Manual verification required — setting is in the deprecated Per-user MFA portal." `
        -Remediation "Disable 'Allow users to remember MFA on trusted devices' in the legacy MFA portal, or migrate to Conditional Access sign-in frequency policies."
}

function Invoke-Check5_28 {
    $cid = "5.28"; $title = "Ensure Privileged Users Are Protected by Phishing-Resistant MFA"; $level = 1; $sec = "5 - Identity Services"
    New-CISResult $cid $title $level $sec $script:MANUAL `
        -Details "Manual verification required — review privileged-role MFA methods in the Entra ID portal." `
        -Remediation "Entra ID > Users > Per-user MFA, or Conditional Access > Grant > Require authentication strength > Phishing-resistant MFA for all privileged roles."
}

function Invoke-Check5_4 {
    $cid = "5.4"; $title = "Ensure That 'Restrict Non-Admin Users From Creating Tenants' Is Set to 'Yes'"; $level = 1; $sec = "5 - Identity Services"

    $url = "https://graph.microsoft.com/v1.0/policies/authorizationPolicy"
    $r   = Invoke-ArmRest -Uri $url

    if (-not $r.Success) {
        return New-ErrorResult $cid $title $level $sec (New-GraphPermissionMessage -Permission 'Policy.Read.All')
    }

    $policy = if ($r.Data -is [array]) { $r.Data[0] } else { $r.Data }
    $allowed = [string]($policy.PSObject.Properties['defaultUserRolePermissions']?.Value.PSObject.Properties['allowedToCreateTenants']?.Value)
    $restricted = $allowed -eq "False" -or $allowed -eq "false"

    New-CISResult $cid $title $level $sec `
        -Status $(if ($restricted) { $script:PASS } else { $script:FAIL }) `
        -Details $(if ($restricted) { "Non-admin tenant creation is restricted." } else { "Non-admin users can create tenants (defaultUserRolePermissions.allowedToCreateTenants: $allowed)." }) `
        -Remediation $(if (-not $restricted) { "Entra ID > Users > User settings > Restrict non-admin users from creating tenants > Yes" } else { "" })
}

function Invoke-Check5_14 {
    $cid = "5.14"; $title = "Ensure That 'Users Can Register Applications' Is Set to 'No'"; $level = 1; $sec = "5 - Identity Services"

    $url = "https://graph.microsoft.com/v1.0/policies/authorizationPolicy"
    $r   = Invoke-ArmRest -Uri $url

    if (-not $r.Success) {
        return New-ErrorResult $cid $title $level $sec (New-GraphPermissionMessage -Permission 'Policy.Read.All')
    }

    $policy = if ($r.Data -is [array]) { $r.Data[0] } else { $r.Data }
    $allowed = [string]($policy.PSObject.Properties['defaultUserRolePermissions']?.Value.PSObject.Properties['allowedToCreateApps']?.Value)
    $restricted = $allowed -eq "False" -or $allowed -eq "false"

    New-CISResult $cid $title $level $sec `
        -Status $(if ($restricted) { $script:PASS } else { $script:FAIL }) `
        -Details $(if ($restricted) { "Users cannot register applications." } else { "Users can register applications." }) `
        -Remediation $(if (-not $restricted) { "Entra ID > User Settings > App registrations > Users can register applications > No" } else { "" })
}

function Invoke-Check5_15 {
    $cid = "5.15"; $title = "Ensure That 'Guest Users Access Restrictions' Is Set to 'Guest user access is restricted'"; $level = 1; $sec = "5 - Identity Services"

    $url = "https://graph.microsoft.com/v1.0/policies/authorizationPolicy"
    $r   = Invoke-ArmRest -Uri $url

    if (-not $r.Success) {
        return New-ErrorResult $cid $title $level $sec (New-GraphPermissionMessage -Permission 'Policy.Read.All')
    }

    # GuestUserRoleId:
    #   10dae51f-b6af-4016-8d66-8c2a99b929b3 = Restricted Guest User (most restrictive) — PASS only
    #   2af84b1e-32c8-42b7-82bc-daa82404023b = Guest User (can read non-hidden directory objects) — FAIL
    #   a0b1b346-4d3e-4e8b-98f8-753987be4970 = Same access as members — FAIL
    $policy = if ($r.Data -is [array]) { $r.Data[0] } else { $r.Data }
    $roleId = [string]$policy.guestUserRoleId
    $restrictedGuestId = "10dae51f-b6af-4016-8d66-8c2a99b929b3"
    $pass = $roleId -eq $restrictedGuestId

    New-CISResult $cid $title $level $sec `
        -Status $(if ($pass) { $script:PASS } else { $script:FAIL }) `
        -Details $(if ($pass) { "Guest user access is restricted to most restrictive level (Restricted Guest User)." } else { "Guest user role is not the most restrictive setting (current: $roleId). Must be Restricted Guest User ($restrictedGuestId)." }) `
        -Remediation $(if (-not $pass) { "Entra ID > External Identities > External collaboration settings > Guest access restrictions > Guest user access is restricted to properties and memberships of their own directory objects" } else { "" })
}

function Invoke-Check5_16 {
    $cid = "5.16"; $title = "Ensure That 'Guest Invite Restrictions' Is Set to 'Only Admins and Users in the Guest Inviter Role'"; $level = 2; $sec = "5 - Identity Services"

    $url = "https://graph.microsoft.com/v1.0/policies/authorizationPolicy"
    $r   = Invoke-ArmRest -Uri $url

    if (-not $r.Success) {
        return New-ErrorResult $cid $title $level $sec (New-GraphPermissionMessage -Permission 'Policy.Read.All')
    }

    # allowInvitesFrom:
    #   "adminsAndGuestInviters", "admins", or "none" = PASS
    #   "adminsAndAllMembers", "everyone", "allUsers" = FAIL
    $policy = if ($r.Data -is [array]) { $r.Data[0] } else { $r.Data }
    $setting = if ($policy) { [string]$policy.allowInvitesFrom } else { '' }
    $pass = $setting -and ($setting.ToLower() -in @("adminsandguestinviters", "admins", "none"))

    New-CISResult $cid $title $level $sec `
        -Status $(if ($pass) { $script:PASS } else { $script:FAIL }) `
        -Details $(if ($pass) { "Guest invitations restricted to admins/guest inviters (allowInvitesFrom: $setting)." } else { "Any user can invite guests (allowInvitesFrom: $setting)." }) `
        -Remediation $(if (-not $pass) { "Entra ID > External Identities > External collaboration settings > Guest invite restrictions: Only users assigned to specific admin roles" } else { "" })
}

# ── Per-subscription checks ──────────────────────────────────────────────────

function Invoke-Check5_3_3 {
    param([string]$SubscriptionId, [string]$SubscriptionName, [hashtable]$PrefetchData)
    $cid = "5.3.3"; $title = "Ensure 'User Access Administrator' Role Is Not Assigned at Subscription Level"; $level = 1; $sec = "5 - Identity Services"
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
        -Remediation "IAM > Role assignments > Remove UAA role from subscription scope; use resource-group scope instead." `
        -SubscriptionId $sid -SubscriptionName $sname
}

function Invoke-Check5_23 {
    param([string]$SubscriptionId, [string]$SubscriptionName)
    $cid = "5.23"; $title = "Ensure That No Custom Subscription Owner Roles Are Created"; $level = 1; $sec = "5 - Identity Services"
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
        -Details "Custom role(s) with Owner-level permissions: $names" `
        -Remediation "IAM > Roles > Review and remove custom roles with wildcard (*) actions." `
        -SubscriptionId $sid -SubscriptionName $sname
}

function Invoke-Check5_27 {
    param([string]$SubscriptionId, [string]$SubscriptionName, [hashtable]$PrefetchData)
    $cid = "5.27"; $title = "Ensure That the Subscription Has Between 2 and 3 Owners"; $level = 1; $sec = "5 - Identity Services"
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
        -Details "Found $count subscription Owner(s). CIS recommends 2–3." `
        -Remediation $(if (-not $pass) { "IAM > Role assignments > Adjust Owner assignments to be between 2 and 3." } else { "" }) `
        -SubscriptionId $sid -SubscriptionName $sname
}

function Invoke-Section5TenantChecks {
    <#
    .SYNOPSIS
    Run all tenant-level Section 5 checks (called once before subscription loop).
    #>
    $results = [System.Collections.Generic.List[object]]::new()
    $checks  = @(
        @{ Id = '5.1.1'; Title = 'Security Defaults';       Fn = { Invoke-Check5_1_1 } }
        @{ Id = '5.1.2'; Title = 'MFA for Admin Roles';      Fn = { Invoke-Check5_1_2 } }
        @{ Id = '5.1.3'; Title = 'MFA Device Memory';        Fn = { Invoke-Check5_1_3 } }
        @{ Id = '5.28';  Title = 'Phishing-Resistant MFA';   Fn = { Invoke-Check5_28 } }
        @{ Id = '5.4';   Title = 'Restrict Tenant Creation'; Fn = { Invoke-Check5_4  } }
        @{ Id = '5.14';  Title = 'User App Registration';    Fn = { Invoke-Check5_14 } }
        @{ Id = '5.15';  Title = 'Guest Access Restrictions'; Fn = { Invoke-Check5_15 } }
        @{ Id = '5.16';  Title = 'Guest Invite Restrictions'; Fn = { Invoke-Check5_16 } }
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
    try { $results.Add((Invoke-Check5_23  -SubscriptionId $SubscriptionId -SubscriptionName $SubscriptionName)) } catch { Write-AuditLog "5.23 error: $_" -Level WARNING }
    try { $results.Add((Invoke-Check5_27  -SubscriptionId $SubscriptionId -SubscriptionName $SubscriptionName -PrefetchData $PrefetchData)) } catch { Write-AuditLog "5.27 error: $_" -Level WARNING }

    return $results.ToArray()
}
