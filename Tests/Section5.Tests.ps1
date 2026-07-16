#Requires -Version 7.0
<#
.SYNOPSIS
    Section 5 — Identity Services checks and Identity.ps1 helpers.
    Split from the former Tests\Checks.Tests.ps1 monolith; shared fixtures and the
    hermetic default mocks live in Tests\TestHelpers.ps1.
#>

param()

BeforeAll {
    . (Join-Path $PSScriptRoot "TestHelpers.ps1")
}

# =============================================================================
# SECTION 5 — IDENTITY SERVICES
# =============================================================================

Describe "Invoke-Check5_1_1 — Security Defaults" {
    It "returns PASS when security defaults enabled" {
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ isEnabled = $true } } }
        $r = Invoke-Check5_1_1
        $r.Status | Should -Be "PASS"
    }

    It "returns FAIL when security defaults off and no CA policies" {
        Mock Invoke-ArmRest {
            param($Uri)
            if ($Uri -match "identitySecurityDefaults") {
                return [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ isEnabled = $false } }
            }
            return [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @() } }
        }
        $r = Invoke-Check5_1_1
        $r.Status | Should -Be "FAIL"
    }

    It "returns PASS when security defaults off but CA policies exist" {
        Mock Invoke-ArmRest {
            param($Uri)
            if ($Uri -match "identitySecurityDefaults") {
                return [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ isEnabled = $false } }
            }
            # CA policy response
            return [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @([PSCustomObject]@{ id = "ca1" }) } }
        }
        $r = Invoke-Check5_1_1
        $r.Status | Should -Be "PASS"
    }

    It "returns ERROR on API failure" {
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $false; Error = "403 Forbidden"; Data = $null } }
        $r = Invoke-Check5_1_1
        $r.Status | Should -Be "ERROR"
    }
}

Describe "Invoke-Check5_1_2 — Device Registration MFA (manual)" {
    It "returns MANUAL status" {
        $r = Invoke-Check5_1_2
        $r.Status    | Should -Be "MANUAL"
        $r.ControlId | Should -Be "5.1.2"
    }
}

Describe "Invoke-Check5_1_3 — MFA for All Users" {
    It "returns PASS when all users have MFA" {
        $users = @(
            [PSCustomObject]@{ userPrincipalName = "alice@test.com"; isMfaRegistered = $true }
            [PSCustomObject]@{ userPrincipalName = "bob@test.com";   isMfaRegistered = $true }
        )
        Mock Invoke-AzRestPaged { [PSCustomObject]@{ Success = $true; Data = $users } }
        $r = Invoke-Check5_1_3
        $r.Status | Should -Be "PASS"
    }

    It "returns FAIL when any user lacks MFA" {
        $users = @(
            [PSCustomObject]@{ userPrincipalName = "alice@test.com"; isMfaRegistered = $true }
            [PSCustomObject]@{ userPrincipalName = "bob@test.com";   isMfaRegistered = $false }
        )
        Mock Invoke-AzRestPaged { [PSCustomObject]@{ Success = $true; Data = $users } }
        $r = Invoke-Check5_1_3
        $r.Status  | Should -Be "FAIL"
        $r.Details | Should -Match "1 user"
        $r.Details | Should -Match "bob@test.com"
    }

    It "returns FAIL when a non-admin user lacks MFA (all-user scope)" {
        # v6 5.1.3 covers ALL users, not just admins — a non-admin without MFA must FAIL.
        $users = @(
            [PSCustomObject]@{ userPrincipalName = "admin@test.com";    isMfaRegistered = $true }
            [PSCustomObject]@{ userPrincipalName = "external@corp.com"; isMfaRegistered = $false }
        )
        Mock Invoke-AzRestPaged { [PSCustomObject]@{ Success = $true; Data = $users } }
        $r = Invoke-Check5_1_3
        $r.Status | Should -Be "FAIL"
    }

    It "returns ERROR on API failure" {
        Mock Invoke-AzRestPaged { [PSCustomObject]@{ Success = $false; Error = "Forbidden"; Data = $null } }
        (Invoke-Check5_1_3).Status | Should -Be "ERROR"
    }

    It "returns PASS for empty tenant" {
        Mock Invoke-AzRestPaged { [PSCustomObject]@{ Success = $true; Data = @() } }
        (Invoke-Check5_1_3).Status | Should -Be "PASS"
    }
}

Describe "Section 5 manual controls" {
    It "5.1.4 remember-MFA returns MANUAL" {
        $r = Invoke-Check5_1_4; $r.Status | Should -Be "MANUAL"; $r.ControlId | Should -Be "5.1.4"
    }
    It "5.3.1 admin accounts daily ops returns MANUAL" {
        $r = Invoke-Check5_3_1; $r.Status | Should -Be "MANUAL"; $r.ControlId | Should -Be "5.3.1"
    }
    It "5.3.4 privileged role review returns MANUAL" {
        $r = Invoke-Check5_3_4; $r.Status | Should -Be "MANUAL"; $r.ControlId | Should -Be "5.3.4"
    }
    It "5.3.6 tenant creator review returns MANUAL" {
        $r = Invoke-Check5_3_6; $r.Status | Should -Be "MANUAL"; $r.ControlId | Should -Be "5.3.6"
    }
    It "5.3.7 non-privileged review returns MANUAL" {
        $r = Invoke-Check5_3_7; $r.Status | Should -Be "MANUAL"; $r.ControlId | Should -Be "5.3.7"
    }
}

Describe "Invoke-Check5_3_2 — Guest Users Reviewed" {
    It "returns PASS when the tenant has no guest users" {
        Mock Invoke-AzRestPaged { [PSCustomObject]@{ Success = $true; Data = @(
            [PSCustomObject]@{ userPrincipalName = "alice@test.com"; userType = "Member" }
            [PSCustomObject]@{ userPrincipalName = "bob@test.com";   userType = "Member" }
        ) } }
        $r = Invoke-Check5_3_2
        $r.Status    | Should -Be "PASS"
        $r.ControlId | Should -Be "5.3.2"
    }

    It "returns MANUAL with the guest inventory when guests exist" {
        Mock Invoke-AzRestPaged { [PSCustomObject]@{ Success = $true; Data = @(
            [PSCustomObject]@{ userPrincipalName = "alice@test.com";              userType = "Member" }
            [PSCustomObject]@{ userPrincipalName = "ext_x_corp.com#EXT#@t.com";   userType = "Guest" }
            [PSCustomObject]@{ userPrincipalName = "ext_y_corp.com#EXT#@t.com";   userType = "Guest" }
        ) } }
        $r = Invoke-Check5_3_2
        $r.Status  | Should -Be "MANUAL"
        $r.Details | Should -Match "2 guest user"
        $r.Details | Should -Match "ext_x_corp"
    }

    It "returns ERROR when Graph users cannot be read" {
        Mock Invoke-AzRestPaged { [PSCustomObject]@{ Success = $false; Error = "Forbidden"; Data = @() } }
        $r = Invoke-Check5_3_2
        $r.Status  | Should -Be "ERROR"
        $r.Details | Should -Match "User.Read.All"
    }
}

Describe "Invoke-Check5_3_5 — Disabled Accounts Role Assignments" {
    BeforeAll {
        function New-DisabledUsersPD {
            param([object[]]$Users)
            @{ disabledUsers = @{ users = $Users } }
        }
        function New-RoleRecord {
            param([string]$PrincipalId, [string]$PrincipalName = "")
            [PSCustomObject]@{
                principalId      = $PrincipalId
                principalName    = $PrincipalName
                roleDefinitionId = "/subscriptions/$($script:T_SID)/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7"
                scope            = "/subscriptions/$($script:T_SID)"
            }
        }
    }

    It "returns PASS when the tenant has no disabled users" {
        $pd = Merge-PD @((New-PD "roles" @((New-RoleRecord "id-1" "alice"))), (New-DisabledUsersPD @()))
        $r = Invoke-Check5_3_5 -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd
        $r.Status    | Should -Be "PASS"
        $r.ControlId | Should -Be "5.3.5"
    }

    It "returns PASS when disabled users hold no assignments in the subscription" {
        $disabled = @([PSCustomObject]@{ id = "id-dis"; userPrincipalName = "gone@test.com" })
        $pd = Merge-PD @((New-PD "roles" @((New-RoleRecord "id-1" "alice"))), (New-DisabledUsersPD $disabled))
        $r = Invoke-Check5_3_5 -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd
        $r.Status | Should -Be "PASS"
    }

    It "returns FAIL naming the account when a disabled user holds an assignment" {
        $disabled = @([PSCustomObject]@{ id = "id-dis"; userPrincipalName = "gone@test.com" })
        $pd = Merge-PD @((New-PD "roles" @((New-RoleRecord "id-1" "alice"), (New-RoleRecord "id-dis" "gone"))), (New-DisabledUsersPD $disabled))
        $r = Invoke-Check5_3_5 -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd
        $r.Status  | Should -Be "FAIL"
        $r.Details | Should -Match "gone@test.com"
        $r.Details | Should -Match "1 role assignment"
    }

    It "returns ERROR when the roles prefetch failed" {
        $pd = Merge-PD @(@{ roles = @{ __error = "Graph query failed" } }, (New-DisabledUsersPD @()))
        $r = Invoke-Check5_3_5 -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd
        $r.Status  | Should -Be "ERROR"
        $r.Details | Should -Match "Graph query failed"
    }

    It "returns ERROR with Graph guidance when disabled users could not be read" {
        $pd = Merge-PD @((New-PD "roles" @()), @{ disabledUsers = @{ __error = "Forbidden" } })
        $r = Invoke-Check5_3_5 -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd
        $r.Status  | Should -Be "ERROR"
        $r.Details | Should -Match "User.Read.All"
    }

    It "returns ERROR when the disabledUsers prefetch key is absent" {
        $pd = New-PD "roles" @()
        $r = Invoke-Check5_3_5 -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd
        $r.Status  | Should -Be "ERROR"
        $r.Details | Should -Match "User.Read.All"
    }
}

Describe "New-KeyVaultProbeWarning" {
    It "returns nothing when there are no failures" {
        @(New-KeyVaultProbeWarning -Failures @()).Count | Should -Be 0
    }

    It "consolidates authorization failures into one warning naming each vault" {
        $failures = @(
            [PSCustomObject]@{ Vault = "kv-one"; SubId = "s1"; Error = "Operation returned Forbidden" }
            [PSCustomObject]@{ Vault = "kv-two"; SubId = "s1"; Error = "The user is not authorized to perform action" }
        )
        $w = @(New-KeyVaultProbeWarning -Failures $failures)
        $w.Count | Should -Be 1
        $w[0]    | Should -Match "kv-one"
        $w[0]    | Should -Match "kv-two"
        $w[0]    | Should -Match "Key Vault Reader"
    }

    It "reports firewall-blocked vaults separately with allowlist guidance" {
        $failures = @(
            [PSCustomObject]@{ Vault = "kv-fw"; SubId = "s1"; Error = "Request was blocked by the vault firewall" }
        )
        $w = @(New-KeyVaultProbeWarning -Failures $failures)
        $w.Count | Should -Be 1
        $w[0]    | Should -Match "kv-fw"
        $w[0]    | Should -Match "allowlist"
    }

    It "classifies the real Key Vault firewall-block message as firewall, not missing RBAC" {
        $failures = @(
            [PSCustomObject]@{ Vault = "kv-fw2"; SubId = "s1"; Error = "Client address is not authorized and caller is not a trusted service" }
        )
        $w = @(New-KeyVaultProbeWarning -Failures $failures)
        $w.Count | Should -Be 1
        $w[0]    | Should -Match "allowlist"
        $w[0]    | Should -Not -Match "Key Vault Reader"
    }

    It "separates authorization and firewall causes into distinct warnings" {
        $failures = @(
            [PSCustomObject]@{ Vault = "kv-authz"; SubId = "s1"; Error = "Access denied" }
            [PSCustomObject]@{ Vault = "kv-fw";    SubId = "s2"; Error = "blocked by firewall" }
        )
        $w = @(New-KeyVaultProbeWarning -Failures $failures)
        $w.Count | Should -Be 2
    }

    It "surfaces unclassified errors with the raw message" {
        $failures = @(
            [PSCustomObject]@{ Vault = "kv-odd"; SubId = "s1"; Error = "Connection reset by peer" }
        )
        $w = @(New-KeyVaultProbeWarning -Failures $failures)
        $w.Count | Should -Be 1
        $w[0]    | Should -Match "Connection reset by peer"
    }
}

Describe "Get-DisabledUserPrefetch" {
    It "returns a users array on success" {
        Mock Invoke-AzRestPaged { [PSCustomObject]@{ Success = $true; Data = @(
            [PSCustomObject]@{ id = "id-1"; userPrincipalName = "gone@test.com" }
        ) } }
        $pd = Get-DisabledUserPrefetch
        $pd.ContainsKey('users') | Should -BeTrue
        @($pd['users']).Count    | Should -Be 1
    }

    It "returns the __error sentinel on failure" {
        Mock Invoke-AzRestPaged { [PSCustomObject]@{ Success = $false; Error = "Forbidden"; Data = @() } }
        $pd = Get-DisabledUserPrefetch
        $pd['__error'] | Should -Be "Forbidden"
    }
}

Describe "Invoke-Check5_5 — Custom Role for Resource Locks" {
    It "returns PASS when a custom role grants locks actions (flattened shape)" {
        Mock Get-AzRoleDefinition { @([PSCustomObject]@{ Name = "Lock Admin"; IsCustom = $true; Actions = @('Microsoft.Authorization/locks/*') }) }
        $r = Invoke-Check5_5 -SubscriptionId $T_SID -SubscriptionName $T_SNAME
        $r.Status    | Should -Be "PASS"
        $r.ControlId | Should -Be "5.5"
        $r.Level     | Should -Be 2
        $r.Details   | Should -Match "Lock Admin"
    }

    It "returns PASS when a custom role grants locks actions (Permissions[n].Actions shape)" {
        Mock Get-AzRoleDefinition { @([PSCustomObject]@{
            Name = "Lock Admin v2"; IsCustom = $true
            Permissions = @([PSCustomObject]@{ Actions = @('Microsoft.Authorization/locks/read', 'Microsoft.Authorization/locks/write') })
        }) }
        $r = Invoke-Check5_5 -SubscriptionId $T_SID -SubscriptionName $T_SNAME
        $r.Status | Should -Be "PASS"
    }

    It "returns FAIL when no custom role grants locks actions" {
        Mock Get-AzRoleDefinition { @([PSCustomObject]@{ Name = "Reader Plus"; IsCustom = $true; Actions = @('Microsoft.Storage/read') }) }
        $r = Invoke-Check5_5 -SubscriptionId $T_SID -SubscriptionName $T_SNAME
        $r.Status | Should -Be "FAIL"
    }

    It "returns FAIL when no custom roles exist at all" {
        Mock Get-AzRoleDefinition { @() }
        $r = Invoke-Check5_5 -SubscriptionId $T_SID -SubscriptionName $T_SNAME
        $r.Status | Should -Be "FAIL"
    }

    It "returns ERROR when role definitions cannot be read" {
        Mock Get-AzRoleDefinition { throw "AuthorizationFailed" }
        $r = Invoke-Check5_5 -SubscriptionId $T_SID -SubscriptionName $T_SNAME
        $r.Status | Should -Be "ERROR"
    }
}

Describe "Invoke-Check5_6 — Subscription Tenant-Transfer Policy" {
    It "returns PASS when both leaving and entering are blocked" {
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{
            properties = [PSCustomObject]@{ blockSubscriptionsLeavingTenant = $true; blockSubscriptionsIntoTenant = $true }
        } } }
        $r = Invoke-Check5_6
        $r.Status    | Should -Be "PASS"
        $r.ControlId | Should -Be "5.6"
        $r.Level     | Should -Be 2
    }

    It "returns FAIL naming the gap when only leaving is blocked" {
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{
            properties = [PSCustomObject]@{ blockSubscriptionsLeavingTenant = $true; blockSubscriptionsIntoTenant = $false }
        } } }
        $r = Invoke-Check5_6
        $r.Status  | Should -Be "FAIL"
        $r.Details | Should -Match "entering"
        $r.Details | Should -Not -Match "leaving Microsoft Entra tenant' is not blocked"
    }

    It "returns FAIL when neither is blocked" {
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{
            properties = [PSCustomObject]@{ blockSubscriptionsLeavingTenant = $false; blockSubscriptionsIntoTenant = $false }
        } } }
        $r = Invoke-Check5_6
        $r.Status  | Should -Be "FAIL"
        $r.Details | Should -Match "leaving"
        $r.Details | Should -Match "entering"
    }

    It "returns ERROR when the tenant policy cannot be read" {
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $false; Error = "HTTP 403"; Data = $null } }
        $r = Invoke-Check5_6
        $r.Status | Should -Be "ERROR"
    }
}

Describe "Invoke-Check5_3_3 — No UAA at Subscription Scope" {
    It "returns PASS when no UAA assignments at subscription scope" {
        $pd = New-PD "roles" @()
        $r = Invoke-Check5_3_3 -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd
        $r.Status | Should -Be "PASS"
    }

    It "returns FAIL when UAA assigned at subscription scope" {
        $uaaRole = [PSCustomObject]@{
            roleDefinitionId = "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9"
            scope            = "/subscriptions/$T_SID"
            principalName    = "bad-user"
            principalId      = "pid-123"
        }
        $pd = New-PD "roles" @($uaaRole)
        $r = Invoke-Check5_3_3 -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd
        $r.Status | Should -Be "FAIL"
        $r.Details | Should -Match "bad-user"
    }

    It "does not flag UAA at resource-group scope" {
        $uaaRole = [PSCustomObject]@{
            roleDefinitionId = "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9"
            scope            = "/subscriptions/$T_SID/resourceGroups/my-rg"
            principalName    = "ok-user"
            principalId      = "pid-456"
        }
        $pd = New-PD "roles" @($uaaRole)
        $r = Invoke-Check5_3_3 -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd
        $r.Status | Should -Be "PASS"
    }
}

Describe "Invoke-Check5_4 — No Custom Subscription Administrator Roles" {
    It "returns PASS when no custom wildcard roles" {
        Mock Get-AzRoleDefinition { @() }
        $r = Invoke-Check5_4 -SubscriptionId $T_SID -SubscriptionName $T_SNAME
        $r.Status    | Should -Be "PASS"
        $r.ControlId | Should -Be "5.4"
    }

    It "returns FAIL when a custom role has wildcard (*) actions (flattened pre-Az.Resources-10 shape)" {
        Mock Get-AzRoleDefinition { @([PSCustomObject]@{ Name = "MyAdminRole"; IsCustom = $true; Actions = @('*') }) }
        $r = Invoke-Check5_4 -SubscriptionId $T_SID -SubscriptionName $T_SNAME
        $r.Status  | Should -Be "FAIL"
        $r.Details | Should -Match "MyAdminRole"
    }

    It "returns FAIL when a custom role has wildcard (*) actions (Permissions[n].Actions Az.Resources 10 shape)" {
        Mock Get-AzRoleDefinition { @([PSCustomObject]@{
            Name = "MyNewShapeRole"; IsCustom = $true
            Permissions = @(
                [PSCustomObject]@{ Actions = @('Microsoft.Compute/read') }
                [PSCustomObject]@{ Actions = @('*') }
            )
        }) }
        $r = Invoke-Check5_4 -SubscriptionId $T_SID -SubscriptionName $T_SNAME
        $r.Status  | Should -Be "FAIL"
        $r.Details | Should -Match "MyNewShapeRole"
    }

    It "returns PASS when custom roles exist but none has wildcard actions (both shapes)" {
        Mock Get-AzRoleDefinition { @(
            [PSCustomObject]@{ Name = "ScopedOld"; IsCustom = $true; Actions = @('Microsoft.Storage/read') }
            [PSCustomObject]@{ Name = "ScopedNew"; IsCustom = $true; Permissions = @([PSCustomObject]@{ Actions = @('Microsoft.Network/read') }) }
        ) }
        (Invoke-Check5_4 -SubscriptionId $T_SID -SubscriptionName $T_SNAME).Status | Should -Be "PASS"
    }

    It "returns ERROR on API failure" {
        Mock Get-AzRoleDefinition { throw "AuthorizationFailed" }
        (Invoke-Check5_4 -SubscriptionId $T_SID -SubscriptionName $T_SNAME).Status | Should -Be "ERROR"
    }
}

Describe "Invoke-Check5_7 — 2-3 Subscription Owners" {
    BeforeAll {
        function New-Owner {
            param([string]$Name, [string]$PType = "User")
            [PSCustomObject]@{
                roleDefinitionId = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
                scope            = "/subscriptions/$script:T_SID"
                principalName    = $Name
                principalId      = "pid-$Name"
                principalType    = $PType
            }
        }
    }

    It "returns FAIL for zero owners" {
        $pd = New-PD "roles" @()
        (Invoke-Check5_7 -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd).Status | Should -Be "FAIL"
    }

    It "returns FAIL for one owner" {
        $pd = New-PD "roles" @(New-Owner "alice")
        (Invoke-Check5_7 -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd).Status | Should -Be "FAIL"
    }

    It "returns PASS for two owners" {
        $pd = New-PD "roles" @(New-Owner "alice"; New-Owner "bob")
        (Invoke-Check5_7 -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd).Status | Should -Be "PASS"
    }

    It "returns PASS for three owners" {
        $pd = New-PD "roles" @(New-Owner "alice"; New-Owner "bob"; New-Owner "carol")
        (Invoke-Check5_7 -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd).Status | Should -Be "PASS"
    }

    It "returns FAIL for four owners" {
        $pd = New-PD "roles" @(New-Owner "a"; New-Owner "b"; New-Owner "c"; New-Owner "d")
        (Invoke-Check5_7 -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd).Status | Should -Be "FAIL"
    }

    It "does not count management-group scoped owner" {
        $mgOwner = [PSCustomObject]@{
            roleDefinitionId = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
            scope            = "/providers/Microsoft.Management/managementGroups/root"
            principalName    = "mg-admin"
            principalId      = "pid-mg"
            principalType    = "User"
        }
        $pd = New-PD "roles" @($mgOwner)
        (Invoke-Check5_7 -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd).Status | Should -Be "FAIL"
    }
}

Describe "Invoke-Check5_1_1 — Conditional Access read failure" {
    It "returns ERROR when security defaults off and CA policies cannot be read" {
        Mock Invoke-ArmRest {
            param($Uri)
            if ($Uri -match "identitySecurityDefaultsEnforcementPolicy") {
                return [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ isEnabled = "false" }; Error = $null }
            }
            return [PSCustomObject]@{ Success = $false; Data = $null; Error = "403 insufficient privileges" }
        }
        (Invoke-Check5_1_1).Status | Should -Be "ERROR"
    }
}
