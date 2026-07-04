# Azure identity and permission helpers

function Get-SignedInUserId {
    <#
    .SYNOPSIS
    Return the identity of the currently signed-in user from the Az context.
    Returns a UPN for users, or app/service-principal ID for service principals.
    #>
    try {
        $ctx = Get-AzContext
        if ($ctx -and $ctx.Account -and $ctx.Account.Id) { return $ctx.Account.Id }
    } catch {}
    return $null
}

function Get-SubscriptionList {
    <#
    .SYNOPSIS
    Return all subscriptions accessible to the current identity (all states).
    Scoped to the specified tenant when provided — prevents cross-tenant subscription
    leakage when the account is a guest in multiple tenants (Get-AzSubscription without
    -TenantId can return subscriptions from all accessible tenants).
    Returns array of {id, name, state} objects.
    Callers are responsible for state-filtering so they can emit useful diagnostics.
    #>
    param([string]$TenantId = "")
    try {
        $subs = if ($TenantId) {
            Get-AzSubscription -TenantId $TenantId -WarningAction SilentlyContinue
        } else {
            Get-AzSubscription -WarningAction SilentlyContinue
        }
        return @($subs | ForEach-Object {
            [PSCustomObject]@{ id = $_.Id; name = $_.Name; state = $_.State }
        })
    } catch {
        throw "Failed to list subscriptions: $_"
    }
}

function Test-AuditPermissions {
    <#
    .SYNOPSIS
    Preflight — verify the signed-in identity can read resources on each subscription.
    Checks run in parallel (up to 8 at once, matching the Python implementation) and
    aggregate unique roles across all subscriptions rather than printing per-sub lines.
    Returns hashtable: .AllClear [bool], .Warnings [string[]], .UserId [string],
                       .Roles [string[]], .RoleSubCount [hashtable], .TotalSubs [int]
    #>
    param(
        [string[]]$SubscriptionIds,
        [hashtable]$SubNames = @{}   # id -> display name used in warning messages
    )

    $warnings = [System.Collections.Generic.List[string]]::new()
    $userId   = Get-SignedInUserId

    if (-not $userId) {
        $warnings.Add("Could not determine signed-in user identity. Run 'Connect-AzAccount' first.")
        return @{ AllClear = $false; Warnings = $warnings.ToArray(); UserId = $null; Roles = @(); RoleSubCount = @{}; TotalSubs = 0 }
    }

    Write-AuditLog "Identity: $userId" -Level DEBUG

    # Capture account type before spawning parallel runspaces so we know whether
    # to use -SignInName (User) or -ObjectId (ServicePrincipal) in Get-AzRoleAssignment.
    $azCtxForParallel = Get-AzContext
    $accountTypeLocal = [string]$azCtxForParallel.Account.Type   # 'User' or 'ServicePrincipal'
    $total            = $SubscriptionIds.Count

    # Run all role lookups in parallel — up to 8 at once
    $subResults = $SubscriptionIds | ForEach-Object -Parallel {
        $subId       = $_
        $uid         = $using:userId
        $accountType = $using:accountTypeLocal

        try {
            # Switch context to this subscription in the current runspace.
            # Note: -SubscriptionId alone is correct here — combining -Context and
            # -SubscriptionId uses conflicting parameter sets and throws.
            $null = Set-AzContext -SubscriptionId $subId `
                        -WarningAction SilentlyContinue -ErrorAction Stop

            $roles = @()
            try {
                # Targeted query — filter to the current identity on the server side
                $assignments = if ($accountType -eq 'ServicePrincipal') {
                    @(Get-AzRoleAssignment -ObjectId $uid -ErrorAction Stop)
                } else {
                    @(Get-AzRoleAssignment -SignInName $uid -ErrorAction Stop)
                }
                $roles = @($assignments | Select-Object -ExpandProperty RoleDefinitionName | Sort-Object -Unique)
            } catch {
                # Fallback: enumerate all assignments and return unique role names
                # (handles edge cases such as group-based assignments or cross-tenant guest accounts)
                $all = @(Get-AzRoleAssignment -ErrorAction SilentlyContinue)
                if ($all.Count -gt 0) {
                    $roles = @($all | Select-Object -ExpandProperty RoleDefinitionName | Sort-Object -Unique)
                }
            }

            [PSCustomObject]@{ SubId = $subId; Success = $true; Roles = $roles; Error = $null }
        } catch {
            $errMsg = ($_.Exception.Message -replace '\r?\n', ' ').Trim()
            [PSCustomObject]@{ SubId = $subId; Success = $false; Roles = @(); Error = $errMsg }
        }
    } -ThrottleLimit 8

    # Aggregate: collect unique roles and count how many subscriptions each appears in
    $roleSubCount = @{}
    foreach ($sr in $subResults) {
        $label = if ($SubNames.ContainsKey($sr.SubId) -and $SubNames[$sr.SubId]) { $SubNames[$sr.SubId] } else { $sr.SubId }
        if (-not $sr.Success) {
            $warnings.Add("Could not verify permissions for '$label' ($($sr.SubId)): $($sr.Error)")
            continue
        }
        foreach ($role in ($sr.Roles | Select-Object -Unique)) {
            $roleSubCount[$role] = ($roleSubCount[$role] ?? 0) + 1
        }
    }

    $allRoles    = @($roleSubCount.Keys | Sort-Object)
    $rolesLower  = @($allRoles | ForEach-Object { $_.ToLower() })
    $hasReader   = @($rolesLower | Where-Object { $_ -in @('reader', 'contributor', 'owner', 'user access administrator') }).Count -gt 0
    $hasSecurity = @($rolesLower | Where-Object { $_ -like 'security*' }).Count -gt 0

    if (-not $hasReader) {
        $warnings.Add("No 'Reader' or higher role found — most audit checks require Reader access.")
    }
    if (-not $hasSecurity) {
        $warnings.Add("No 'Security Reader' or 'Security Admin' role found — some checks (Sections 2, 8) may show as ERROR.")
    }

    return @{
        AllClear     = ($warnings.Count -eq 0)
        Warnings     = $warnings.ToArray()
        UserId       = $userId
        Roles        = $allRoles
        RoleSubCount = $roleSubCount
        TotalSubs    = $total
    }
}
