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
        [hashtable]$SubNames = @{},  # id -> display name used in warning messages
        [switch]$ProbeKeyVaults      # probe each vault's data plane so the 8.3.x access gap surfaces once, upfront
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
    $probeKVLocal     = $ProbeKeyVaults.IsPresent

    # Run all role lookups in parallel — up to 8 at once
    $subResults = $SubscriptionIds | ForEach-Object -Parallel {
        $subId       = $_
        $uid         = $using:userId
        $accountType = $using:accountTypeLocal
        $probeKV     = $using:probeKVLocal

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

            # Data-plane probe: list one key per vault. Raw error messages are
            # classified in the caller (Test-AuthzError etc. are not visible here —
            # parallel runspaces don't inherit module functions).
            $vaultFailures = @()
            if ($probeKV) {
                $vaults = @()
                try { $vaults = @(Get-AzKeyVault -WarningAction SilentlyContinue -ErrorAction Stop) } catch {}
                foreach ($v in $vaults) {
                    $vn = [string]$v.VaultName
                    try {
                        $null = Get-AzKeyVaultKey -VaultName $vn -WarningAction SilentlyContinue -ErrorAction Stop |
                                    Select-Object -First 1
                    } catch {
                        $vaultFailures += [PSCustomObject]@{
                            Vault = $vn
                            SubId = $subId
                            Error = ($_.Exception.Message -replace '\r?\n', ' ').Trim()
                        }
                    }
                }
            }

            [PSCustomObject]@{ SubId = $subId; Success = $true; Roles = $roles; Error = $null; VaultFailures = $vaultFailures }
        } catch {
            $errMsg = ($_.Exception.Message -replace '\r?\n', ' ').Trim()
            [PSCustomObject]@{ SubId = $subId; Success = $false; Roles = @(); Error = $errMsg; VaultFailures = @() }
        }
    } -ThrottleLimit 8

    # Aggregate: collect unique roles and count how many subscriptions each appears in
    $roleSubCount  = @{}
    $vaultFailures = [System.Collections.Generic.List[object]]::new()
    foreach ($sr in $subResults) {
        $label = if ($SubNames.ContainsKey($sr.SubId) -and $SubNames[$sr.SubId]) { $SubNames[$sr.SubId] } else { $sr.SubId }
        if (-not $sr.Success) {
            $warnings.Add("Could not verify permissions for '$label' ($($sr.SubId)): $($sr.Error)")
            continue
        }
        foreach ($role in ($sr.Roles | Select-Object -Unique)) {
            $roleSubCount[$role] = ($roleSubCount[$role] ?? 0) + 1
        }
        foreach ($vf in @($sr.VaultFailures)) { $vaultFailures.Add($vf) }
    }

    foreach ($w in (New-KeyVaultProbeWarning -Failures $vaultFailures.ToArray())) {
        $warnings.Add($w)
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

function New-KeyVaultProbeWarning {
    <#
    .SYNOPSIS
    Turn per-vault data-plane probe failures into consolidated preflight warnings —
    one per cause (authorization / firewall / other) instead of one ERROR per control
    per vault later. Returns string[]; empty when there are no failures.
    #>
    param([object[]]$Failures = @())

    if ($Failures.Count -eq 0) { return @() }

    $authz    = [System.Collections.Generic.List[string]]::new()
    $firewall = [System.Collections.Generic.List[string]]::new()
    $other    = [System.Collections.Generic.List[string]]::new()

    foreach ($f in $Failures) {
        $name = [string]$f.Vault
        if (Test-AuthzError ([string]$f.Error))        { $authz.Add($name) }
        elseif (Test-FirewallError ([string]$f.Error)) { $firewall.Add($name) }
        else                                           { $other.Add("$name ($([string]$f.Error))") }
    }

    $out = [System.Collections.Generic.List[string]]::new()
    if ($authz.Count -gt 0) {
        $out.Add("Key Vault data-plane access is missing for $($authz.Count) vault(s): $($authz -join ', '). " +
            "Dependent checks (8.3.x) will show ERROR for these vaults. Grant the 'Key Vault Reader' role " +
            "(RBAC vaults) or an access policy with List permissions, e.g. " +
            "az role assignment create --role 'Key Vault Reader' --assignee <upn-or-app-id> --scope <vault-resource-id>")
    }
    if ($firewall.Count -gt 0) {
        $out.Add("Key Vault firewall blocks this machine for $($firewall.Count) vault(s): $($firewall -join ', '). " +
            "Dependent checks (8.3.x) will show ERROR for these vaults. Add the audit machine's IP to each vault's firewall allowlist.")
    }
    if ($other.Count -gt 0) {
        $out.Add("Key Vault data-plane probe failed for $($other.Count) vault(s): $($other -join '; ')")
    }
    return $out.ToArray()
}

function Get-DisabledUserPrefetch {
    <#
    .SYNOPSIS
    Fetch all disabled Entra ID user accounts (tenant-wide) via Microsoft Graph.
    Returns @{ users = [array of {id, userPrincipalName}] } on success or
    @{ __error = <message> } on failure — same sentinel convention as the
    Resource Graph prefetch entries, so Get-PrefetchError works unchanged.
    #>
    $uri = 'https://graph.microsoft.com/v1.0/users?$filter=accountEnabled eq false&$select=id,userPrincipalName'
    $r = Invoke-AzRestPaged -Uri $uri
    if (-not $r.Success) {
        return @{ __error = [string]$r.Error }
    }
    return @{ users = @($r.Data) }
}
