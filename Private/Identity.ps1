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
    Returns array of {id, name, state} objects.
    Callers are responsible for state-filtering so they can emit useful diagnostics.
    #>
    try {
        return @(Get-AzSubscription -WarningAction SilentlyContinue | ForEach-Object {
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
        $warnings.Add("Could not determine signed-in user identity. Run 'az login' first.")
        return @{ AllClear = $false; Warnings = $warnings.ToArray(); UserId = $null; Roles = @(); RoleSubCount = @{}; TotalSubs = 0 }
    }

    Write-AuditLog "Identity: $userId" -Level DEBUG

    $azCmdLocal = $script:AZ_CMD
    $total      = $SubscriptionIds.Count

    # Run all role lookups in parallel — up to 8 at once (matches Python ThreadPoolExecutor)
    # Invoke-AzCli is not available inside ForEach-Object -Parallel runspaces, so the
    # az call is inlined here using $using: captured variables.
    $subResults = $SubscriptionIds | ForEach-Object -Parallel {
        $subId  = $_
        $azCmd  = $using:azCmdLocal
        $uid    = $using:userId

        # Helper: run az and return (exitCode, stdoutText, stderrText)
        function _AzRaw {
            param([string]$Cmd, [string[]]$CmdArgs)
            $out = & $Cmd @CmdArgs 2>&1
            $ec  = $LASTEXITCODE
            $so  = ($out | Where-Object { $_ -is [string] }) -join "`n"
            $se  = ($out | Where-Object { $_ -isnot [string] } | ForEach-Object { "$_" }) -join ' '
            return $ec, $so.Trim(), $se.Trim()
        }

        # Primary query — scoped to assignee (fast, works when $uid is a GUID)
        $subArgs = @("role","assignment","list","--assignee",$uid,"--include-inherited","--include-groups",
                     "--query","[].roleDefinitionName","--output","json")
        if ($subId) { $subArgs += "--subscription"; $subArgs += $subId }
        $ec, $so, $se = _AzRaw -Cmd $azCmd -CmdArgs $subArgs

        # Fallback — mirrors Python: if --assignee failed, try --all filtered to User principals
        if ($ec -ne 0) {
            $fbArgs = @("role","assignment","list","--all","--include-inherited",
                        "--query","[?principalType=='User'].roleDefinitionName","--output","json")
            if ($subId) { $fbArgs += "--subscription"; $fbArgs += $subId }
            $ec, $so, $se = _AzRaw -Cmd $azCmd -CmdArgs $fbArgs
        }

        if ($ec -ne 0) {
            $errMsg = if ($se) { $se } else { $so }
            [PSCustomObject]@{ SubId = $subId; Success = $false; Roles = @(); Error = ($errMsg -replace '\r?\n', ' ').Trim() }
        } else {
            $roles = @()
            if ($so) {
                try { $roles = @($so | ConvertFrom-Json -Depth 5 | Where-Object { $_ }) } catch { }
            }
            [PSCustomObject]@{ SubId = $subId; Success = $true; Roles = $roles; Error = $null }
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
