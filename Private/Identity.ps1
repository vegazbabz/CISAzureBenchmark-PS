# Azure identity and permission helpers

function Get-SignedInUserId {
    <#
    .SYNOPSIS
    Return the Azure AD object ID of the currently signed-in user.
    #>
    $result = Invoke-AzCli -Arguments @("ad", "signed-in-user", "show", "--query", "id") -TimeoutSec 30
    if ($result.Success -and $result.Data) {
        return [string]$result.Data -replace '"', ''
    }
    # Fallback: use UPN from account show and resolve
    $acct = Invoke-AzCli -Arguments @("account", "show") -TimeoutSec 30
    if ($acct.Success -and $acct.Data.user.name) {
        return [string]$acct.Data.user.name
    }
    return $null
}

function Get-SubscriptionList {
    <#
    .SYNOPSIS
    Return all subscriptions accessible to the current identity (all states).
    Returns array of {id, name, state} objects.
    Callers are responsible for state-filtering so they can emit useful diagnostics.
    #>
    $result = Invoke-AzCli -Arguments @(
        "account", "list", "--all",
        "--query", "[].{id:id,name:name,state:state}"
    ) -TimeoutSec 60
    if (-not $result.Success) {
        throw "Failed to list subscriptions: $($result.Error)"
    }
    return @($result.Data)
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

        $output   = & $azCmd "role" "assignment" "list" `
            "--assignee" $uid `
            "--subscription" $subId `
            "--include-groups" "--include-inherited" `
            "--query" "[].roleDefinitionName" `
            "--output" "json" 2>&1
        $exitCode = $LASTEXITCODE

        $stdoutLines = @($output | Where-Object { $_ -is [string] })
        $stderrLines = @($output | Where-Object { $_ -isnot [string] } | ForEach-Object { "$_" })

        if ($exitCode -ne 0) {
            $errMsg = if ($stderrLines) { $stderrLines -join ' ' } else { $stdoutLines -join ' ' }
            [PSCustomObject]@{ SubId = $subId; Success = $false; Roles = @(); Error = ($errMsg -replace '\r?\n', ' ').Trim() }
        } else {
            $stdout = ($stdoutLines -join "`n").Trim()
            $roles  = @()
            if ($stdout) {
                try { $roles = @($stdout | ConvertFrom-Json -Depth 5 | Where-Object { $_ }) } catch { }
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
    $rolesLower  = $allRoles | ForEach-Object { $_.ToLower() }
    $hasReader   = ($rolesLower | Where-Object { $_ -in @('reader', 'contributor', 'owner', 'user access administrator') }).Count -gt 0
    $hasSecurity = ($rolesLower | Where-Object { $_ -like 'security*' }).Count -gt 0

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
