# Section 3 — Compute Services checks

function Invoke-Check3_1_1 {
    <#
    .SYNOPSIS
    3.1.1 — Only MFA-enabled identities can access privileged VMs (Manual, Level 2)

    .DESCRIPTION
    Verify that identities assigned the Virtual Machine Administrator Login
    (or Virtual Machine User Login) role have MFA enabled — either via
    per-user MFA or a Conditional Access policy.  Revoke admin-level
    permissions that violate least-privilege.

    Full automation requires correlating per-subscription role assignments
    with per-user MFA registration status and Conditional Access policy
    evaluation (UserAuthenticationMethod.Read.All + Policy.Read.All).
    Partial checks would be misleading, so this remains manual.
    #>
    $cid = "3.1.1"
    $title = "Ensure Only MFA Enabled Identities Can Access Privileged Virtual Machine"
    $level = 2
    $sec = "3 - Compute Services"

    New-CISResult $cid $title $level $sec $script:MANUAL `
        -Details ("Manual verification required — check that all identities with " +
            "'Virtual Machine Administrator Login' or 'Virtual Machine User Login' " +
            "roles have MFA enabled (per-user MFA or Conditional Access).") `
        -Remediation ("Subscription > Access control (IAM) > Role assignments > filter on " +
            "'Virtual Machine Administrator Login'. For each identity, verify MFA " +
            "via Entra ID > Users > Per-user MFA, or confirm coverage by a " +
            "Conditional Access policy requiring MFA.")
}

function Invoke-Section3TenantChecks {
    <#
    .SYNOPSIS
    Run all tenant-level Section 3 checks (called once before subscription loop).
    #>
    $results = [System.Collections.Generic.List[object]]::new()
    $checks = @(
        @{ Id = '3.1.1'; Title = 'MFA for Privileged VM Access'; Fn = { Invoke-Check3_1_1 } }
    )
    foreach ($check in $checks) {
        try {
            $r = & $check.Fn
            $results.Add($r)
            $icon = switch ($r.Status) {
                'PASS'   { "`u{2705}" }
                'FAIL'   { "`u{274C}" }
                'ERROR'  { "`u{26A0}`u{FE0F}" }
                'INFO'   { "`u{2139}`u{FE0F}" }
                'MANUAL' { "`u{1F4CB}" }
                default  { "?" }
            }
            Write-AuditLog "    $($check.Id.PadRight(10)) $icon  $($r.Status)" -Level INFO
        } catch {
            Write-AuditLog "    $($check.Id.PadRight(10)) `u{26A0}`u{FE0F}  ERROR in check: $_" -Level WARNING
        }
    }
    return $results.ToArray()
}
