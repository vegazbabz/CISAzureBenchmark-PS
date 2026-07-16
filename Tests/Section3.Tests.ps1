#Requires -Version 7.0
<#
.SYNOPSIS
    Section 3 — Compute Services checks.
    Split from the former Tests\Checks.Tests.ps1 monolith; shared fixtures and the
    hermetic default mocks live in Tests\TestHelpers.ps1.
#>

param()

BeforeAll {
    . (Join-Path $PSScriptRoot "TestHelpers.ps1")
}

# =============================================================================
# SECTION 3 — COMPUTE SERVICES
# =============================================================================

Describe "Invoke-Check3_1_1 — MFA for Privileged VM Access (Manual)" {
    It "returns MANUAL status" {
        $r = Invoke-Check3_1_1
        $r.Status | Should -Be "MANUAL"
    }

    It "returns control id 3.1.1" {
        $r = Invoke-Check3_1_1
        $r.ControlId | Should -Be "3.1.1"
    }
}

Describe "Invoke-Section3TenantChecks" {
    It "returns exactly one result" {
        $results = @(Invoke-Section3TenantChecks)
        $results | Should -HaveCount 1
    }

    It "result has MANUAL status" {
        $results = @(Invoke-Section3TenantChecks)
        $results[0].Status | Should -Be "MANUAL"
    }
}
