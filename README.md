# CISAzureBenchmark-PS

PowerShell audit tool for the **CIS Microsoft Azure Foundations Benchmark v5.0.0**.
Scans Azure subscriptions and produces an HTML report with per-control
PASS / FAIL / ERROR / INFO / MANUAL results.

## Features

- **72 automated checks** across 6 CIS sections (2, 5, 6, 7, 8, 9)
- Rich single-file **HTML report** with filtering, compliance scoring, and remediation guidance
- **Parallel** subscription auditing (configurable worker count)
- **Checkpoint / resume** — interrupted runs pick up where they left off
- Zero external module dependencies — only PowerShell 7+ and the Azure CLI

## Prerequisites

| Requirement | Minimum |
|---|---|
| PowerShell | 7.0+ |
| Azure CLI | 2.60+ |
| Azure role | **Reader** on target subscriptions |

Authenticate before running:

```powershell
az login
```

## Quick start

```powershell
# Audit all accessible subscriptions
.\Invoke-CISAzureAudit.ps1

# Audit specific subscriptions with parallelism
.\Invoke-CISAzureAudit.ps1 -Subscriptions "sub-id-1","sub-id-2" -Parallel 5

# Resume an interrupted run
.\Invoke-CISAzureAudit.ps1 -Resume

# Level 1 checks only, custom output path
.\Invoke-CISAzureAudit.ps1 -Level 1 -Output report.html
```

## Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-Subscriptions` | string[] | all | One or more subscription IDs to audit |
| `-Output` | string | `cis_audit_report.html` | HTML report path |
| `-Parallel` | int | 3 | Concurrent subscription workers |
| `-Level` | 1 \| 2 \| both | both | CIS level filter |
| `-Resume` | switch | | Resume from checkpoints |
| `-NoCheckpoint` | switch | | Disable checkpoint save |
| `-SkipTenantChecks` | switch | | Skip tenant-level (Section 5) checks |
| `-NoPermissionCheck` | switch | | Skip preflight permission check |
| `-DebugMode` | switch | | Verbose debug logging |
| `-LogFile` | string | | Write log to file |

## Check coverage

| Section | Area | Controls |
|---|---|---|
| 2 | Azure Databricks | 5 |
| 5 | Identity Services | 10 |
| 6 | Logging & Monitoring | 7 |
| 7 | Networking | 13 |
| 8 | Security Services | 14 |
| 9 | Storage | 23 |
| | **Total** | **72** |

## Project structure

```
Invoke-CISAzureAudit.ps1     Main entry point / orchestrator
Private/
  AzureClient.ps1             az CLI subprocess wrapper
  CheckHelpers.ps1            Prefetch data lookups, error formatting
  Checkpoint.ps1              Save/resume audit state
  Config.ps1                  Timeouts, constants, PASS/FAIL labels
  Helpers.ps1                 Logging, utilities
  History.ps1                 Run history tracking
  Identity.ps1                Subscription enumeration, permission checks
  Models.ps1                  New-CISResult / New-ErrorResult / New-InfoResult
  Report.ps1                  HTML report generation
Checks/
  Section2.ps1                Databricks checks
  Section5.ps1                Identity & access checks
  Section6.ps1                Logging & monitoring checks
  Section7.ps1                Networking checks
  Section8.ps1                Security services checks (Defender, Key Vault)
  Section9.ps1                Storage checks
Tests/
  Checks.Tests.ps1            Pester unit tests (174 tests)
  Run-Tests.ps1               Test runner
```

## Running tests

```powershell
# Requires Pester 5.0+
Install-Module Pester -Force -Scope CurrentUser

# Run all tests
.\Tests\Run-Tests.ps1

# Run a specific check
.\Tests\Run-Tests.ps1 -Test "5_27"

# With code coverage
.\Tests\Run-Tests.ps1 -Coverage
```

## License

[MIT](LICENSE)
