# CIS Microsoft Azure Foundations Benchmark v5.0.0 — Audit Tool (PowerShell)

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![CIS Benchmark](https://img.shields.io/badge/CIS%20Benchmark-v5.0.0-orange.svg)](https://www.cisecurity.org/benchmark/azure)
[![PowerShell](https://img.shields.io/badge/PowerShell-7.0%2B-blue.svg)](https://learn.microsoft.com/en-us/powershell/)
[![CI](https://github.com/vegazbabz/CISAzureBenchmark-PS/actions/workflows/ci.yml/badge.svg)](https://github.com/vegazbabz/CISAzureBenchmark-PS/actions/workflows/ci.yml)

> **[📊 View sample report](https://htmlpreview.github.io/?https://raw.githubusercontent.com/vegazbabz/CISAzureBenchmark-PS/main/docs/sample_report.html)** — synthetic data, no real tenant information.

![Sample report dashboard](docs/sample_report_dashboard.png)

**Version:** 1.0.1
**Benchmark:** [CIS Microsoft Azure Foundations Benchmark v5.0.0](https://www.cisecurity.org/benchmark/azure) (September 2025)
**Coverage:** 82 automated controls across 6 sections · 1 manual control noted in output

---

## Overview

A PowerShell tool that audits an Azure tenant against the **[CIS Microsoft Azure Foundations Benchmark v5.0.0](https://www.cisecurity.org/benchmark/azure)** — the industry-standard hardening guide for Azure environments, published by the [Center for Internet Security (CIS)](https://www.cisecurity.org/).

Zero external module dependencies — only PowerShell 7+ and the Azure CLI.

Results are saved as checkpoints after each subscription completes, so a failed or interrupted run
can be resumed without re-running completed work. Output is a self-contained HTML report with
filtering, compliance scoring, charts, and per-finding remediation guidance.

---

## Requirements

### Runtime

| Requirement | Details |
| --- | --- |
| PowerShell | [7.0 or higher](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell) |
| Azure CLI | Any recent version — <https://aka.ms/install-azure-cli> |
| Azure login | `az login` completed before running |

### Azure permissions

| Scope | Role | Purpose |
| --- | --- | --- |
| Each subscription | Reader | Enumerate all resources |
| Each subscription | Security Reader | Defender plans, security contacts |
| Microsoft Entra ID (tenant) | Global Reader | Identity checks (5.x) |
| Key Vaults (optional) | Key Vault Reader | List keys, secrets, certificates for 8.3.x checks |

> **Key Vault data plane:** Controls 8.3.1–8.3.4, 8.3.9, and 8.3.11 enumerate individual keys,
> secrets, and certificates. This requires data plane access in addition to Reader.
> For RBAC-enabled vaults assign **Key Vault Reader**; for access-policy vaults, add the
> runner account to the vault's access policy. Without this, affected checks return ERROR with a
> clear explanation and remediation hint in the report — compliance is unknown, not assumed clean.

---

## Quick Start

```powershell
# 1. Login to Azure
az login

# 2. Run the audit (audits all enabled subscriptions)
.\Invoke-CISAzureAudit.ps1
```

The report opens automatically in your browser when the audit finishes. The script will
automatically enumerate all enabled subscriptions, run all checks, and save the report.

---

## Getting Started (step-by-step)

New to PowerShell or the Azure CLI? Follow these steps to get the tool running on your machine.

### Step 1 — Install PowerShell 7+

1. Go to [https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell) and follow the instructions for your OS.
2. Verify the installation:

   ```powershell
   pwsh --version
   ```

### Step 2 — Install the Azure CLI

1. Follow the official instructions at <https://aka.ms/install-azure-cli> for your OS.
2. Verify:

   ```powershell
   az --version
   ```

### Step 3 — Get the tool

**Option A — Clone with Git** (recommended — makes updating easy):

```powershell
git clone https://github.com/vegazbabz/CISAzureBenchmark-PS.git
cd CISAzureBenchmark-PS
```

**Option B — Download as ZIP** (no Git required):

1. On the [GitHub repository page](https://github.com/vegazbabz/CISAzureBenchmark-PS),
   click the green **Code** button → **Download ZIP**.
2. Extract the ZIP and open a terminal in the extracted folder.

### Step 4 — Log in to Azure

```powershell
az login
```

A browser window will open for you to sign in. The account you use needs at minimum **Reader**
and **Security Reader** on the subscriptions you want to audit.

### Step 5 — Run the audit

```powershell
.\Invoke-CISAzureAudit.ps1
```

The tool will enumerate all your enabled subscriptions, run all checks, and open the HTML report
in your browser automatically when done.

> **Tip:** To audit specific subscriptions, use the `-Subscriptions` parameter:
>
> ```powershell
> .\Invoke-CISAzureAudit.ps1 -Subscriptions "subscription-id-1","subscription-id-2"
> ```

---

## Project Structure

```text
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
  Section2.ps1                Databricks checks (5 controls)
  Section5.ps1                Identity & access checks (10 controls)
  Section6.ps1                Logging & monitoring checks (17 controls)
  Section7.ps1                Networking checks (13 controls)
  Section8.ps1                Security services checks (14 controls)
  Section9.ps1                Storage checks (24 controls — 82 total)
Tests/
  Checks.Tests.ps1            Pester unit tests (178 tests)
  Run-Tests.ps1               Test runner
scripts/
  New-SampleReport.ps1        Generate sample report with synthetic data
docs/
  sample_report.html          Pre-generated sample report
```

---

## Usage

```text
.\Invoke-CISAzureAudit.ps1 [options]
```

### All parameters

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `-Subscriptions` | string[] | all | One or more subscription IDs to audit |
| `-Output` | string | `cis_audit_report.html` | HTML report path |
| `-Parallel` | int | 3 | Concurrent subscription workers |
| `-Level` | 1 \| 2 \| both | both | CIS level filter |
| `-Fresh` | switch | | Clear all checkpoints and start a full re-audit |
| `-ReportOnly` | switch | | Regenerate report from existing checkpoints — no API calls |
| `-NoCheckpoint` | switch | | Disable checkpoint save |
| `-SkipTenantChecks` | switch | | Skip tenant-level (Section 5) checks |
| `-NoPermissionCheck` | switch | | Skip preflight permission check |
| `-NoOpen` | switch | | Do not auto-open the report in the browser |
| `-DebugMode` | switch | | Verbose debug logging |
| `-LogFile` | string | | Write log to file |

### Examples

```powershell
# Audit all subscriptions
.\Invoke-CISAzureAudit.ps1

# Audit specific subscriptions with parallelism
.\Invoke-CISAzureAudit.ps1 -Subscriptions "sub-id-1","sub-id-2" -Parallel 5

# Level 1 checks only, custom output path
.\Invoke-CISAzureAudit.ps1 -Level 1 -Output report.html

# Start completely fresh, ignoring previous checkpoints
.\Invoke-CISAzureAudit.ps1 -Fresh

# Regenerate the HTML report without re-running any checks
.\Invoke-CISAzureAudit.ps1 -ReportOnly

# Trace-level diagnostics written to a log file
.\Invoke-CISAzureAudit.ps1 -DebugMode -LogFile cis_audit.log

# Skip tenant-level identity checks
.\Invoke-CISAzureAudit.ps1 -SkipTenantChecks

# Interrupted run? Just re-run — it resumes automatically
.\Invoke-CISAzureAudit.ps1
```

---

## How It Works

### Data collection — three methods

#### 1. Azure Resource Graph (bulk prefetch — once per audit)

Before any per-subscription work begins, Kusto queries fetch all relevant resources across the
entire tenant in a single round trip:

- Network Security Groups and security rules
- Storage accounts and security properties
- Key Vaults — access configuration and network settings
- Virtual Networks, subnets, and NSG associations
- Application Gateways and WAF settings
- Databricks workspaces
- Bastion Hosts
- Network Watchers and resource locations
- Role assignments (Owner and User Access Administrator)
- WAF policies

#### 2. Azure CLI calls per subscription

For live service configurations and data Resource Graph cannot expose:

- `az security pricing show` — Defender plan statuses (8.1.x)
- `az security contact list` — notification settings (8.1.12–8.1.15)
- `az monitor diagnostic-settings list` — Key Vault and subscription logging
- `az monitor activity-log alert list` — all 11 alert checks (6.1.2.x)
- `az keyvault key/secret list` — expiry dates per key and secret
- `az keyvault key rotation-policy show` — auto rotation configuration
- `az keyvault certificate show` — certificate validity periods
- `az storage account blob-service-properties show` — soft delete, versioning
- `az storage account file-service-properties show` — file soft delete, SMB settings
- `az network watcher flow-log list` — flow log retention (7.5, 7.8)
- `az role definition list` — custom admin roles (5.23)

#### 3. Azure REST API via `az rest`

For tenant-level identity checks not available via the az CLI:

- `graph.microsoft.com/v1.0/policies/authorizationPolicy` — covers 5.4, 5.14, 5.15, 5.16
- ARM REST for WDATP integration settings (8.1.3.3) and attack path notifications (8.1.15)

### Permission preflight

Before the audit begins, the tool checks whether the runner account holds the required roles on
every subscription.

### Checkpoints and resume

After each subscription completes, results are written to `cis_checkpoints/<subscription-id>.json`.
If the script is stopped or crashes mid-run, re-running it will skip completed subscriptions and
continue from where it left off. Use `-Fresh` to discard all checkpoints and start over.

### Parallel execution

Subscriptions run concurrently via PowerShell runspaces. The default is 3 parallel workers
(configurable via `-Parallel`). The Resource Graph prefetch always runs once before the parallel
loop begins.

---

## HTML Report

The generated report is a self-contained HTML file with no external dependencies.

- **Summary cards** — compliance score (PASS / total, excluding INFO and MANUAL), plus counts for each status.
- **Compliance donuts** — three ring charts showing PASS/FAIL/ERROR proportions overall, for Level 1, and for Level 2.
- **Section breakdown** — horizontal stacked bars per CIS section, sorted worst to best.
- **Per-subscription summary** — stacked-bar table showing pass/fail/error counts per subscription; click a row to filter the results table to that subscription.
- **Filterable table** — filter simultaneously by free-text search, subscription, status, and level (L1/L2). Section headers collapse when all their results are filtered out.
- **Per-resource results** — each NSG, storage account, Key Vault, subnet, and Databricks workspace is reported individually, not aggregated to a single pass/fail per control.
- **Remediation hints** — every FAIL result includes the Azure portal navigation path to fix the issue. ERROR results include an actionable explanation of what access is missing.
- **Compliance trend** — after two or more full-tenant audit runs, a collapsible chart appears showing the compliance score over time.
- **Back to top** — fixed button in the bottom-right corner for long reports.

### Status types

| Status | Meaning |
| --- | --- |
| PASS | Control is compliant |
| FAIL | Control is non-compliant — remediation hint provided |
| ERROR | Check could not complete — audit gap (permissions missing, timeout, or API error). Compliance is **unknown**; do not treat as clean. |
| INFO | Not applicable — the resource type doesn't exist or the account type doesn't support the feature |
| MANUAL | Cannot be automated — requires manual verification per the CIS PDF |
| SUPPRESSED | Accepted risk — finding acknowledged with justification |

> **ERROR vs INFO distinction:**
> `ERROR` means *"the control applies, but the audit couldn't evaluate it"* — flag it for follow-up.
> `INFO` means *"the control genuinely doesn't apply here"* — for example, an ADLS Gen2 storage account
> has no blob/file service by design, so the blob checks simply don't apply. There is nothing to fix.

### `-ReportOnly`: regenerate the report without re-auditing

```powershell
.\Invoke-CISAzureAudit.ps1 -ReportOnly
```

Loads all existing checkpoints and regenerates the HTML — no Azure API calls are made.
Useful after upgrading the tool or changing the `-Level` filter.

---

## Controls Covered

### Section 2 — Azure Databricks (5 automated)

| Control | Title | Level |
| --- | --- | --- |
| 2.1.2 | NSGs configured for Databricks subnets | L1 |
| 2.1.7 | Diagnostic logging configured | L1 |
| 2.1.9 | No Public IP enabled | L1 |
| 2.1.10 | Public network access disabled | L1 |
| 2.1.11 | Private endpoints used to access workspaces | L2 |

### Section 5 — Identity Services (9 automated · 1 manual)

| Control | Title | Level | Notes |
| --- | --- | --- | --- |
| 5.1.1 | Security defaults enabled | L1 | |
| 5.1.2 | MFA enabled for all users | L1 | |
| 5.1.3 | Allow users to remember MFA on trusted devices disabled | L1 | **Manual** |
| 5.3.3 | User Access Administrator role restricted | L1 | |
| 5.4 | Restrict non-admin users from creating tenants | L1 | |
| 5.14 | Users cannot register applications | L1 | |
| 5.15 | Guest access restricted to own directory objects | L1 | |
| 5.16 | Guest invite restrictions set to admins or no one | L2 | |
| 5.23 | No custom subscription administrator roles | L1 | |
| 5.27 | Between 2 and 3 subscription owners | L1 | |

### Section 6 — Logging & Monitoring (17 automated)

| Control | Title | Level |
| --- | --- | --- |
| 6.1.1.1 | Diagnostic Setting exists for Subscription Activity Logs | L1 |
| 6.1.1.2 | Diagnostic Setting captures required categories | L1 |
| 6.1.1.3 | Ensure App Service logs are captured | L1 |
| 6.1.1.4 | Key Vault diagnostic logging enabled | L1 |
| 6.1.1.6 | Azure AppService HTTP logs enabled | L2 |
| 6.1.2.1 | Activity Log Alert: Create Policy Assignment | L1 |
| 6.1.2.2 | Activity Log Alert: Delete Policy Assignment | L1 |
| 6.1.2.3 | Activity Log Alert: Create or Update NSG | L1 |
| 6.1.2.4 | Activity Log Alert: Delete NSG | L1 |
| 6.1.2.5 | Activity Log Alert: Create or Update Security Solution | L1 |
| 6.1.2.6 | Activity Log Alert: Delete Security Solution | L1 |
| 6.1.2.7 | Activity Log Alert: Create or Update SQL Firewall Rule | L1 |
| 6.1.2.8 | Activity Log Alert: Delete SQL Firewall Rule | L1 |
| 6.1.2.9 | Activity Log Alert: Create or Update Public IP | L1 |
| 6.1.2.10 | Activity Log Alert: Delete Public IP | L1 |
| 6.1.2.11 | Activity Log Alert: Service Health | L1 |
| 6.1.3.1 | Application Insights configured | L2 |

### Section 7 — Networking Services (13 automated)

| Control | Title | Level |
| --- | --- | --- |
| 7.1 | RDP (3389) not open to internet | L1 |
| 7.2 | SSH (22) not open to internet | L1 |
| 7.3 | UDP access from internet restricted | L1 |
| 7.4 | HTTP/HTTPS (80/443) from internet evaluated and restricted | L1 |
| 7.5 | NSG flow log retention >= 90 days | L2 |
| 7.6 | Network Watcher enabled for all regions in use | L2 |
| 7.8 | VNet flow log retention >= 90 days | L2 |
| 7.10 | WAF enabled on Azure Application Gateway | L2 |
| 7.11 | Subnets associated with NSGs | L1 |
| 7.12 | App Gateway SSL policy min TLS 1.2+ | L1 |
| 7.13 | HTTP2 enabled on Application Gateway | L1 |
| 7.14 | WAF request body inspection enabled | L2 |
| 7.15 | WAF bot protection enabled | L2 |

### Section 8 — Security Services (14 automated)

| Control | Title | Level |
| --- | --- | --- |
| 8.1.3.3 | Endpoint protection (WDATP) component | L2 |
| 8.1.10 | Defender configured to check VM OS updates | L1 |
| 8.1.12 | Security alerts notify subscription Owners | L1 |
| 8.1.13 | Additional email addresses for security contact | L1 |
| 8.1.14 | Alert severity notifications configured | L1 |
| 8.1.15 | Attack path notifications configured | L1 |
| 8.3.5 | Key Vault purge protection enabled | L1 |
| 8.3.6 | Key Vault RBAC authorization enabled | L2 |
| 8.3.7 | Key Vault public network access disabled | L1 |
| 8.3.8 | Private endpoints used to access Key Vault | L2 |
| 8.3.9 | Automatic key rotation enabled | L2 |
| 8.3.11 | Certificate validity period <= 12 months | L1 |
| 8.4.1 | Azure Bastion Host exists | L2 |
| 8.5 | DDoS Network Protection enabled on VNets | L2 |

### Section 9 — Storage Services (24 automated)

| Control | Title | Level |
| --- | --- | --- |
| 9.1.1 | Azure Files soft delete enabled | L1 |
| 9.1.2 | SMB protocol version >= 3.1.1 | L1 |
| 9.1.3 | SMB channel encryption AES-256-GCM or higher | L1 |
| 9.2.1 | Blob soft delete enabled | L1 |
| 9.2.2 | Container soft delete enabled | L1 |
| 9.2.3 | Blob versioning enabled | L2 |
| 9.2.4 | Immutable blob storage configured | L2 |
| 9.2.5 | Blob change feed enabled | L2 |
| 9.2.6 | Point-in-time restore for blob data enabled | L2 |
| 9.3.1.1 | Key rotation reminders enabled | L1 |
| 9.3.1.2 | Access keys regenerated within 90 days | L1 |
| 9.3.1.3 | Storage account key access disabled | L1 |
| 9.3.2.1 | Private endpoints used to access storage accounts | L2 |
| 9.3.2.2 | Public network access disabled | L1 |
| 9.3.2.3 | Default network access rule is Deny | L1 |
| 9.3.3.1 | Default to Microsoft Entra authorization in Azure portal | L1 |
| 9.3.4 | Secure transfer (HTTPS) required | L1 |
| 9.3.5 | Allow Azure trusted services to access storage | L2 |
| 9.3.6 | Minimum TLS version 1.2 | L1 |
| 9.3.7 | Cross-tenant replication disabled | L1 |
| 9.3.8 | Blob anonymous access disabled | L1 |
| 9.3.9 | Storage account has CanNotDelete resource lock | L1 |
| 9.3.10 | Storage account has ReadOnly resource lock | L2 |
| 9.3.11 | Redundancy set to geo-redundant (GRS) | L2 |

---

## Testing

The test suite uses **Pester 5** — all tests mock Azure CLI calls so no real Azure connection is needed.

### Run everything

```powershell
# Requires Pester 5.0+
Install-Module Pester -Force -Scope CurrentUser

# Run all tests
.\Tests\Run-Tests.ps1
```

### Run a single check

```powershell
.\Tests\Run-Tests.ps1 -Test "5_27"
```

### With code coverage

```powershell
.\Tests\Run-Tests.ps1 -Coverage
```

### Continuous Integration

A GitHub Actions pipeline runs on every push and pull request:

- Pester tests (Ubuntu + Windows)
- PSScriptAnalyzer linting

The workflow file lives at `.github/workflows/ci.yml`.

---

## Checkpoint Files

```text
cis_checkpoints/
  |- xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx.json   <- completed
  |- yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy.json   <- completed
  `- zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz.json  <- failed (retried on next run)
```

Each file contains the full result set for that subscription, a UTC timestamp, and a completion
status. Delete the `cis_checkpoints/` folder or use `-Fresh` to discard all checkpoints.
Use `-ReportOnly` to regenerate the HTML report from existing checkpoints without running any checks.

---

## Known Limitations

**Read-only** — the script audits only. It makes no changes to your environment.

**Point-in-time** — results reflect the state at the moment the script ran.

**Key Vault data plane access** — listing keys, secrets, and certificates requires data plane
permissions in addition to subscription Reader. Assign **Key Vault Reader** (RBAC vaults) or add
the runner account to the vault's access policy (non-RBAC vaults). Without this, affected checks
return ERROR with an explanatory message. The report clearly distinguishes this from a clean
result — compliance is unknown, not assumed clean.

**Graph API for identity checks** — controls 5.4, 5.14, 5.15, and 5.16 call the Graph API via
`az rest`. If the required Graph permissions have not been consented for the Azure CLI app, these
will return ERROR. Test with:

```powershell
az rest --method get --url "https://graph.microsoft.com/v1.0/policies/authorizationPolicy"
```

**Conditional Access policies (5.2.x)** — marked Manual in the benchmark and not checked by this
tool. They require review in the Entra ID portal.

---

## Troubleshooting

**`az` not found**
Ensure the Azure CLI is installed and on your PATH, then restart your terminal.

**Identity checks return ERROR (AccessDenied)**
Your account needs Global Reader in Entra ID. Test the Graph call directly:

```powershell
az rest --method get --url "https://graph.microsoft.com/v1.0/policies/authorizationPolicy"
```

If this fails, ask your Entra ID admin to grant Global Reader or consent to the required Graph API
permissions for the Azure CLI app (app ID: `04b07795-8ddb-461a-bbee-02f9e1bf7b46`).

**Key Vault checks return ERROR (audit incomplete)**
The runner account needs Key Vault data plane access. For RBAC-enabled vaults assign the
**Key Vault Reader** role; for access-policy vaults, add the account to the vault's access policy.
The ERROR message in the report states exactly what is missing.

**Subscription not found**
Subscription IDs must be exact GUIDs. Run `az account list --output table` to see the available
subscriptions.

**Interrupted run**
Re-run the same command to resume from where it stopped, or add `-Fresh` to start over.

---

## Disclaimer

This tool is provided **as-is, with no warranty of any kind**. The maintainers and contributors
offer no SLA, make no guarantee of accuracy or completeness, and accept no legal responsibility
or liability for the use of this tool or any decisions made based on its output. Use is entirely
at your own risk. See [LICENSE](LICENSE) for the full MIT disclaimer.

## Attribution

This is an independent community implementation referencing the publicly available
**[CIS Microsoft Azure Foundations Benchmark v5.0.0](https://www.cisecurity.org/benchmark/azure)**.
CIS Benchmarks are the property of the Center for Internet Security (<https://www.cisecurity.org>),
used under [CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/).
This tool is not affiliated with, endorsed by, or approved by CIS.

## License

[MIT](LICENSE)

**Version:** 1.0.1
**Benchmark:** CIS Microsoft Azure Foundations Benchmark v5.0.0 (September 2025)
**Coverage:** 82 automated controls across 6 sections · 1 manual control noted in output
