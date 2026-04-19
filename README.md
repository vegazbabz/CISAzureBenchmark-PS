# CIS Microsoft Azure Foundations Benchmark v5.0.0 — Audit Tool (PowerShell)

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![CIS Benchmark](https://img.shields.io/badge/CIS%20Benchmark-v5.0.0-orange.svg)](https://www.cisecurity.org/benchmark/azure)
[![PowerShell](https://img.shields.io/badge/PowerShell-7.0%2B-blue.svg)](https://learn.microsoft.com/en-us/powershell/)
[![CI](https://github.com/vegazbabz/CISAzureBenchmark-PS/actions/workflows/ci.yml/badge.svg)](https://github.com/vegazbabz/CISAzureBenchmark-PS/actions/workflows/ci.yml)

> **[📊 View sample report](https://htmlpreview.github.io/?https://raw.githubusercontent.com/vegazbabz/CISAzureBenchmark-PS/main/docs/sample_report.html)** — synthetic data, no real tenant information.

![Sample report dashboard](docs/sample_report_dashboard.png)

**Version:** 1.0.0
**Benchmark:** [CIS Microsoft Azure Foundations Benchmark v5.0.0](https://www.cisecurity.org/benchmark/azure) (September 2025)
**Coverage:** 98 automated controls across 7 sections · 3 manual controls noted in output

---

## Overview

A PowerShell tool that audits an Azure tenant against the **[CIS Microsoft Azure Foundations Benchmark v5.0.0](https://www.cisecurity.org/benchmark/azure)** — the industry-standard hardening guide for Azure environments, published by the [Center for Internet Security (CIS)](https://www.cisecurity.org/).

All audit checks use the Az PowerShell module — no Azure CLI required.
The optional permission preflight uses `Get-AzRoleAssignment` in parallel runspaces to verify
the runner account holds the required roles before the audit begins.
Skip it with `-NoPermissionCheck` if you already know your permissions are correct.
Install the required Az modules once, then run `Connect-AzAccount` to authenticate.

Results are saved as checkpoints after each subscription completes, so a failed or interrupted run
can be resumed without re-running completed work. Output is a self-contained HTML report with
filtering, compliance scoring, charts, and per-finding remediation guidance.

---

## Requirements

### Runtime

| Requirement | Details |
| --- | --- |
| PowerShell | [7.0 or higher](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell) |
| Az.Accounts | `Install-Module Az.Accounts` — authentication, context, REST calls |
| Az.ResourceGraph | `Install-Module Az.ResourceGraph` — resource prefetch queries |
| Az.Monitor | `Install-Module Az.Monitor` — log profiles, diagnostic settings, activity log alerts |
| Az.Network | `Install-Module Az.Network` — network watcher flow logs |
| Az.Storage | `Install-Module Az.Storage` — storage account enumeration |
| Az.KeyVault | `Install-Module Az.KeyVault` — key rotation policies |
| Az.Resources | `Install-Module Az.Resources` — role definitions |
| Azure login | `Connect-AzAccount` completed before running |

> **Install Az modules all at once:**
> ```powershell
> Install-Module Az.Accounts, Az.ResourceGraph, Az.Monitor, Az.Network, Az.Storage, Az.KeyVault, Az.Resources, Az.Security -Scope CurrentUser
> ```

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
# 1. Install required Az PowerShell modules (one-time)
Install-Module Az.Accounts, Az.ResourceGraph, Az.Monitor, Az.Network, Az.Storage, Az.KeyVault, Az.Resources, Az.Security -Scope CurrentUser

# 2. Log in to Azure
Connect-AzAccount

# 3. Run the audit (audits all enabled subscriptions)
.\Invoke-CISAzureAudit.ps1
```

The report opens automatically in your browser when the audit finishes. The script will
automatically enumerate all enabled subscriptions, run all checks, and save the report.

---

## Getting Started (step-by-step)

New to PowerShell or Azure? Follow these steps to get the tool running on your machine.

### Step 1 — Install PowerShell 7+

1. Go to [https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell) and follow the instructions for your OS.
2. Verify the installation:

   ```powershell
   pwsh --version
   ```

### Step 2 — Install the required Az PowerShell modules

Run this once in a PowerShell 7 terminal:

```powershell
Install-Module Az.Accounts, Az.ResourceGraph, Az.Monitor, Az.Network, Az.Storage, Az.KeyVault, Az.Resources, Az.Security -Scope CurrentUser
```

If prompted to install from an untrusted repository, type `Y` and press Enter.

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
Connect-AzAccount
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
  AzureClient.ps1             PS-based API client: Resource Graph (Search-AzGraph)
                              and ARM REST (Invoke-AzRestMethod)
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
  Section3.ps1                Compute checks (1 manual control)
  Section5.ps1                Identity & access checks (11 controls)
  Section6.ps1                Logging & monitoring checks (17 controls)
  Section7.ps1                Networking checks (13 controls)
  Section8.ps1                Security services checks (30 controls)
  Section9.ps1                Storage checks (24 controls — 101 total)
Tests/
  Checks.Tests.ps1            Pester unit tests (226 tests)
  Run-Tests.ps1               Test runner
scripts/
  New-SampleReport.ps1        Generate sample report with synthetic data
docs/
  sample_report.html          Pre-generated sample report
suppressions.json.example   Suppression template with annotated examples
```

---

## Usage

```text
.\Invoke-CISAzureAudit.ps1 [options]
```

### All parameters

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `-Subscriptions` | string[] | all | One or more subscription names or IDs to audit |
| `-Output` | string | `cis_audit_report.html` | HTML report path |
| `-Parallel` | int | 3 | Concurrent subscription workers |
| `-Level` | 1 \| 2 \| both | both | CIS level filter |
| `-Fresh` | switch | | Clear all checkpoints and start a full re-audit |
| `-ReportOnly` | switch | | Regenerate report from existing checkpoints — no API calls |
| `-NoCheckpoint` | switch | | Disable checkpoint save |
| `-SkipTenantChecks` | switch | | Skip tenant-level checks (Section 3 and 5) |
| `-NoPermissionCheck` | switch | | Skip preflight permission check |
| `-NoOpen` | switch | | Do not auto-open the report in the browser |
| `-ExitCode` | switch | | Exit with code 2 when FAIL or ERROR results are found (for CI/CD) |
| `-SuppressionsFile` | string | `suppressions.json` | Path to the suppressions file (see *Suppressing Findings*) |
| `-DebugMode` | switch | | Verbose debug logging |
| `-LogFile` | string | | Write log to file |

### Configuration file

Create a `cis_audit.json` file next to the script to set persistent defaults. CLI arguments always
override config file values. Set the `CIS_AUDIT_CONFIG` environment variable to use a custom path.

See [`cis_audit.json.example`](cis_audit.json.example) for all available settings.

```json
{
    "audit": {
        "parallel": 3,
        "level": "both",
        "exit_code": true,
        "no_open": true
    },
    "timeouts": {
        "default": 60,
        "storage_list": 90
    }
}
```

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

# Show what findings are currently suppressed
.\Invoke-CISAzureAudit.ps1 -ReportOnly  # suppressions applied during report generation
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

#### 2. Az PowerShell module calls per subscription

For live service configurations and data Resource Graph cannot expose:

- `Get-AzSecurityPricing` — Defender plan statuses (8.1.x)
- `Get-AzActivityLogAlert` — all 11 alert checks (6.1.2.x)
- `Get-AzDiagnosticSetting` — Key Vault and App Service diagnostic logging (6.1.1.4, 6.1.1.6)
- `Get-AzLogProfile` — activity log retention via log profile (6.1.1.3)
- `Get-AzNetworkWatcherFlowLog` — flow log retention (7.5, 7.8)
- `Get-AzKeyVaultKey` / `Get-AzKeyVaultSecret` / `Get-AzKeyVaultCertificate` — expiry dates (8.3.x)
- `Get-AzKeyVaultKeyRotationPolicy` — auto rotation configuration (8.3.9)
- `Get-AzStorageBlobServiceProperty` — soft delete, versioning, logging (9.2.x)
- `Get-AzStorageFileServiceProperty` — file soft delete and SMB settings (9.1.x)
- `Get-AzStorageAccount` — storage security properties (9.3.x)
- `Get-AzResourceLock` — CanNotDelete / ReadOnly locks (9.3.9, 9.3.10)
- `Get-AzRoleDefinition` — custom admin role detection (5.23)

#### 3. ARM / Microsoft Graph REST via `Invoke-AzRestMethod`

For tenant-level identity checks and APIs not exposed by Az module cmdlets:

- `graph.microsoft.com/v1.0/policies/authorizationPolicy` — covers 5.4, 5.14, 5.15, 5.16
- `management.azure.com/.../diagnosticSettings` — subscription-level activity log routing (6.1.1.x)
- ARM REST for security contacts (8.1.12–8.1.15), WDATP integration (8.1.3.3), and attack path notifications (8.1.15)

#### 4. Permission preflight

Before the audit begins, `Get-AzRoleAssignment` is called in parallel runspaces (up to 8 at once)
to verify the runner account holds the required roles on every subscription. No Azure CLI is
required. Use `-NoPermissionCheck` to bypass the preflight entirely.

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

Adaptive concurrency is built-in: if Azure returns throttling responses (HTTP 429), the tool
automatically reduces the number of concurrent workers. After two consecutive batches without
throttling, workers are increased back towards the original value.

---

## HTML Report

The generated report is a self-contained HTML file with no external dependencies.

- **Summary cards** — compliance score (PASS / (PASS + FAIL), excluding ERROR, INFO and MANUAL), plus counts for each status.
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

### Output files

Every run writes three files alongside the HTML report:

| File | Format | Purpose |
| --- | --- | --- |
| `cis_audit_report.html` | HTML | Interactive visual report (auto-opened unless `-NoOpen`) |
| `cis_audit_report.json` | JSON | Machine-readable results for downstream tooling |
| `cis_audit_report.csv` | CSV | Spreadsheet-friendly format for compliance teams |

Use `-Output report.html` to change the base path — `.json` and `.csv` extensions are derived automatically.

---

## Suppressing Findings (Accepted Risks)

Create a `suppressions.json` file in the project root to mark specific findings as accepted risks.
Suppressed findings are reclassified as **SUPPRESSED** in the report and excluded from the FAIL/ERROR counts.

A template with annotated examples is provided in [`suppressions.json.example`](suppressions.json.example)
(includes examples for WAF-fronted architectures and B2B guest admin accounts).
Copy it to `suppressions.json` and remove any entries that don't apply.

### suppressions.json format

```json
[
  {
    "control_id": "9.5",
    "justification": "Legacy storage account — migration planned for Q3",
    "expires": "2025-09-30",
    "resource": "/subscriptions/.../storageAccounts/legacy01",
    "subscription": "Production"
  }
]
```

### Suppression rules

- `control_id` (required) — CIS control ID to suppress (e.g. `"9.5"`).
- `justification` (required) — human-readable reason for the suppression.
- `expires` (required) — expiry date in `YYYY-MM-DD` format. Maximum 365 days from today.
- `resource` (optional) — resource ID to match. Omit to suppress all resources for this control.
- `subscription` (optional) — subscription name or ID. Omit to suppress across all subscriptions.

Expired entries are silently ignored. The summary banner shows active suppression count.

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

> **2.1.1** (Databricks in customer-managed VNet) — pending implementation.

### Section 3 — Compute Services (1 manual)

| Control | Title | Level | Notes |
| --- | --- | --- | --- |
| 3.1.1 | Only MFA-enabled identities can access privileged VMs | L2 | **Manual** — requires correlating role assignments with MFA status |

> **Sections 3 and 4** of the CIS Azure Foundations Benchmark v5.0.0 are largely reference
> sections — most Compute and Database controls have been relocated to the
> *CIS Microsoft Azure Compute Services Benchmark* and *CIS Microsoft Azure Database
> Services Benchmark* respectively. Only 3.1.1 (Virtual Machines) remains in the
> Foundations Benchmark as an auditable control.

### Section 5 — Identity Services (9 automated · 2 manual)

| Control | Title | Level | Notes |
| --- | --- | --- | --- |
| 5.1.1 | Security defaults enabled | L1 | |
| 5.1.2 | MFA enabled for all users | L1 | |
| 5.1.3 | Allow users to remember MFA on trusted devices disabled | L1 | **Manual** |
| 5.28 | Privileged users protected by phishing-resistant MFA | L1 | **Manual** |
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
| 6.1.1.3 | Activity log retention >= 365 days | L1 |

> **6.1.1.3 storage destinations:** When subscription diagnostic settings route activity logs to a
> Storage Account, the check now inspects the retention policy on the Administrative log category.
> A setting with `retentionPolicy.enabled = false` (indefinite) passes; `enabled = true` with
> `days < 365` fails. Log Analytics workspace and Event Hub destinations always pass this check
> (retention is configured on the destination resource itself).
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
| 7.6 | Network Watcher enabled for all regions in use | L1 |
| 7.8 | VNet flow log retention >= 90 days | L2 |
| 7.10 | WAF enabled on Azure Application Gateway | L2 |
| 7.11 | Subnets associated with NSGs | L1 |
| 7.12 | App Gateway SSL policy min TLS 1.2+ | L1 |
| 7.13 | HTTP2 enabled on Application Gateway | L1 |
| 7.14 | WAF request body inspection enabled | L2 |
| 7.15 | WAF bot protection enabled | L2 |

### Section 8 — Security Services (30 automated)

| Control | Title | Level |
| --- | --- | --- |
| 8.1.1.1 | Microsoft Defender CSPM | L2 |
| 8.1.2.1 | Microsoft Defender for APIs | L2 |
| 8.1.3.1 | Microsoft Defender for Servers | L2 |
| 8.1.3.3 | Endpoint protection (WDATP) component | L1 |
| 8.1.4.1 | Microsoft Defender for Containers | L2 |
| 8.1.5.1 | Microsoft Defender for Storage | L2 |
| 8.1.6.1 | Microsoft Defender for App Services | L2 |
| 8.1.7.1 | Microsoft Defender for Azure Cosmos DB | L2 |
| 8.1.7.2 | Microsoft Defender for Open-Source Relational DBs | L2 |
| 8.1.7.3 | Microsoft Defender for SQL (Managed Instance) | L2 |
| 8.1.7.4 | Microsoft Defender for SQL Servers on Machines | L2 |
| 8.1.8.1 | Microsoft Defender for Key Vault | L2 |
| 8.1.9.1 | Microsoft Defender for Resource Manager | L2 |
| 8.1.10 | Defender configured to check VM OS updates | L1 |
| 8.1.12 | Security alerts notify subscription Owners | L1 |
| 8.1.13 | Additional email addresses for security contact | L1 |
| 8.1.14 | Alert severity notifications configured | L1 |
| 8.1.15 | Attack path notifications configured | L1 |
| 8.3.1 | Key expiration set — RBAC Key Vaults | L1 |
| 8.3.2 | Key expiration set — non-RBAC Key Vaults | L1 |
| 8.3.3 | Secret expiration set — RBAC Key Vaults | L1 |
| 8.3.4 | Secret expiration set — non-RBAC Key Vaults | L1 |
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
| 9.2.4 | Storage logging enabled for Blob Service read requests | L2 |
| 9.2.5 | Storage logging enabled for Blob Service write requests | L2 |
| 9.2.6 | Storage logging enabled for Blob Service delete requests | L2 |
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

The test suite uses **Pester 5** — all tests mock Az module calls so no real Azure connection is needed.

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

#### Using this tool in your own CI/CD pipeline

Add `-ExitCode` to make the tool exit with code 2 when any FAIL or ERROR results are found.
This lets Azure DevOps, GitHub Actions, and similar systems fail the build on compliance regressions:

```yaml
# GitHub Actions example
- name: Azure foundations audit
  shell: pwsh
  run: |
    .\Invoke-CISAzureAudit.ps1 `
      -Subscriptions "Production" `
      -NoOpen `
      -ExitCode
  # Step fails (exit code 2) if any controls are non-compliant
```

```yaml
# Azure DevOps example
- task: PowerShell@2
  displayName: 'Azure Foundations audit'
  inputs:
    targetType: inline
    pwsh: true
    script: |
      .\Invoke-CISAzureAudit.ps1 -Subscriptions $(SUB_NAME) -NoOpen -ExitCode
  # Marks the pipeline stage as failed when FAIL/ERROR results are found
```

Exit code summary:

| Code | Meaning |
| --- | --- |
| `0` | Audit completed — all controls passed (or all failures are suppressed) |
| `1` | Tool setup error — az CLI missing, not logged in, or authentication failed |
| `2` | Compliance failure — one or more FAIL or ERROR results detected (only with `-ExitCode`) |

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

**Graph API for identity checks** — controls 5.4, 5.14, 5.15, and 5.16 call the Microsoft Graph
API via `Invoke-AzRestMethod`. If the required Graph permissions have not been consented for the
identity running the audit, these will return ERROR. Test with:

```powershell
Invoke-AzRestMethod -Method GET -Uri "https://graph.microsoft.com/v1.0/policies/authorizationPolicy"
```

**Conditional Access policies (5.2.x)** — marked Manual in the benchmark and not checked by this
tool. They require review in the Entra ID portal.

---

## Troubleshooting

**Identity checks return ERROR (AccessDenied)**
Your account needs Global Reader in Entra ID. To verify Graph API access:

```powershell
Invoke-AzRestMethod -Method GET -Uri "https://graph.microsoft.com/v1.0/policies/authorizationPolicy"
```

If this returns a 403, ask your Entra ID admin to grant Global Reader or consent to the required
Graph API permissions for the service principal used for auditing.

**Key Vault checks return ERROR (audit incomplete)**
The runner account needs Key Vault data plane access. For RBAC-enabled vaults assign the
**Key Vault Reader** role; for access-policy vaults, add the account to the vault's access policy.
The ERROR message in the report states exactly what is missing.

**Subscription not found**
Values passed to `-Subscriptions` must match an existing subscription name or ID exactly.
Run `Get-AzSubscription | Select-Object Name, Id` to see the available subscriptions.

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

**Version:** 1.0.0
**Benchmark:** CIS Microsoft Azure Foundations Benchmark v5.0.0 (September 2025)
**Coverage:** 98 automated controls across 7 sections · 3 manual controls noted in output
