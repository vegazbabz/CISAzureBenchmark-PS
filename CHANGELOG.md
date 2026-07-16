# Changelog

All notable changes to CISAzureBenchmark-PS are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) · Versioning: [SemVer](https://semver.org/).
For compliance users the key question is *which controls changed* — every entry calls that out explicitly.

## [Unreleased]

### Changed

- README: installation instructions now lead with `Install-Module CISAzureFoundationsBenchmark`
  from the PowerShell Gallery (Quick Start and Getting Started); cloning remains documented as
  an alternative. Documentation only — no control results change.

## [2.2.0] — 2026-07-16

### Changed

- **Module renamed to `CISAzureFoundationsBenchmark`** (was `CISAzureBenchmark`): the
  PowerShell Gallery package ID `CISAzureBenchmark` is owned by an unrelated project, so this
  module publishes to the Gallery as `CISAzureFoundationsBenchmark`. The manifest/loader files,
  the summary object's type name (`CISAzureFoundationsBenchmark.AuditSummary`), and the SARIF
  tool driver name follow the new name. The exported command is still `Invoke-CISAzureAudit`,
  the repository name is unchanged, and no control results or scores change. If you imported
  the module by path, update the manifest filename; the root script shim is unaffected.

## [2.1.0] — 2026-07-16

Feature release: run-to-run diff, SARIF export, three newly automated identity controls
(5.5, 5.6, 5.3.5), Key Vault preflight probing, CI hardening — plus internal restructuring
with no behavior change (live-validated E2E against a real tenant). Scores remain
comparable with 2.0.0.

### Added

- **Coverage gate in CI**: `Run-Tests.ps1` gained `-MinCoverage <percent>` (implies
  `-Coverage`) — prints the coverage percentage, publishes it to the GitHub Actions job
  summary, and exits non-zero below the floor. CI's Ubuntu test leg now enforces a 75%
  floor (baseline 82.7% at introduction). No control results change.
- **Scheduled-audit recipe with OIDC** (docs): the README's CI/CD section now includes a
  complete GitHub Actions example for recurring audits — weekly cron, `azure/login` with
  federated credentials (no stored secrets), `-ExitCode` to fail the job on findings, and
  artifact upload of all report files — plus the one-time Azure setup commands (app
  registration, federated credential, role assignments). No code changes; no control
  results change.
- **Run-to-run diff report** (`-CompareWith`): pass a previous run's `<report>.json` (or
  `auto` to pick the most recent report JSON in the output directory) and the HTML report
  gains a "Changes vs previous run" section — regressions (was passing, now FAIL/ERROR),
  improvements, new results and removed results, keyed by control + subscription + resource.
  The same breakdown is written to `<report>.diff.json` for machine consumption. No control
  results or scores change; without `-CompareWith` the report is unchanged.
- **SARIF 2.1.0 export**: every run now writes `<report>.sarif` alongside the JSON/CSV
  outputs, ready for `github/codeql-action/upload-sarif` (GitHub code scanning) and
  Defender for DevOps. FAIL maps to `error`, ERROR to `warning` (an unauditable control is
  a finding, mirroring the score), SUPPRESSED results carry a SARIF suppression object;
  alerts are fingerprinted by control + subscription + resource so they track across runs.
  Output validates against the official SARIF 2.1.0 schema. README documents the upload
  workflow.
- **Key Vault data-plane preflight**: the permission preflight now probes each vault (lists one
  key) and prints one consolidated warning naming every inaccessible vault with the grant
  command — instead of the gap only surfacing as repeated per-control ERRORs (8.3.x) at the end
  of the run. Result statuses and the score are unchanged.
- **Control 5.3.5 is now automated** (previously MANUAL): disabled user accounts are fetched
  once from Microsoft Graph (`accountEnabled eq false`) and cross-referenced against each
  subscription's role assignments — FAIL names the offending accounts and scopes, ERROR (with
  permission guidance) when Graph users cannot be read. Section 5 is now 8 automated · 7 manual
  (93 automated / 34 manual overall).
- **Controls 5.5 and 5.6 are now automated** (previously MANUAL): 5.5 checks each
  subscription for a custom role granting `Microsoft.Authorization/locks` actions
  (PASS/FAIL/ERROR); 5.6 reads the tenant subscription-transfer policy via ARM and fails
  unless both leaving and entering are set to 'Permit no one'. Section 5 is now
  7 automated · 8 manual (92 automated / 35 manual overall).
- **Control 5.3.2** (guest users reviewed) now pulls the guest inventory via Microsoft
  Graph: PASS when the tenant has no guests, MANUAL with guest count + sample UPNs when
  guests exist, ERROR (with permission guidance) when Graph users cannot be read.
- **PowerShell module packaging** (#59): `CISAzureBenchmark.psd1`/`.psm1` with an exported
  `Invoke-CISAzureAudit` that returns a typed summary object (`ExitCode`, `Counts`, `Score`,
  `Results`, `ReportPath`). The root `Invoke-CISAzureAudit.ps1` script is now a thin
  compatibility shim — existing command lines and CI pipelines are unaffected.
- **PowerShell Gallery release pipeline**: tag pushes publish the staged module to the Gallery
  when the `PSGALLERY_API_KEY` repo secret is configured (`scripts/Build-ModulePackage.ps1`
  stages runtime files only). Skips with a notice when the secret is absent.
- CI: module manifest validation step (Test-ModuleManifest + import smoke test).
- `PSScriptAnalyzerSettings.psd1` — shared rule exclusions, auto-discovered by the VS Code
  PowerShell extension and referenced by CI, so editor warnings match what CI enforces.

### Changed

- **Control 5.4** (no custom subscription administrator roles) now reads role definitions via
  `Permissions[n].Actions` with a fallback to the flattened `Actions` property (#58) — forward
  compatible with the Az.Resources 10 / Az 16 breaking change. Check semantics unchanged.
- **Scoring is now computed in one place** (`Private/Scoring.ps1`): the console summary, HTML
  report (including the L1/L2 donuts), run history, and exit code all share the same
  `Get-AuditCounts`/`Get-AuditScore` functions instead of four hand-copied formulas. No score
  values change — this removes the risk of the outputs drifting apart.
- **Key Vault and Storage data-plane reads now retry on throttling**: key/secret/certificate
  listings and blob/file service property reads are wrapped in the same jittered-backoff retry
  as REST calls, so a transient 429/5xx no longer surfaces as a permanent ERROR for that
  control.
- **Control metadata now lives in one catalog** (`Private/Controls.ps1`, 127 controls): checks
  emit results by control id and the title/level/section are resolved from the catalog, instead
  of every emission branch repeating the literals (the 9.2.3 title used to appear 7 times).
  A benchmark-version bump now changes control metadata in exactly one file, and a title can no
  longer differ between branches of the same control. Generic fallback titles in error paths
  ("Key Expiration Check", "Activity Log Alert Check") are replaced by the real control titles.
- **Error-path classification centralized**: the ~11 copies of the four-branch
  not-applicable/authorization/firewall/fallback catch block in Sections 8 and 9 are collapsed
  into one `Add-ClassifiedErrorSet` helper. Statuses are unchanged; a few per-control message
  variants within the same failed read are consolidated to the most specific wording.
- **The orchestrator's report/summary tail exists once** (`Complete-AuditRun` in
  `Private/AuditPipeline.ps1`): the full-run and `-ReportOnly` paths used to carry two
  hand-copied versions of the dedupe → suppressions → level filter → score → console summary →
  report → history → exit-code sequence; both now call the same function. Output and exit-code
  behavior are unchanged.
- **Test suite split into per-section files**: the 3,900-line `Tests/Checks.Tests.ps1` monolith
  is now nine focused files (`Section2`–`Section9`, `Helpers`, `Pipeline`) sharing one
  bootstrap (`Tests/TestHelpers.ps1`) for module loading, fixtures, and the hermetic default
  mocks. Same 314 tests; the suite runs noticeably faster.

### Fixed

- **Microsoft Graph pagination**: paged Graph calls only followed ARM's `nextLink` and ignored
  Graph's `@odata.nextLink`, silently truncating results to the first page. In large tenants
  this could produce a **false PASS** on controls 5.3.5 (disabled users beyond the first 100
  were invisible), 5.1.3 (MFA registration report truncated), and 5.3.2 (guest inventory
  truncated past 999 users). Both link conventions are now followed, and the disabled-user
  query requests the maximum page size.
- **Key Vault firewall errors misclassified as missing RBAC**: Key Vault's firewall-block
  message ("Client address is not authorized and caller is not a trusted service") matched the
  authorization classifier, so the preflight and 8.3.x/9.x error paths recommended granting
  'Key Vault Reader' when the actual fix is the vault firewall allowlist. Firewall patterns now
  take precedence.
- **JSON report encoding**: `<report>.json` is now written without a UTF-8 BOM (RFC 8259
  forbids it; strict JSON parsers rejected the file). CSV keeps its BOM for Excel.

## [2.0.0] — 2026-07-15

Major release: full port to **CIS Microsoft Azure Foundations Benchmark v6.0.0** (April 2026).
Control IDs, titles, and audit procedures follow the v6 numbering — scores are **not**
comparable with v1.x runs against the v5 benchmark.

### Added

- CIS v6.0.0 control set across Sections 2, 3, 5, 6, 7, 8, 9 (127 controls; automated + manual
  surfaced) — including the reorganised Section 5 Identity controls (5.1.x, 5.3.x) and
  tenant-level checks for Sections 2, 3, 6, 7 and 8.
- Transient-failure retry with jittered exponential backoff on all Resource Graph and ARM/Graph
  REST calls, feeding the adaptive parallel-worker loop (`Invoke-WithRetry`).
- Prefetch failure propagation: a failed Resource Graph query surfaces as ERROR results for
  every dependent control — never a false PASS.
- Suppressions (`suppressions.json`): accepted-risk management with mandatory expiry
  (365-day cap); suppressed findings excluded from the score, raw results preserved on disk.
- CI guard for the report's inline JavaScript (`node --check` on generated report) (#56).
- UTF-8 BOM enforcement for non-ASCII scripts (#55); hardened workflow permissions and pinned
  action SHAs (#53).

### Changed

- **Compliance score now counts ERROR against the score** — `PASS / (PASS+FAIL+ERROR)`.
  An unauditable control is treated as failing rather than silently excluded; scores are
  therefore lower (more honest) than v1.x for the same tenant.
- All data collection is Az PowerShell (`Search-AzGraph`, `Invoke-AzRestMethod`, Az.* cmdlets);
  the Azure CLI subprocess layer was removed — `az` is no longer required.
- Explicit audit scope is required: `-TenantId` or `-Subscriptions` (#38); parallel workers get
  isolated Az contexts pinned to the tenant (#37, #39).
- `suppressions.json` is no longer tracked — the annotated `suppressions.json.example` is the
  template (#57).

### Fixed

- Control 5.4 wildcard detection across all error paths; Section 9 blob-service error handling
  emits all six 9.2.x controls on unexpected errors; security-contact error rows use proper
  control titles; report score consistency across console, HTML, and history (#27–#34, #52).

## [1.0.0] — 2026-04-19

Initial public release.

### Added

- Audit of **CIS Microsoft Azure Foundations Benchmark v5.0.0** (September 2025): 98 automated
  controls across 7 sections, 3 manual controls surfaced in output.
- Self-contained HTML report (filtering, compliance donuts, per-section breakdown,
  per-subscription summary, remediation hints) plus JSON and CSV outputs.
- Checkpoint save/resume per subscription; `-ReportOnly` regeneration; run history with trend
  chart; adaptive parallel execution; permission preflight; Pester suite + PSScriptAnalyzer CI.

[Unreleased]: https://github.com/vegazbabz/CISAzureBenchmark-PS/compare/v2.2.0...HEAD
[2.2.0]: https://github.com/vegazbabz/CISAzureBenchmark-PS/compare/v2.1.0...v2.2.0
[2.1.0]: https://github.com/vegazbabz/CISAzureBenchmark-PS/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/vegazbabz/CISAzureBenchmark-PS/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/vegazbabz/CISAzureBenchmark-PS/releases/tag/v1.0.0
