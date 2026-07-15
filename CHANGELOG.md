# Changelog

All notable changes to CISAzureBenchmark-PS are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) · Versioning: [SemVer](https://semver.org/).
For compliance users the key question is *which controls changed* — every entry calls that out explicitly.

## [Unreleased]

### Added
- **PowerShell module packaging** (#59): `CISAzureBenchmark.psd1`/`.psm1` with an exported
  `Invoke-CISAzureAudit` that returns a typed summary object (`ExitCode`, `Counts`, `Score`,
  `Results`, `ReportPath`). The root `Invoke-CISAzureAudit.ps1` script is now a thin
  compatibility shim — existing command lines and CI pipelines are unaffected.
- **PowerShell Gallery release pipeline**: tag pushes publish the staged module to the Gallery
  when the `PSGALLERY_API_KEY` repo secret is configured (`scripts/Build-ModulePackage.ps1`
  stages runtime files only). Skips with a notice when the secret is absent.
- CI: module manifest validation step (Test-ModuleManifest + import smoke test).

### Changed
- **Control 5.4** (no custom subscription administrator roles) now reads role definitions via
  `Permissions[n].Actions` with a fallback to the flattened `Actions` property (#58) — forward
  compatible with the Az.Resources 10 / Az 16 breaking change. Check semantics unchanged.

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

[Unreleased]: https://github.com/vegazbabz/CISAzureBenchmark-PS/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/vegazbabz/CISAzureBenchmark-PS/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/vegazbabz/CISAzureBenchmark-PS/releases/tag/v1.0.0
