# Contributing to CISAzureBenchmark-PS

Thank you for considering a contribution! This document covers the basics.

## Getting started

1. **Fork** the repository and clone your fork.
2. Create a feature branch from `main`:

   ```powershell
   git checkout -b feature/my-change
   ```

3. Make your changes.
4. Run the test suite:

   ```powershell
   .\Tests\Run-Tests.ps1
   ```

5. Push your branch and open a **Pull Request** against `main`.

## Development requirements

| Tool | Version |
| --- | --- |
| PowerShell | 7.0+ |
| Pester | 5.0+ |
| PSScriptAnalyzer | latest (optional, CI runs it) |

Install dev dependencies:

```powershell
Install-PSResource Pester
Install-PSResource PSScriptAnalyzer
```

## Project layout

| Path | Purpose |
| --- | --- |
| `Invoke-CISAzureAudit.ps1` | Main entry point |
| `Private/` | Internal helper functions |
| `Checks/` | CIS check implementations (one file per section) |
| `Tests/` | Pester unit tests |

## Adding a new check

1. Add the check function to the appropriate `Checks/Section*.ps1` file.
2. Return results using `New-CISResult` (from `Private/Models.ps1`) or the `New-ErrorResult` / `New-InfoResult` / `New-ManualResult` helpers (from `Private/CheckHelpers.ps1`).
3. Add unit tests in the matching `Tests/Section*.Tests.ps1` file (shared fixtures and default mocks come from `Tests/TestHelpers.ps1`, dot-sourced in each file's `BeforeAll`).
4. Update the check-coverage table in `README.md`.

## Code style

- Use `Set-StrictMode -Version Latest` patterns.
- Follow the existing naming conventions (`Invoke-CheckX_Y` for per-control functions, `Invoke-SectionNChecks` / `Invoke-SectionNTenantChecks` for section entry points).
- Keep functions focused — one check per function.
- Avoid external module dependencies.

## Reporting issues

Use the [issue templates](https://github.com/vegazbabz/CISAzureBenchmark-PS/issues/new/choose) for bugs and feature requests.
