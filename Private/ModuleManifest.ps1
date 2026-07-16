# Single source of truth for the module dot-source order.
#
# Consumed by BOTH loaders — the top-level loader in Invoke-CISAzureAudit.ps1 and
# the per-subscription parallel re-import — so the two can never drift. Previously
# the list was duplicated, and a Private/*.ps1 or Checks/*.ps1 that a parallel
# worker needed but was omitted from the second list produced a CommandNotFound
# only under -Parallel > 1, which the sequential test suite never exercised.
#
# Order matters: Config/Models/AzureClient/Helpers define the primitives every
# later file depends on, so they load first.
$script:ModuleFiles = @(
    "Private\Config.ps1",
    "Private\Controls.ps1",
    "Private\Models.ps1",
    "Private\Scoring.ps1",
    "Private\AzureClient.ps1",
    "Private\Helpers.ps1",
    "Private\CheckHelpers.ps1",
    "Private\Identity.ps1",
    "Private\Checkpoint.ps1",
    "Private\History.ps1",
    "Private\RunDiff.ps1",
    "Private\AuditPipeline.ps1",
    "Private\Report.ps1",
    "Private\Sarif.ps1",
    "Private\Suppressions.ps1",
    "Checks\Section2.ps1",
    "Checks\Section3.ps1",
    "Checks\Section5.ps1",
    "Checks\Section6.ps1",
    "Checks\Section7.ps1",
    "Checks\Section8.ps1",
    "Checks\Section9.ps1"
)
