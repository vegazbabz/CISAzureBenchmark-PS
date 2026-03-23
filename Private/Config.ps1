# CIS Azure Benchmark PS - Configuration
# CIS Microsoft Azure Foundations Benchmark v5.0.0

Set-StrictMode -Version Latest

$script:CIS_VERSION   = "1.0.1"
$script:BENCHMARK_VER = "5.0.0"

# Status constants — avoid $Error which is a PS reserved variable
$script:PASS       = "PASS"
$script:FAIL       = "FAIL"
$script:ERR        = "ERROR"
$script:INFO       = "INFO"
$script:MANUAL     = "MANUAL"
$script:SUPPRESSED = "SUPPRESSED"

# Azure RBAC role GUIDs
$script:ROLE_OWNER = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
$script:ROLE_UAA   = "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9"

# Internet source addresses for NSG inbound rule evaluation
$script:INTERNET_SRCS = @("*", "0.0.0.0", "internet", "any", "0.0.0.0/0", "<internet>")

# Subnets exempt from NSG requirement (Azure platform subnets)
$script:EXEMPT_SUBNETS = @(
    "gatewaysubnet",
    "azurebastionsubnet",
    "azurefirewallsubnet",
    "azurefirewallmanagementsubnet",
    "routeserversubnet"
)

# CLI timeouts (seconds)
$script:TIMEOUTS = @{
    default      = 60
    storage_list = 90
    storage_svc  = 45
    activity_log = 75
    graph        = 180
}

# Checkpoint directory (relative to working directory)
$script:CHECKPOINT_DIR = "cis_checkpoints"

# Module-level flags (set by entry point)
$script:DEBUG_MODE   = $false
$script:VERBOSE_MODE = $false
$script:LOG_FILE     = $null

# Resource Graph Kusto queries (one per resource type)
$script:GRAPH_QUERIES = @{

    nsgs = @"
resources | where type =~ 'microsoft.network/networksecuritygroups'
| project id, name, resourceGroup, subscriptionId, rules = properties.securityRules
"@

    storage = @"
resources | where type =~ 'microsoft.storage/storageaccounts'
| project id, name, resourceGroup, subscriptionId,
    httpsOnly    = properties.supportsHttpsTrafficOnly,
    publicAccess = properties.publicNetworkAccess,
    crossTenant  = properties.allowCrossTenantReplication,
    blobAnon     = properties.allowBlobPublicAccess,
    defaultAction= properties.networkAcls.defaultAction,
    bypass       = properties.networkAcls.bypass,
    minTls       = properties.minimumTlsVersion,
    keyAccess    = properties.allowSharedKeyAccess,
    oauthDefault = properties.defaultToOAuthAuthentication,
    sku          = sku.name,
    privateEps   = array_length(properties.privateEndpointConnections)
"@

    keyvaults = @"
resources | where type =~ 'microsoft.keyvault/vaults'
| project id, name, resourceGroup, subscriptionId,
    purgeProtection = properties.enablePurgeProtection,
    rbac            = properties.enableRbacAuthorization,
    publicAccess    = properties.publicNetworkAccess,
    privateEps      = array_length(properties.privateEndpointConnections)
"@

    vnets = @"
resources | where type =~ 'microsoft.network/virtualnetworks'
| project id, name, resourceGroup, subscriptionId, location,
    hasDdos = isnotnull(properties.ddosProtectionPlan.id)
"@

    subnets = @"
resources | where type =~ 'microsoft.network/virtualnetworks'
| project subscriptionId,
    vnetName      = tostring(name),
    resourceGroup = tostring(resourceGroup),
    subnets       = properties.subnets
| mv-expand subnet = subnets
| project subscriptionId, vnetName, resourceGroup,
    subnetName = tostring(subnet.name),
    hasNsg     = isnotnull(subnet.properties.networkSecurityGroup.id)
"@

    bastion = @"
resources | where type =~ 'microsoft.network/bastionhosts'
| project id, name, resourceGroup, subscriptionId, sku
"@

    vms = @"
resources | where type =~ 'microsoft.compute/virtualmachines'
| project id, name, subscriptionId
"@

    watchers = @"
resources | where type =~ 'microsoft.network/networkwatchers'
| project id, name, subscriptionId, location, state = properties.provisioningState
"@

    locations = @"
resources | project subscriptionId, location | distinct subscriptionId, location
"@

    roles = @"
authorizationresources
| where type =~ 'microsoft.authorization/roleassignments'
| where properties.roleDefinitionId endswith '8e3af657-a8ff-443c-a75c-2fe8c4bcb635'
    or  properties.roleDefinitionId endswith '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9'
| project subscriptionId = tostring(subscriptionId),
    principalId      = tostring(properties.principalId),
    principalName    = tostring(properties.principalName),
    principalType    = tostring(properties.principalType),
    roleDefinitionId = tostring(properties.roleDefinitionId),
    scope            = tostring(properties.scope)
"@

    app_gateways = @"
resources | where type =~ 'microsoft.network/applicationgateways'
| project id, name, resourceGroup, subscriptionId,
    enableHttp2 = properties.enableHttp2,
    wafEnabled  = properties.webApplicationFirewallConfiguration.enabled,
    wafMode     = properties.webApplicationFirewallConfiguration.firewallMode,
    wafReqBody  = properties.webApplicationFirewallConfiguration.requestBodyCheck,
    sslMinProto = properties.sslPolicy.minProtocolVersion,
    wafPolicyId = tostring(properties.firewallPolicy.id)
"@

    databricks = @"
resources | where type =~ 'microsoft.databricks/workspaces'
| project id, name, resourceGroup, subscriptionId,
    noPublicIp   = properties.parameters.enableNoPublicIp.value,
    publicAccess = properties.publicNetworkAccess,
    vnetId       = tostring(properties.parameters.customVirtualNetworkId.value),
    privateEps   = array_length(properties.privateEndpointConnections)
"@

    waf_policies = @"
resources | where type =~ 'microsoft.network/applicationgatewaywebapplicationfirewallpolicies'
| project id, name, subscriptionId,
    botMode            = properties.policySettings.mode,
    requestBodyInspect = properties.policySettings.requestBodyInspect
"@

    app_services = @"
resources | where type =~ 'microsoft.web/sites'
| project id, name, resourceGroup, subscriptionId, kind
"@
}
