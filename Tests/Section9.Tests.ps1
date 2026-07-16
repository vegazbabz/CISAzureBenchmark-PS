#Requires -Version 7.0
<#
.SYNOPSIS
    Section 9 — Storage Services checks.
    Split from the former Tests\Checks.Tests.ps1 monolith; shared fixtures and the
    hermetic default mocks live in Tests\TestHelpers.ps1.
#>

param()

BeforeAll {
    . (Join-Path $PSScriptRoot "TestHelpers.ps1")
}

# =============================================================================
# SECTION 9 — STORAGE
# =============================================================================

Describe "Invoke-Section9Checks — no storage accounts" {
    It "returns INFO for all storage controls" {
        $pd = New-PD "storage" @()
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        $results.Count | Should -BeGreaterThan 5
        $results | ForEach-Object { $_.Status | Should -Be "INFO" }
    }
}

Describe "Invoke-Section9Checks — 9.3.4 Secure Transfer" {
    It "returns PASS when httpsOnly is true" {
        $acct = [PSCustomObject]@{
            id = "/sub/x/sa/sa1"; name = "sa1"; resourceGroup = "rg"; kind = "StorageV2"
            httpsOnly = "true"; publicAccess = "Disabled"; crossTenant = "false"
            blobAnon = "false"; defaultAction = "Deny"; bypass = "AzureServices"
            minTls = "TLS1_2"; keyAccess = "false"; oauthDefault = "true"
            sku = "Standard_GRS"; privateEps = 1
        }
        $pd = New-PD "storage" @($acct)

        $blobSvc = [PSCustomObject]@{
            DeleteRetentionPolicy          = [PSCustomObject]@{ Enabled = $true; Days = 7 }
            ContainerDeleteRetentionPolicy = [PSCustomObject]@{ Enabled = $true; Days = 7 }
            IsVersioningEnabled            = $true
            Logging                        = [PSCustomObject]@{ Read = $true; Write = $true; Delete = $true }
        }
        $fileSvc = [PSCustomObject]@{
            shareDeleteRetentionPolicy = [PSCustomObject]@{ enabled = $true; days = 7 }
            protocolSettings = [PSCustomObject]@{
                smb = [PSCustomObject]@{
                    versions           = "SMB3.0;SMB3.1.1"
                    channelEncryption  = "AES-128-GCM;AES-256-GCM"
                }
            }
        }

        Mock Get-AzStorageBlobServiceProperty { $blobSvc }
        Mock Get-AzStorageFileServiceProperty  { $fileSvc }
        Mock Get-AzStorageAccount              { throw "not available" }
        Mock Get-AzResourceLock                { @() }

        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.3.4" }).Status | Should -Be "PASS"
    }

    It "returns FAIL when httpsOnly is false" {
        $acct = [PSCustomObject]@{
            id = "/sub/x/sa/sa2"; name = "sa2"; resourceGroup = "rg"; kind = "StorageV2"
            httpsOnly = "false"; publicAccess = "Enabled"; crossTenant = "true"
            blobAnon = "true"; defaultAction = "Allow"; bypass = "None"
            minTls = "TLS1_0"; keyAccess = "true"; oauthDefault = "false"
            sku = "Standard_LRS"; privateEps = 0
        }
        $pd = New-PD "storage" @($acct)
        Mock Get-AzStorageBlobServiceProperty { throw "not available" }
        Mock Get-AzStorageFileServiceProperty  { throw "not available" }
        Mock Get-AzStorageAccount              { throw "not available" }
        Mock Get-AzResourceLock                { @() }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.3.4" }).Status | Should -Be "FAIL"
    }

    It "9.2.1 — retries a throttled blob-properties read instead of reporting ERROR" {
        $acct = [PSCustomObject]@{
            id = "/sub/x/sa/sa1"; name = "sa1"; resourceGroup = "rg"; kind = "StorageV2"
            httpsOnly = "true"; publicAccess = "Disabled"; crossTenant = "false"
            blobAnon = "false"; defaultAction = "Deny"; bypass = "AzureServices"
            minTls = "TLS1_2"; keyAccess = "false"; oauthDefault = "true"
            sku = "Standard_GRS"; privateEps = 1
        }
        $pd = New-PD "storage" @($acct)
        Mock Start-Sleep {}
        $script:blobPropCalls = 0
        Mock Get-AzStorageBlobServiceProperty {
            $script:blobPropCalls++
            if ($script:blobPropCalls -eq 1) { throw "request was throttled" }
            [PSCustomObject]@{
                DeleteRetentionPolicy          = [PSCustomObject]@{ Enabled = $true; Days = 7 }
                ContainerDeleteRetentionPolicy = [PSCustomObject]@{ Enabled = $true; Days = 7 }
                IsVersioningEnabled            = $true
            }
        }
        Mock Get-AzStorageFileServiceProperty  { throw "not available" }
        Mock Get-AzStorageAccount              { throw "not available" }
        Mock Get-AzResourceLock                { @() }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.2.1" }).Status | Should -Be "PASS"
        $script:blobPropCalls | Should -Be 2
    }
}

Describe "Invoke-Section9Checks — 9.3.6 Minimum TLS 1.2" {
    It "returns PASS when minTls is TLS1_2" {
        $acct = [PSCustomObject]@{
            id = "/sub/x/sa/sa3"; name = "sa3"; resourceGroup = "rg"; kind = "StorageV2"
            httpsOnly = "true"; publicAccess = "Enabled"; crossTenant = "false"
            blobAnon = "false"; defaultAction = "Allow"; bypass = "AzureServices"
            minTls = "TLS1_2"; keyAccess = "false"; oauthDefault = "true"
            sku = "Standard_LRS"; privateEps = 0
        }
        $pd = New-PD "storage" @($acct)
        Mock Get-AzStorageBlobServiceProperty { throw "not available" }
        Mock Get-AzStorageFileServiceProperty  { throw "not available" }
        Mock Get-AzStorageAccount              { throw "not available" }
        Mock Get-AzResourceLock                { @() }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.3.6" }).Status | Should -Be "PASS"
    }

    It "returns FAIL when minTls is TLS1_0" {
        $acct = [PSCustomObject]@{
            id = "/sub/x/sa/sa4"; name = "sa4"; resourceGroup = "rg"; kind = "StorageV2"
            httpsOnly = "true"; publicAccess = "Enabled"; crossTenant = "false"
            blobAnon = "false"; defaultAction = "Allow"; bypass = "AzureServices"
            minTls = "TLS1_0"; keyAccess = "false"; oauthDefault = "true"
            sku = "Standard_LRS"; privateEps = 0
        }
        $pd = New-PD "storage" @($acct)
        Mock Get-AzStorageBlobServiceProperty { throw "not available" }
        Mock Get-AzStorageFileServiceProperty  { throw "not available" }
        Mock Get-AzStorageAccount              { throw "not available" }
        Mock Get-AzResourceLock                { @() }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.3.6" }).Status | Should -Be "FAIL"
    }
}

Describe "Invoke-Section9Checks — 9.3.8 Blob Public Access" {
    It "returns PASS when blobAnon is false" {
        $acct = [PSCustomObject]@{
            id = "/sub/x/sa/sa5"; name = "sa5"; resourceGroup = "rg"; kind = "StorageV2"
            httpsOnly = "true"; publicAccess = "Enabled"; crossTenant = "false"
            blobAnon = "false"; defaultAction = "Allow"; bypass = "AzureServices"
            minTls = "TLS1_2"; keyAccess = "false"; oauthDefault = "true"
            sku = "Standard_LRS"; privateEps = 0
        }
        $pd = New-PD "storage" @($acct)
        Mock Get-AzStorageBlobServiceProperty { throw "not available" }
        Mock Get-AzStorageFileServiceProperty  { throw "not available" }
        Mock Get-AzStorageAccount              { throw "not available" }
        Mock Get-AzResourceLock                { @() }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.3.8" }).Status | Should -Be "PASS"
    }

    It "returns FAIL when blobAnon is true" {
        $acct = [PSCustomObject]@{
            id = "/sub/x/sa/sa6"; name = "sa6"; resourceGroup = "rg"; kind = "StorageV2"
            httpsOnly = "true"; publicAccess = "Enabled"; crossTenant = "false"
            blobAnon = "true"; defaultAction = "Allow"; bypass = "AzureServices"
            minTls = "TLS1_2"; keyAccess = "false"; oauthDefault = "true"
            sku = "Standard_LRS"; privateEps = 0
        }
        $pd = New-PD "storage" @($acct)
        Mock Get-AzStorageBlobServiceProperty { throw "not available" }
        Mock Get-AzStorageFileServiceProperty  { throw "not available" }
        Mock Get-AzStorageAccount              { throw "not available" }
        Mock Get-AzResourceLock                { @() }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.3.8" }).Status | Should -Be "FAIL"
    }
}

Describe "Invoke-Section9Checks — 9.3.7 Cross-Tenant Replication" {
    It "returns PASS when crossTenant is false" {
        $acct = [PSCustomObject]@{
            id = "/x"; name = "sa7"; resourceGroup = "rg"; kind = "StorageV2"
            httpsOnly = "true"; publicAccess = "Enabled"; crossTenant = "false"
            blobAnon = "false"; defaultAction = "Allow"; bypass = "AzureServices"
            minTls = "TLS1_2"; keyAccess = "false"; oauthDefault = "true"
            sku = "Standard_LRS"; privateEps = 0
        }
        $pd = New-PD "storage" @($acct)
        Mock Get-AzStorageBlobServiceProperty { throw "not available" }
        Mock Get-AzStorageFileServiceProperty  { throw "not available" }
        Mock Get-AzStorageAccount              { throw "not available" }
        Mock Get-AzResourceLock                { @() }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.3.7" }).Status | Should -Be "PASS"
    }

    It "returns FAIL when crossTenant is true" {
        $acct = [PSCustomObject]@{
            id = "/x"; name = "sa8"; resourceGroup = "rg"; kind = "StorageV2"
            httpsOnly = "true"; publicAccess = "Enabled"; crossTenant = "true"
            blobAnon = "false"; defaultAction = "Allow"; bypass = "AzureServices"
            minTls = "TLS1_2"; keyAccess = "false"; oauthDefault = "true"
            sku = "Standard_LRS"; privateEps = 0
        }
        $pd = New-PD "storage" @($acct)
        Mock Get-AzStorageBlobServiceProperty { throw "not available" }
        Mock Get-AzStorageFileServiceProperty  { throw "not available" }
        Mock Get-AzStorageAccount              { throw "not available" }
        Mock Get-AzResourceLock                { @() }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.3.7" }).Status | Should -Be "FAIL"
    }
}

# =============================================================================
# SECTION 9 — STORAGE (additional coverage)
# =============================================================================

Describe "Invoke-Section9Checks — 9.3.1.1 Key Rotation Reminder" {
    It "returns PASS when keyExpirationPeriodInDays is set" {
        $acct = [PSCustomObject]@{
            id = "/x"; name = "sa-keyrem"; resourceGroup = "rg"; kind = "StorageV2"
            httpsOnly = "true"; publicAccess = "Disabled"; crossTenant = "false"
            blobAnon = "false"; defaultAction = "Deny"; bypass = "AzureServices"
            minTls = "TLS1_2"; keyAccess = "false"; oauthDefault = "true"
            sku = "Standard_GRS"; privateEps = 1
        }
        $pd = New-PD "storage" @($acct)
        Mock Get-AzStorageBlobServiceProperty { throw "not available" }
        Mock Get-AzStorageFileServiceProperty  { throw "not available" }
        Mock Get-AzStorageAccount {
            [PSCustomObject]@{
                StorageAccountName = "sa-keyrem"
                ResourceGroupName  = "rg"
                KeyPolicy          = [PSCustomObject]@{ KeyExpirationPeriodInDays = 90 }
                KeyCreationTime    = [PSCustomObject]@{
                    Key1 = (Get-Date).AddDays(-30)
                    Key2 = (Get-Date).AddDays(-30)
                }
            }
        }
        Mock Get-AzResourceLock { @() }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.3.1.1" }).Status | Should -Be "PASS"
    }

    It "returns FAIL when keyExpirationPeriodInDays is null" {
        $acct = [PSCustomObject]@{
            id = "/x"; name = "sa-nokeyr"; resourceGroup = "rg"; kind = "StorageV2"
            httpsOnly = "true"; publicAccess = "Disabled"; crossTenant = "false"
            blobAnon = "false"; defaultAction = "Deny"; bypass = "AzureServices"
            minTls = "TLS1_2"; keyAccess = "false"; oauthDefault = "true"
            sku = "Standard_GRS"; privateEps = 1
        }
        $pd = New-PD "storage" @($acct)
        Mock Get-AzStorageBlobServiceProperty { throw "not available" }
        Mock Get-AzStorageFileServiceProperty  { throw "not available" }
        Mock Get-AzStorageAccount {
            [PSCustomObject]@{
                StorageAccountName = "sa-nokeyr"
                ResourceGroupName  = "rg"
                KeyPolicy          = $null
                KeyCreationTime    = [PSCustomObject]@{
                    Key1 = (Get-Date).AddDays(-30)
                    Key2 = (Get-Date).AddDays(-30)
                }
            }
        }
        Mock Get-AzResourceLock { @() }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.3.1.1" }).Status | Should -Be "FAIL"
    }
}

Describe "Invoke-Section9Checks — 9.3.1.2 Key Rotation Within 90 Days" {
    It "returns PASS when both keys are within 90 days" {
        $acct = [PSCustomObject]@{
            id = "/x"; name = "sa-keyrot"; resourceGroup = "rg"; kind = "StorageV2"
            httpsOnly = "true"; publicAccess = "Disabled"; crossTenant = "false"
            blobAnon = "false"; defaultAction = "Deny"; bypass = "AzureServices"
            minTls = "TLS1_2"; keyAccess = "false"; oauthDefault = "true"
            sku = "Standard_GRS"; privateEps = 1
        }
        $pd = New-PD "storage" @($acct)
        Mock Get-AzStorageBlobServiceProperty { throw "not available" }
        Mock Get-AzStorageFileServiceProperty  { throw "not available" }
        Mock Get-AzStorageAccount {
            [PSCustomObject]@{
                StorageAccountName = "sa-keyrot"
                ResourceGroupName  = "rg"
                KeyPolicy          = [PSCustomObject]@{ KeyExpirationPeriodInDays = 90 }
                KeyCreationTime    = [PSCustomObject]@{
                    Key1 = (Get-Date).AddDays(-30)
                    Key2 = (Get-Date).AddDays(-10)
                }
            }
        }
        Mock Get-AzResourceLock { @() }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.3.1.2" }).Status | Should -Be "PASS"
    }

    It "returns FAIL when a key is older than 90 days" {
        $acct = [PSCustomObject]@{
            id = "/x"; name = "sa-keyold"; resourceGroup = "rg"; kind = "StorageV2"
            httpsOnly = "true"; publicAccess = "Disabled"; crossTenant = "false"
            blobAnon = "false"; defaultAction = "Deny"; bypass = "AzureServices"
            minTls = "TLS1_2"; keyAccess = "false"; oauthDefault = "true"
            sku = "Standard_GRS"; privateEps = 1
        }
        $pd = New-PD "storage" @($acct)
        Mock Get-AzStorageBlobServiceProperty { throw "not available" }
        Mock Get-AzStorageFileServiceProperty  { throw "not available" }
        Mock Get-AzStorageAccount {
            [PSCustomObject]@{
                StorageAccountName = "sa-keyold"
                ResourceGroupName  = "rg"
                KeyPolicy          = [PSCustomObject]@{ KeyExpirationPeriodInDays = 90 }
                KeyCreationTime    = [PSCustomObject]@{
                    Key1 = (Get-Date).AddDays(-120)
                    Key2 = (Get-Date).AddDays(-30)
                }
            }
        }
        Mock Get-AzResourceLock { @() }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.3.1.2" }).Status | Should -Be "FAIL"
    }
}

Describe "Invoke-Section9Checks — 9.3.1.3 Shared Key Access" {
    It "returns PASS when keyAccess is false" {
        $acct = [PSCustomObject]@{
            id = "/x"; name = "sa9"; resourceGroup = "rg"; kind = "StorageV2"
            httpsOnly = "true"; publicAccess = "Disabled"; crossTenant = "false"
            blobAnon = "false"; defaultAction = "Deny"; bypass = "AzureServices"
            minTls = "TLS1_2"; keyAccess = "false"; oauthDefault = "true"
            sku = "Standard_GRS"; privateEps = 1
        }
        $pd = New-PD "storage" @($acct)
        Mock Get-AzStorageBlobServiceProperty { throw "not available" }
        Mock Get-AzStorageFileServiceProperty  { throw "not available" }
        Mock Get-AzStorageAccount              { throw "not available" }
        Mock Get-AzResourceLock                { @() }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.3.1.3" }).Status | Should -Be "PASS"
    }

    It "returns FAIL when keyAccess is true" {
        $acct = [PSCustomObject]@{
            id = "/x"; name = "sa10"; resourceGroup = "rg"; kind = "StorageV2"
            httpsOnly = "true"; publicAccess = "Enabled"; crossTenant = "false"
            blobAnon = "false"; defaultAction = "Allow"; bypass = "None"
            minTls = "TLS1_2"; keyAccess = "true"; oauthDefault = "false"
            sku = "Standard_LRS"; privateEps = 0
        }
        $pd = New-PD "storage" @($acct)
        Mock Get-AzStorageBlobServiceProperty { throw "not available" }
        Mock Get-AzStorageFileServiceProperty  { throw "not available" }
        Mock Get-AzStorageAccount              { throw "not available" }
        Mock Get-AzResourceLock                { @() }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.3.1.3" }).Status | Should -Be "FAIL"
    }
}

Describe "Invoke-Section9Checks — 9.3.3.1 OAuth Default" {
    It "returns PASS when oauthDefault is true" {
        $acct = [PSCustomObject]@{
            id = "/x"; name = "sa-oauth"; resourceGroup = "rg"; kind = "StorageV2"
            httpsOnly = "true"; publicAccess = "Disabled"; crossTenant = "false"
            blobAnon = "false"; defaultAction = "Deny"; bypass = "AzureServices"
            minTls = "TLS1_2"; keyAccess = "false"; oauthDefault = "true"
            sku = "Standard_GRS"; privateEps = 1
        }
        $pd = New-PD "storage" @($acct)
        Mock Get-AzStorageBlobServiceProperty { throw "not available" }
        Mock Get-AzStorageFileServiceProperty  { throw "not available" }
        Mock Get-AzStorageAccount              { throw "not available" }
        Mock Get-AzResourceLock                { @() }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.3.3.1" }).Status | Should -Be "PASS"
    }

    It "returns FAIL when oauthDefault is false" {
        $acct = [PSCustomObject]@{
            id = "/x"; name = "sa-nooauth"; resourceGroup = "rg"; kind = "StorageV2"
            httpsOnly = "true"; publicAccess = "Enabled"; crossTenant = "false"
            blobAnon = "false"; defaultAction = "Allow"; bypass = "None"
            minTls = "TLS1_2"; keyAccess = "true"; oauthDefault = "false"
            sku = "Standard_LRS"; privateEps = 0
        }
        $pd = New-PD "storage" @($acct)
        Mock Get-AzStorageBlobServiceProperty { throw "not available" }
        Mock Get-AzStorageFileServiceProperty  { throw "not available" }
        Mock Get-AzStorageAccount              { throw "not available" }
        Mock Get-AzResourceLock                { @() }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.3.3.1" }).Status | Should -Be "FAIL"
    }
}

Describe "Invoke-Section9Checks — 9.3.2.x Network Checks" {
    BeforeAll {
        $script:compliantAcct = [PSCustomObject]@{
            id = "/x"; name = "sa-net"; resourceGroup = "rg"; kind = "StorageV2"
            httpsOnly = "true"; publicAccess = "Disabled"; crossTenant = "false"
            blobAnon = "false"; defaultAction = "Deny"; bypass = "AzureServices"
            minTls = "TLS1_2"; keyAccess = "false"; oauthDefault = "true"
            sku = "Standard_GRS"; privateEps = 2
        }
        $script:nonCompliantAcct = [PSCustomObject]@{
            id = "/x"; name = "sa-net2"; resourceGroup = "rg"; kind = "StorageV2"
            httpsOnly = "true"; publicAccess = "Enabled"; crossTenant = "false"
            blobAnon = "false"; defaultAction = "Allow"; bypass = "None"
            minTls = "TLS1_2"; keyAccess = "false"; oauthDefault = "true"
            sku = "Standard_LRS"; privateEps = 0
        }
    }

    It "9.3.2.1 — PASS with private endpoints" {
        $pd = New-PD "storage" @($compliantAcct)
        Mock Get-AzStorageBlobServiceProperty { throw "not available" }
        Mock Get-AzStorageFileServiceProperty  { throw "not available" }
        Mock Get-AzStorageAccount              { throw "not available" }
        Mock Get-AzResourceLock                { @() }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.3.2.1" }).Status | Should -Be "PASS"
    }

    It "9.3.2.1 — FAIL without private endpoints" {
        $pd = New-PD "storage" @($nonCompliantAcct)
        Mock Get-AzStorageBlobServiceProperty { throw "not available" }
        Mock Get-AzStorageFileServiceProperty  { throw "not available" }
        Mock Get-AzStorageAccount              { throw "not available" }
        Mock Get-AzResourceLock                { @() }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.3.2.1" }).Status | Should -Be "FAIL"
    }

    It "9.3.2.2 — PASS when publicAccess Disabled" {
        $pd = New-PD "storage" @($compliantAcct)
        Mock Get-AzStorageBlobServiceProperty { throw "not available" }
        Mock Get-AzStorageFileServiceProperty  { throw "not available" }
        Mock Get-AzStorageAccount              { throw "not available" }
        Mock Get-AzResourceLock                { @() }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.3.2.2" }).Status | Should -Be "PASS"
    }

    It "9.3.2.2 — FAIL when publicAccess Enabled" {
        $pd = New-PD "storage" @($nonCompliantAcct)
        Mock Get-AzStorageBlobServiceProperty { throw "not available" }
        Mock Get-AzStorageFileServiceProperty  { throw "not available" }
        Mock Get-AzStorageAccount              { throw "not available" }
        Mock Get-AzResourceLock                { @() }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.3.2.2" }).Status | Should -Be "FAIL"
    }

    It "9.3.2.3 — PASS when defaultAction Deny" {
        $pd = New-PD "storage" @($compliantAcct)
        Mock Get-AzStorageBlobServiceProperty { throw "not available" }
        Mock Get-AzStorageFileServiceProperty  { throw "not available" }
        Mock Get-AzStorageAccount              { throw "not available" }
        Mock Get-AzResourceLock                { @() }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.3.2.3" }).Status | Should -Be "PASS"
    }

    It "9.3.2.3 — FAIL when defaultAction Allow" {
        $pd = New-PD "storage" @($nonCompliantAcct)
        Mock Get-AzStorageBlobServiceProperty { throw "not available" }
        Mock Get-AzStorageFileServiceProperty  { throw "not available" }
        Mock Get-AzStorageAccount              { throw "not available" }
        Mock Get-AzResourceLock                { @() }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.3.2.3" }).Status | Should -Be "FAIL"
    }
}

Describe "Invoke-Section9Checks — 9.3.5 Trusted Services Bypass" {
    It "returns PASS when bypass includes AzureServices" {
        $acct = [PSCustomObject]@{
            id = "/x"; name = "sa-bp"; resourceGroup = "rg"; kind = "StorageV2"
            httpsOnly = "true"; publicAccess = "Disabled"; crossTenant = "false"
            blobAnon = "false"; defaultAction = "Deny"; bypass = "AzureServices"
            minTls = "TLS1_2"; keyAccess = "false"; oauthDefault = "true"
            sku = "Standard_GRS"; privateEps = 1
        }
        $pd = New-PD "storage" @($acct)
        Mock Get-AzStorageBlobServiceProperty { throw "not available" }
        Mock Get-AzStorageFileServiceProperty  { throw "not available" }
        Mock Get-AzStorageAccount              { throw "not available" }
        Mock Get-AzResourceLock                { @() }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.3.5" }).Status | Should -Be "PASS"
    }

    It "returns FAIL when bypass does not include AzureServices" {
        $acct = [PSCustomObject]@{
            id = "/x"; name = "sa-nobp"; resourceGroup = "rg"; kind = "StorageV2"
            httpsOnly = "true"; publicAccess = "Disabled"; crossTenant = "false"
            blobAnon = "false"; defaultAction = "Deny"; bypass = "None"
            minTls = "TLS1_2"; keyAccess = "false"; oauthDefault = "true"
            sku = "Standard_GRS"; privateEps = 1
        }
        $pd = New-PD "storage" @($acct)
        Mock Get-AzStorageBlobServiceProperty { throw "not available" }
        Mock Get-AzStorageFileServiceProperty  { throw "not available" }
        Mock Get-AzStorageAccount              { throw "not available" }
        Mock Get-AzResourceLock                { @() }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.3.5" }).Status | Should -Be "FAIL"
    }
}

Describe "Invoke-Section9Checks — 9.3.11 Geo-Redundant Storage" {
    It "returns PASS for GRS SKU" {
        $acct = [PSCustomObject]@{
            id = "/x"; name = "sa-grs"; resourceGroup = "rg"; kind = "StorageV2"
            httpsOnly = "true"; publicAccess = "Disabled"; crossTenant = "false"
            blobAnon = "false"; defaultAction = "Deny"; bypass = "AzureServices"
            minTls = "TLS1_2"; keyAccess = "false"; oauthDefault = "true"
            sku = "Standard_GRS"; privateEps = 1
        }
        $pd = New-PD "storage" @($acct)
        Mock Get-AzStorageBlobServiceProperty { throw "not available" }
        Mock Get-AzStorageFileServiceProperty  { throw "not available" }
        Mock Get-AzStorageAccount              { throw "not available" }
        Mock Get-AzResourceLock                { @() }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.3.11" }).Status | Should -Be "PASS"
    }

    It "returns FAIL for LRS SKU" {
        $acct = [PSCustomObject]@{
            id = "/x"; name = "sa-lrs"; resourceGroup = "rg"; kind = "StorageV2"
            httpsOnly = "true"; publicAccess = "Disabled"; crossTenant = "false"
            blobAnon = "false"; defaultAction = "Deny"; bypass = "AzureServices"
            minTls = "TLS1_2"; keyAccess = "false"; oauthDefault = "true"
            sku = "Standard_LRS"; privateEps = 1
        }
        $pd = New-PD "storage" @($acct)
        Mock Get-AzStorageBlobServiceProperty { throw "not available" }
        Mock Get-AzStorageFileServiceProperty  { throw "not available" }
        Mock Get-AzStorageAccount              { throw "not available" }
        Mock Get-AzResourceLock                { @() }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.3.11" }).Status | Should -Be "FAIL"
    }
}

Describe "Invoke-Section9Checks — 9.2.x Blob Service" {
    BeforeAll {
        $script:saBase = [PSCustomObject]@{
            id = "/x"; name = "sa-blob"; resourceGroup = "rg"; kind = "StorageV2"
            httpsOnly = "true"; publicAccess = "Disabled"; crossTenant = "false"
            blobAnon = "false"; defaultAction = "Deny"; bypass = "AzureServices"
            minTls = "TLS1_2"; keyAccess = "false"; oauthDefault = "true"
            sku = "Standard_GRS"; privateEps = 1
        }
    }

    It "returns PASS for all blob checks when compliant" {
        $pd = New-PD "storage" @($saBase)
        $blobSvc = [PSCustomObject]@{
            DeleteRetentionPolicy          = [PSCustomObject]@{ Enabled = $true; Days = 7 }
            ContainerDeleteRetentionPolicy = [PSCustomObject]@{ Enabled = $true; Days = 7 }
            IsVersioningEnabled            = $true
            Logging                        = [PSCustomObject]@{ Read = $true; Write = $true; Delete = $true }
        }
        Mock Get-AzStorageBlobServiceProperty { $blobSvc }
        Mock Get-AzStorageFileServiceProperty  { throw "not available" }
        Mock Get-AzStorageAccount              { throw "not available" }
        Mock Get-AzResourceLock                { @() }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.2.1" }).Status | Should -Be "PASS"
        ($results | Where-Object { $_.ControlId -eq "9.2.2" }).Status | Should -Be "PASS"
        ($results | Where-Object { $_.ControlId -eq "9.2.3" }).Status | Should -Be "PASS"
    }

    It "returns FAIL when blob soft delete disabled" {
        $pd = New-PD "storage" @($saBase)
        $blobSvc = [PSCustomObject]@{
            DeleteRetentionPolicy          = [PSCustomObject]@{ Enabled = $false; Days = 0 }
            ContainerDeleteRetentionPolicy = [PSCustomObject]@{ Enabled = $false; Days = 0 }
            IsVersioningEnabled            = $false
            Logging                        = [PSCustomObject]@{ Read = $false; Write = $false; Delete = $false }
        }
        Mock Get-AzStorageBlobServiceProperty { $blobSvc }
        Mock Get-AzStorageFileServiceProperty  { throw "not available" }
        Mock Get-AzStorageAccount              { throw "not available" }
        Mock Get-AzResourceLock                { @() }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.2.1" }).Status | Should -Be "FAIL"
        ($results | Where-Object { $_.ControlId -eq "9.2.2" }).Status | Should -Be "FAIL"
        ($results | Where-Object { $_.ControlId -eq "9.2.3" }).Status | Should -Be "FAIL"
    }
}

Describe "Invoke-Section9Checks — 9.1.x File Service" {
    BeforeAll {
        $script:saFile = [PSCustomObject]@{
            id = "/x"; name = "sa-file"; resourceGroup = "rg"; kind = "StorageV2"
            httpsOnly = "true"; publicAccess = "Disabled"; crossTenant = "false"
            blobAnon = "false"; defaultAction = "Deny"; bypass = "AzureServices"
            minTls = "TLS1_2"; keyAccess = "false"; oauthDefault = "true"
            sku = "Standard_GRS"; privateEps = 1
        }
    }

    It "returns PASS when file soft delete and SMB settings compliant" {
        $pd = New-PD "storage" @($saFile)
        $fileSvc = [PSCustomObject]@{
            shareDeleteRetentionPolicy = [PSCustomObject]@{ enabled = $true; days = 14 }
            protocolSettings = [PSCustomObject]@{
                smb = [PSCustomObject]@{
                    versions          = "SMB3.0;SMB3.1.1"
                    channelEncryption = "AES-128-GCM;AES-256-GCM"
                }
            }
        }
        Mock Get-AzStorageBlobServiceProperty { throw "not available" }
        Mock Get-AzStorageFileServiceProperty  { $fileSvc }
        Mock Get-AzStorageAccount              { throw "not available" }
        Mock Get-AzResourceLock                { @() }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.1.1" }).Status | Should -Be "PASS"
        ($results | Where-Object { $_.ControlId -eq "9.1.2" }).Status | Should -Be "PASS"
        ($results | Where-Object { $_.ControlId -eq "9.1.3" }).Status | Should -Be "PASS"
    }

    It "returns FAIL when file soft delete disabled" {
        $pd = New-PD "storage" @($saFile)
        $fileSvc = [PSCustomObject]@{
            shareDeleteRetentionPolicy = [PSCustomObject]@{ enabled = $false; days = 0 }
            protocolSettings = [PSCustomObject]@{
                smb = [PSCustomObject]@{
                    versions          = "SMB2.1;SMB3.0"
                    channelEncryption = "AES-128-GCM"
                }
            }
        }
        Mock Get-AzStorageBlobServiceProperty { throw "not available" }
        Mock Get-AzStorageFileServiceProperty  { $fileSvc }
        Mock Get-AzStorageAccount              { throw "not available" }
        Mock Get-AzResourceLock                { @() }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.1.1" }).Status | Should -Be "FAIL"
        ($results | Where-Object { $_.ControlId -eq "9.1.2" }).Status | Should -Be "FAIL"
        ($results | Where-Object { $_.ControlId -eq "9.1.3" }).Status | Should -Be "FAIL"
    }
}

Describe "Invoke-Section9Checks — 9.3.9/9.3.10 Resource Locks" {
    BeforeAll {
        $script:saLock = [PSCustomObject]@{
            id = "/subscriptions/$($script:T_SID)/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa-lock"
            name = "sa-lock"; resourceGroup = "rg"; kind = "StorageV2"
            httpsOnly = "true"; publicAccess = "Disabled"; crossTenant = "false"
            blobAnon = "false"; defaultAction = "Deny"; bypass = "AzureServices"
            minTls = "TLS1_2"; keyAccess = "false"; oauthDefault = "true"
            sku = "Standard_GRS"; privateEps = 1
        }
    }

    It "returns PASS for both when ReadOnly lock exists" {
        $pd = New-PD "storage" @($saLock)
        Mock Get-AzStorageBlobServiceProperty { throw "not available" }
        Mock Get-AzStorageFileServiceProperty  { throw "not available" }
        Mock Get-AzStorageAccount              { throw "not available" }
        Mock Get-AzResourceLock {
            @([PSCustomObject]@{
                LockId = "/subscriptions/$($script:T_SID)/providers/Microsoft.Authorization/locks/mylock"
                Level  = "ReadOnly"
            })
        }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.3.9" }).Status | Should -Be "PASS"
        ($results | Where-Object { $_.ControlId -eq "9.3.10" }).Status | Should -Be "PASS"
    }

    It "returns 9.3.9 PASS / 9.3.10 FAIL for CanNotDelete lock" {
        $pd = New-PD "storage" @($saLock)
        Mock Get-AzStorageBlobServiceProperty { throw "not available" }
        Mock Get-AzStorageFileServiceProperty  { throw "not available" }
        Mock Get-AzStorageAccount              { throw "not available" }
        Mock Get-AzResourceLock {
            @([PSCustomObject]@{
                LockId = "/subscriptions/$($script:T_SID)/providers/Microsoft.Authorization/locks/dellock"
                Level  = "CanNotDelete"
            })
        }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.3.9" }).Status | Should -Be "PASS"
        ($results | Where-Object { $_.ControlId -eq "9.3.10" }).Status | Should -Be "FAIL"
    }

    It "returns FAIL for both when no locks" {
        $pd = New-PD "storage" @($saLock)
        Mock Get-AzStorageBlobServiceProperty { throw "not available" }
        Mock Get-AzStorageFileServiceProperty  { throw "not available" }
        Mock Get-AzStorageAccount              { throw "not available" }
        Mock Get-AzResourceLock { @() }
        $results = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($results | Where-Object { $_.ControlId -eq "9.3.9" }).Status | Should -Be "FAIL"
        ($results | Where-Object { $_.ControlId -eq "9.3.10" }).Status | Should -Be "FAIL"
    }
}

# =============================================================================
# SECTION 9 — ADLS Gen2 HNS detection (regression)
# =============================================================================

Describe "Invoke-Section9Checks — ADLS Gen2 HNS detection (regression)" {
    It "skips blob-service-properties call for HNS-enabled account (isHns=true)" {
        # StorageV2 account with Standard_LRS SKU and isHnsEnabled=true.
        # The old SKU heuristic would not detect it as ADLS and would wrongly call
        # blob-service-properties, which is unsupported for HNS accounts.
        $adlsAcct = [PSCustomObject]@{
            id = "/x"; name = "sa-adls"; resourceGroup = "rg"; kind = "StorageV2"
            httpsOnly = "true"; publicAccess = "Disabled"; crossTenant = "false"
            blobAnon = "false"; defaultAction = "Deny"; bypass = "AzureServices"
            minTls = "TLS1_2"; keyAccess = "false"; oauthDefault = "true"
            isHns = "true"; sku = "Standard_LRS"; privateEps = 1
        }
        $pd = New-PD "storage" @($adlsAcct)
        $script:blobApiCalled = $false
        Mock Get-AzStorageBlobServiceProperty { $script:blobApiCalled = $true }
        Mock Get-AzStorageFileServiceProperty  { throw "not available" }
        Mock Get-AzStorageAccount              { throw "not available" }
        Mock Get-AzResourceLock                { @() }
        Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd | Out-Null
        $script:blobApiCalled | Should -BeFalse
    }

    It "calls blob-service-properties for a regular StorageV2 account (isHns=null)" {
        # A standard StorageV2 account (isHns null/false) must still call the blob API.
        $regularAcct = [PSCustomObject]@{
            id = "/x"; name = "sa-regular"; resourceGroup = "rg"; kind = "StorageV2"
            httpsOnly = "true"; publicAccess = "Disabled"; crossTenant = "false"
            blobAnon = "false"; defaultAction = "Deny"; bypass = "AzureServices"
            minTls = "TLS1_2"; keyAccess = "false"; oauthDefault = "true"
            isHns = $null; sku = "Standard_LRS"; privateEps = 1
        }
        $pd = New-PD "storage" @($regularAcct)
        $script:blobApiCalled = $false
        Mock Get-AzStorageBlobServiceProperty {
            $script:blobApiCalled = $true
            [PSCustomObject]@{
                DeleteRetentionPolicy          = [PSCustomObject]@{ Enabled = $true; Days = 7 }
                ContainerDeleteRetentionPolicy = [PSCustomObject]@{ Enabled = $true; Days = 7 }
                IsVersioningEnabled            = $true
                Logging                        = [PSCustomObject]@{ Read = $true; Write = $true; Delete = $true }
            }
        }
        Mock Get-AzStorageFileServiceProperty  { throw "not available" }
        Mock Get-AzStorageAccount              { throw "not available" }
        Mock Get-AzResourceLock                { @() }
        Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd | Out-Null
        $script:blobApiCalled | Should -BeTrue
    }
}

Describe "Invoke-Section9Checks — lock read failure" {
    It "9.3.9/9.3.10 ERROR (not FAIL) when Get-AzResourceLock throws" {
        Mock Get-AzResourceLock { throw "authorization failed" }
        Mock Invoke-ArmRest { [PSCustomObject]@{ Success = $true; Data = [PSCustomObject]@{ value = @() } } }
        $pd = New-PD "storage" @([PSCustomObject]@{
            id = "/subscriptions/$($script:T_SID)/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa1"
            name = "sa1"; resourceGroup = "rg"; isHns = "false"; sku = "Standard_LRS"
        })
        $r = @(Invoke-Section9Checks -SubscriptionId $T_SID -SubscriptionName $T_SNAME -PrefetchData $pd)
        ($r | Where-Object { $_.ControlId -eq "9.3.9" }).Status | Should -Be "ERROR"
        ($r | Where-Object { $_.ControlId -eq "9.3.10" }).Status | Should -Be "ERROR"
    }
}
