<#
.SYNOPSIS
    Checks SSL certificate expiration for Azure Web Apps and Container Apps.

.DESCRIPTION
    Connects to Azure, retrieves SSL bindings from App Services and Container Apps
    across the entire subscription, and returns certificate details including
    expiration dates.

.PARAMETER SubscriptionId
    Azure Subscription ID to scan.

.PARAMETER ResourceGroupName
    Optional. Resource Group name to scope the check. If omitted, all resource
    groups in the subscription are scanned.

.PARAMETER AppNames
    Optional list of specific app names. If omitted, all apps are checked.
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$SubscriptionId,

    [Parameter(Mandatory = $false)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $false)]
    [string[]]$AppNames,

    [Parameter(Mandatory = $false)]
    [int]$ExpirationThresholdDays = 0
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

#region --- Functions ---

function Get-WebAppSSLCertificates {
    <#
    .SYNOPSIS
        Retrieves SSL certificate info from Azure App Services (ASE/ACE).
    #>
    param(
        [string[]]$ResourceGroupNames,
        [string[]]$AppNames
    )

    $results = @()

    if ($AppNames -and $AppNames.Count -gt 0) {
        # When specific app names are given, search across all provided RGs
        $webApps = @()
        foreach ($rg in $ResourceGroupNames) {
            foreach ($name in $AppNames) {
                $app = Get-AzWebApp -ResourceGroupName $rg -Name $name -ErrorAction SilentlyContinue
                if ($app) { $webApps += $app }
            }
        }
    }
    else {
        $webApps = @()
        foreach ($rg in $ResourceGroupNames) {
            Write-Host "Scanning Web Apps in Resource Group: $rg"
            $webApps += Get-AzWebApp -ResourceGroupName $rg -ErrorAction SilentlyContinue
        }
    }

    foreach ($app in $webApps) {
        $appRg = $app.ResourceGroup
        Write-Host "Checking Web App: $($app.Name) (RG: $appRg)"

        # Get hostname SSL states
        $sslBindings = $app.HostNameSslStates | Where-Object {
            $_.SslState -ne 'Disabled' -and $_.Thumbprint
        }

        if (-not $sslBindings -or $sslBindings.Count -eq 0) {
            Write-Host "  No SSL bindings found for $($app.Name)"
            continue
        }

        foreach ($binding in $sslBindings) {
            # Look up the certificate by thumbprint in the app's resource group
            $cert = Get-AzWebAppCertificate -ResourceGroupName $appRg -ErrorAction SilentlyContinue |
                Where-Object { $_.Thumbprint -eq $binding.Thumbprint } |
                Select-Object -First 1

            $expirationDate = $null
            $issuer = "Unknown"
            $subjectName = $binding.Name

            if ($cert) {
                $expirationDate = $cert.ExpirationDate
                $issuer = $cert.Issuer
                $subjectName = $cert.SubjectName
            }

            $isExpired = $false
            $daysUntilExpiry = $null
            if ($expirationDate) {
                $daysUntilExpiry = [math]::Floor(($expirationDate - (Get-Date)).TotalDays)
                $isExpired = $daysUntilExpiry -le $ExpirationThresholdDays
            }

            $results += [PSCustomObject]@{
                AppType         = "WebApp"
                AppName         = $app.Name
                ResourceGroup   = $appRg
                HostName        = $binding.Name
                Thumbprint      = $binding.Thumbprint
                SslState        = $binding.SslState
                ExpirationDate  = $expirationDate
                DaysUntilExpiry = $daysUntilExpiry
                IsExpired       = $isExpired
                Issuer          = $issuer
                SubjectName     = $subjectName
            }
        }
    }

    return $results
}

function Get-ContainerAppSSLCertificates {
    <#
    .SYNOPSIS
        Retrieves SSL certificate info from Azure Container Apps.
    #>
    param(
        [string[]]$ResourceGroupNames,
        [string[]]$AppNames
    )

    $results = @()

    foreach ($rg in $ResourceGroupNames) {
        # Get Container App Environments in each resource group
        $environments = Get-AzContainerAppManagedEnv -ResourceGroupName $rg -ErrorAction SilentlyContinue

        if (-not $environments) {
            continue
        }

        foreach ($env in $environments) {
            Write-Host "Checking Container App Environment: $($env.Name) (RG: $rg)"

            # Get certificates in the environment
            $certs = Get-AzContainerAppManagedEnvCert -EnvName $env.Name -ResourceGroupName $rg -ErrorAction SilentlyContinue

            if (-not $certs) {
                Write-Host "  No certificates found in environment $($env.Name)"
                continue
            }

            foreach ($cert in $certs) {
                $expirationDate = $cert.ExpirationDate
                $isExpired = $false
                $daysUntilExpiry = $null

                if ($expirationDate) {
                    $daysUntilExpiry = [math]::Floor(($expirationDate - (Get-Date)).TotalDays)
                    $isExpired = $daysUntilExpiry -le $ExpirationThresholdDays
                }

                $results += [PSCustomObject]@{
                    AppType         = "ContainerApp"
                    AppName         = $env.Name
                    ResourceGroup   = $rg
                    HostName        = $cert.SubjectName
                    Thumbprint      = $cert.Thumbprint
                    SslState        = "Bound"
                    ExpirationDate  = $expirationDate
                    DaysUntilExpiry = $daysUntilExpiry
                    IsExpired       = $isExpired
                    Issuer          = $cert.Issuer
                    SubjectName     = $cert.SubjectName
                }
            }
        }
    }

    return $results
}

#endregion

#region --- Main ---

Write-Host "============================================="
Write-Host "SSL Certificate Expiration Check"
Write-Host "============================================="
Write-Host "Subscription : $SubscriptionId"
if ($ResourceGroupName) {
    Write-Host "Resource Group: $ResourceGroupName"
} else {
    Write-Host "Scope         : Entire Subscription"
}
Write-Host "Threshold Days: $ExpirationThresholdDays"
Write-Host "============================================="

# Set subscription context
Set-AzContext -SubscriptionId $SubscriptionId | Out-Null

# Determine which resource groups to scan
if ($ResourceGroupName) {
    $resourceGroups = @($ResourceGroupName)
} else {
    Write-Host "Enumerating all resource groups in subscription..."
    $resourceGroups = (Get-AzResourceGroup).ResourceGroupName
    Write-Host "Found $($resourceGroups.Count) resource groups."
}

# Collect certificates from Web Apps
$webAppCerts = Get-WebAppSSLCertificates -ResourceGroupNames $resourceGroups -AppNames $AppNames

# Collect certificates from Container Apps
$containerCerts = Get-ContainerAppSSLCertificates -ResourceGroupNames $resourceGroups -AppNames $AppNames

$allCerts = @()
$allCerts += $webAppCerts
$allCerts += $containerCerts

if ($allCerts.Count -eq 0) {
    Write-Host "No SSL certificates found."
    exit 0
}

# Display results
Write-Host "`nSSL Certificate Summary:"
Write-Host "------------------------"
$allCerts | Format-Table AppType, AppName, HostName, ExpirationDate, DaysUntilExpiry, IsExpired -AutoSize

# Filter expired/expiring certificates
$expiredCerts = $allCerts | Where-Object { $_.IsExpired -eq $true }

if ($expiredCerts.Count -gt 0) {
    Write-Warning "$($expiredCerts.Count) certificate(s) are expired or expiring within $ExpirationThresholdDays days!"
    $expiredCerts | Format-Table AppType, AppName, HostName, Thumbprint, ExpirationDate, DaysUntilExpiry -AutoSize

    # Export expired cert details as JSON for downstream jobs
    $expiredJson = $expiredCerts | ConvertTo-Json -Compress
    "ExpiredCerts=$expiredJson" | Out-File -FilePath $env:GITHUB_OUTPUT -Append
    "HasExpiredCerts=true" | Out-File -FilePath $env:GITHUB_OUTPUT -Append
}
else {
    Write-Host "`nAll certificates are valid."
    "HasExpiredCerts=false" | Out-File -FilePath $env:GITHUB_OUTPUT -Append
}

# Export full results
$allJson = $allCerts | ConvertTo-Json -Compress
"AllCerts=$allJson" | Out-File -FilePath $env:GITHUB_OUTPUT -Append

#endregion
