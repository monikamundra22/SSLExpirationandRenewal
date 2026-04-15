<#
.SYNOPSIS
    Interactive script to find SSL certificates expiring within 30 days
    on custom domains of Azure Web Apps and Container Apps.

.DESCRIPTION
    Presents an interactive subscription picker, then scans all Web Apps
    and Azure Container Apps for custom-domain SSL certificates that expire
    within 30 days.

.PARAMETER ExpirationThresholdDays
    Number of days to look ahead for expiring certificates. Defaults to 30.
#>

param(
    [Parameter(Mandatory = $false)]
    [int]$ExpirationThresholdDays = 30
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

#region --- Subscription Selection ---

function Select-AzureSubscription {
    <#
    .SYNOPSIS
        Lists available Azure subscriptions and lets the user pick one.
    #>

    $subscriptions = Get-AzSubscription -ErrorAction Stop |
        Where-Object { $_.State -eq "Enabled" } |
        Sort-Object Name

    if ($subscriptions.Count -eq 0) {
        Write-Error "No enabled Azure subscriptions found. Make sure you are logged in (Connect-AzAccount)."
        exit 1
    }

    Write-Host "`n========================================="
    Write-Host " Available Azure Subscriptions"
    Write-Host "========================================="

    for ($i = 0; $i -lt $subscriptions.Count; $i++) {
        Write-Host ("  [{0}] {1}  ({2})" -f ($i + 1), $subscriptions[$i].Name, $subscriptions[$i].Id)
    }

    Write-Host ""
    do {
        $selection = Read-Host "Select a subscription (1-$($subscriptions.Count))"
        $index = 0
        $valid = [int]::TryParse($selection, [ref]$index) -and $index -ge 1 -and $index -le $subscriptions.Count
        if (-not $valid) {
            Write-Warning "Invalid selection. Please enter a number between 1 and $($subscriptions.Count)."
        }
    } while (-not $valid)

    return $subscriptions[$index - 1]
}

#endregion

#region --- Certificate Collection ---

function Get-WebAppExpiringCerts {
    <#
    .SYNOPSIS
        Scans all Web Apps for custom-domain SSL certs expiring within the threshold.
    #>
    param(
        [string[]]$ResourceGroupNames,
        [int]$ThresholdDays
    )

    $results = @()

    foreach ($rg in $ResourceGroupNames) {
        $webApps = Get-AzWebApp -ResourceGroupName $rg -ErrorAction SilentlyContinue
        if (-not $webApps) { continue }

        foreach ($app in $webApps) {
            $appRg = $app.ResourceGroup
            Write-Host "  Scanning Web App: $($app.Name) (RG: $appRg)" -ForegroundColor Gray

            $sslBindings = $app.HostNameSslStates | Where-Object {
                $_.SslState -ne 'Disabled' -and $_.Thumbprint
            }

            if (-not $sslBindings -or $sslBindings.Count -eq 0) { continue }

            foreach ($binding in $sslBindings) {
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

                if (-not $expirationDate) { continue }

                $daysUntilExpiry = [math]::Floor(($expirationDate - (Get-Date)).TotalDays)

                if ($daysUntilExpiry -le $ThresholdDays) {
                    $results += [PSCustomObject]@{
                        AppType         = "WebApp"
                        AppName         = $app.Name
                        ResourceGroup   = $appRg
                        CustomDomain    = $binding.Name
                        Thumbprint      = $binding.Thumbprint
                        SubjectName     = $subjectName
                        Issuer          = $issuer
                        ExpirationDate  = $expirationDate
                        DaysUntilExpiry = $daysUntilExpiry
                    }
                }
            }
        }
    }

    return $results
}

function Get-ContainerAppExpiringCerts {
    <#
    .SYNOPSIS
        Scans all Container App environments for SSL certs expiring within the threshold.
    #>
    param(
        [string[]]$ResourceGroupNames,
        [int]$ThresholdDays
    )

    $results = @()

    foreach ($rg in $ResourceGroupNames) {
        $environments = Get-AzContainerAppManagedEnv -ResourceGroupName $rg -ErrorAction SilentlyContinue
        if (-not $environments) { continue }

        foreach ($env in $environments) {
            Write-Host "  Scanning Container App Environment: $($env.Name) (RG: $rg)" -ForegroundColor Gray

            $certs = Get-AzContainerAppManagedEnvCert -EnvName $env.Name -ResourceGroupName $rg -ErrorAction SilentlyContinue
            if (-not $certs) { continue }

            foreach ($cert in $certs) {
                $expirationDate = $cert.ExpirationDate
                if (-not $expirationDate) { continue }

                $daysUntilExpiry = [math]::Floor(($expirationDate - (Get-Date)).TotalDays)

                if ($daysUntilExpiry -le $ThresholdDays) {
                    $results += [PSCustomObject]@{
                        AppType         = "ContainerApp"
                        AppName         = $env.Name
                        ResourceGroup   = $rg
                        CustomDomain    = $cert.SubjectName
                        Thumbprint      = $cert.Thumbprint
                        SubjectName     = $cert.SubjectName
                        Issuer          = $cert.Issuer
                        ExpirationDate  = $expirationDate
                        DaysUntilExpiry = $daysUntilExpiry
                    }
                }
            }
        }
    }

    return $results
}

#endregion

#region --- Main ---

Write-Host "`n============================================="
Write-Host " SSL Certificate Expiration Scanner"
Write-Host " (Custom Domains - Web Apps & Container Apps)"
Write-Host "=============================================`n"

# Ensure Az module is available
if (-not (Get-Module -ListAvailable -Name Az.Accounts)) {
    Write-Error "Az PowerShell module is not installed. Run: Install-Module -Name Az -Scope CurrentUser"
    exit 1
}

# Check if already logged in; if not, prompt login
$context = Get-AzContext -ErrorAction SilentlyContinue
if (-not $context) {
    Write-Host "No active Azure session found. Launching login..."
    Connect-AzAccount | Out-Null
}

# Let user pick a subscription
$subscription = Select-AzureSubscription
Write-Host "`nSelected: $($subscription.Name) ($($subscription.Id))" -ForegroundColor Cyan
Set-AzContext -SubscriptionId $subscription.Id | Out-Null

# Enumerate resource groups
Write-Host "`nEnumerating resource groups..."
$resourceGroups = (Get-AzResourceGroup).ResourceGroupName
Write-Host "Found $($resourceGroups.Count) resource group(s). Scanning for expiring certificates (threshold: $ExpirationThresholdDays days)...`n"

# Scan Web Apps
Write-Host "[Web Apps]" -ForegroundColor Yellow
$webAppCerts = Get-WebAppExpiringCerts -ResourceGroupNames $resourceGroups -ThresholdDays $ExpirationThresholdDays

# Scan Container Apps
Write-Host "`n[Container Apps]" -ForegroundColor Yellow
$containerCerts = Get-ContainerAppExpiringCerts -ResourceGroupNames $resourceGroups -ThresholdDays $ExpirationThresholdDays

# Combine results
$allExpiring = @()
$allExpiring += $webAppCerts
$allExpiring += $containerCerts

# Display results
Write-Host "`n============================================="
Write-Host " Results - Certificates Expiring Within $ExpirationThresholdDays Days"
Write-Host "=============================================`n"

if ($allExpiring.Count -eq 0) {
    Write-Host "No certificates expiring within $ExpirationThresholdDays days. All clear!" -ForegroundColor Green
}
else {
    Write-Warning "$($allExpiring.Count) certificate(s) expiring within $ExpirationThresholdDays days!`n"

    $allExpiring |
        Sort-Object DaysUntilExpiry |
        Format-Table AppType, AppName, CustomDomain, ExpirationDate,
                     @{Label = "Days Left"; Expression = { $_.DaysUntilExpiry }},
                     Issuer, Thumbprint -AutoSize

    # Export to CSV on the user's desktop
    $csvPath = Join-Path ([Environment]::GetFolderPath("Desktop")) "ExpiringCerts_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $allExpiring | Export-Csv -Path $csvPath -NoTypeInformation
    Write-Host "Results exported to: $csvPath" -ForegroundColor Cyan
}

Write-Host "`nDone.`n"

#endregion
