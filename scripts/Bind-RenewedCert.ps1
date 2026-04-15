<#
.SYNOPSIS
    Binds renewed SSL certificates to App Service (ASE/ACE) and Application Gateway.

.DESCRIPTION
    Takes renewed certificate details and:
    1. Imports the cert from Key Vault into App Service
    2. Updates SSL bindings on the Web App (ASE/ACE)
    3. Updates the Application Gateway HTTPS listener with the new cert

.PARAMETER RenewedCertsJson
    JSON string of renewed certificate details from Find-RenewedCert.ps1.

.PARAMETER AppGatewayName
    Name of the Application Gateway to update.

.PARAMETER AppGatewayResourceGroup
    Resource Group of the Application Gateway.

.PARAMETER KeyVaultName
    Name of the Key Vault containing the renewed certificates.
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$RenewedCertsJson,

    [Parameter(Mandatory = $false)]
    [string]$AppGatewayName,

    [Parameter(Mandatory = $false)]
    [string]$AppGatewayResourceGroup,

    [Parameter(Mandatory = $true)]
    [string]$KeyVaultName
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

#region --- Functions ---

function Update-AppServiceSSLBinding {
    <#
    .SYNOPSIS
        Imports a Key Vault certificate and binds it to an App Service hostname.
    #>
    param(
        [PSCustomObject]$CertInfo,
        [string]$KeyVaultName
    )

    $appName = $CertInfo.AppName
    $resourceGroup = $CertInfo.ResourceGroup
    $hostName = $CertInfo.HostName
    $kvCertName = $CertInfo.KeyVaultCertName
    $newThumbprint = $CertInfo.NewThumbprint

    Write-Host "  Importing certificate '$kvCertName' from Key Vault to App Service..."

    # Import the Key Vault certificate into App Service
    $importedCert = New-AzWebAppSSLBinding `
        -ResourceGroupName $resourceGroup `
        -WebAppName $appName `
        -Name $hostName `
        -KeyVaultId (Get-AzKeyVault -VaultName $KeyVaultName).ResourceId `
        -KeyVaultCertName $kvCertName `
        -SslState "SniEnabled"

    if ($importedCert) {
        Write-Host "  Successfully bound certificate to $hostName on $appName"
        Write-Host "    Thumbprint: $newThumbprint"
        return $true
    }
    else {
        Write-Error "  Failed to bind certificate to $hostName on $appName"
        return $false
    }
}

function Update-ContainerAppSSLBinding {
    <#
    .SYNOPSIS
        Updates SSL certificate on a Container App environment.
    #>
    param(
        [PSCustomObject]$CertInfo,
        [string]$KeyVaultName
    )

    $envName = $CertInfo.AppName
    $resourceGroup = $CertInfo.ResourceGroup
    $kvCertName = $CertInfo.KeyVaultCertName

    Write-Host "  Updating Container App Environment '$envName' certificate..."

    # Get the Key Vault certificate secret URI
    $kvCert = Get-AzKeyVaultCertificate -VaultName $KeyVaultName -Name $kvCertName
    $secretId = $kvCert.SecretId

    # Create/update the managed certificate in the Container App Environment
    $certParams = @{
        EnvName           = $envName
        ResourceGroupName = $resourceGroup
        Name              = $kvCertName
        KeyVaultUrl       = $secretId
    }

    $result = New-AzContainerAppManagedEnvCert @certParams

    if ($result) {
        Write-Host "  Successfully updated certificate in Container App Environment: $envName"
        return $true
    }
    else {
        Write-Error "  Failed to update certificate in Container App Environment: $envName"
        return $false
    }
}

function Update-ApplicationGatewaySSL {
    <#
    .SYNOPSIS
        Updates Application Gateway HTTPS listeners with renewed certificates.
    #>
    param(
        [string]$AppGatewayName,
        [string]$AppGatewayResourceGroup,
        [PSCustomObject[]]$CertInfos,
        [string]$KeyVaultName
    )

    Write-Host "`nUpdating Application Gateway: $AppGatewayName"
    Write-Host "  Resource Group: $AppGatewayResourceGroup"

    # Get the Application Gateway
    $appGw = Get-AzApplicationGateway `
        -Name $AppGatewayName `
        -ResourceGroupName $AppGatewayResourceGroup

    if (-not $appGw) {
        Write-Error "Application Gateway '$AppGatewayName' not found."
        return $false
    }

    $updated = $false

    foreach ($certInfo in $CertInfos) {
        $kvCertName = $certInfo.KeyVaultCertName
        $hostName = $certInfo.HostName
        $secretId = $certInfo.KeyVaultSecretId

        Write-Host "  Processing certificate for hostname: $hostName"

        # Find matching HTTPS listeners by hostname
        $listeners = $appGw.HttpListeners | Where-Object {
            $_.Protocol -eq "Https" -and (
                $_.HostName -eq $hostName -or
                $_.HostNames -contains $hostName
            )
        }

        if (-not $listeners -or $listeners.Count -eq 0) {
            # Try matching by existing SSL certificate on any HTTPS listener
            Write-Host "    No hostname-matched listener found, checking all HTTPS listeners..."
            $listeners = $appGw.HttpListeners | Where-Object {
                $_.Protocol -eq "Https"
            }
        }

        if (-not $listeners -or $listeners.Count -eq 0) {
            Write-Warning "    No HTTPS listeners found on Application Gateway"
            continue
        }

        foreach ($listener in $listeners) {
            $listenerName = $listener.Name
            Write-Host "    Updating listener: $listenerName"

            # Check if a matching SSL cert already exists on the App GW
            $existingSslCert = $appGw.SslCertificates | Where-Object {
                $_.Name -like "*$kvCertName*" -or $_.KeyVaultSecretId -eq $secretId
            }

            $sslCertName = "kv-$kvCertName"

            if ($existingSslCert) {
                # Update the existing SSL certificate reference
                Write-Host "    Updating existing SSL certificate: $($existingSslCert.Name)"
                $appGw = Set-AzApplicationGatewaySslCertificate `
                    -ApplicationGateway $appGw `
                    -Name $existingSslCert.Name `
                    -KeyVaultSecretId $secretId
                $sslCertName = $existingSslCert.Name
            }
            else {
                # Add a new SSL certificate to the App Gateway from Key Vault
                Write-Host "    Adding new SSL certificate: $sslCertName"
                $appGw = Add-AzApplicationGatewaySslCertificate `
                    -ApplicationGateway $appGw `
                    -Name $sslCertName `
                    -KeyVaultSecretId $secretId
            }

            # Get the updated SSL cert object
            $sslCertRef = $appGw.SslCertificates | Where-Object { $_.Name -eq $sslCertName }

            if ($sslCertRef) {
                # Update the listener to use the new SSL cert
                $appGw = Set-AzApplicationGatewayHttpListener `
                    -ApplicationGateway $appGw `
                    -Name $listenerName `
                    -Protocol Https `
                    -FrontendIPConfiguration $listener.FrontendIpConfiguration `
                    -FrontendPort $listener.FrontendPort `
                    -SslCertificate $sslCertRef `
                    -HostName $hostName

                $updated = $true
                Write-Host "    Successfully updated listener '$listenerName' with new certificate"
            }
        }
    }

    if ($updated) {
        Write-Host "  Applying Application Gateway configuration..."
        $appGw = Set-AzApplicationGateway -ApplicationGateway $appGw
        Write-Host "  Application Gateway updated successfully."
        return $true
    }
    else {
        Write-Warning "  No changes were made to the Application Gateway."
        return $false
    }
}

#endregion

#region --- Main ---

Write-Host "============================================="
Write-Host "SSL Certificate Binding Update"
Write-Host "============================================="
Write-Host "Key Vault: $KeyVaultName"
if ($AppGatewayName) {
    Write-Host "App Gateway: $AppGatewayName ($AppGatewayResourceGroup)"
}
Write-Host "============================================="

$renewedCerts = $RenewedCertsJson | ConvertFrom-Json

if (-not $renewedCerts -or $renewedCerts.Count -eq 0) {
    Write-Host "No renewed certificates to bind."
    exit 0
}

$successCount = 0
$failCount = 0

# --- Step 1: Update App Service / Container App bindings ---
Write-Host "`n--- Updating App Service / Container App Bindings ---"

foreach ($cert in $renewedCerts) {
    Write-Host "`nProcessing: $($cert.AppName) - $($cert.HostName)"

    try {
        $result = $false

        switch ($cert.AppType) {
            "WebApp" {
                $result = Update-AppServiceSSLBinding -CertInfo $cert -KeyVaultName $KeyVaultName
            }
            "ContainerApp" {
                $result = Update-ContainerAppSSLBinding -CertInfo $cert -KeyVaultName $KeyVaultName
            }
            default {
                Write-Warning "  Unknown app type: $($cert.AppType)"
            }
        }

        if ($result) {
            $successCount++
        }
        else {
            $failCount++
        }
    }
    catch {
        Write-Error "  Error updating $($cert.AppName): $_"
        $failCount++
    }
}

# --- Step 2: Update Application Gateway ---
if ($AppGatewayName -and $AppGatewayResourceGroup) {
    Write-Host "`n--- Updating Application Gateway ---"

    try {
        $gwResult = Update-ApplicationGatewaySSL `
            -AppGatewayName $AppGatewayName `
            -AppGatewayResourceGroup $AppGatewayResourceGroup `
            -CertInfos $renewedCerts `
            -KeyVaultName $KeyVaultName

        if ($gwResult) {
            Write-Host "Application Gateway update completed successfully."
        }
    }
    catch {
        Write-Error "Error updating Application Gateway: $_"
        $failCount++
    }
}
else {
    Write-Host "`nSkipping Application Gateway update (no gateway specified)."
}

# --- Summary ---
Write-Host "`n============================================="
Write-Host "Binding Update Summary"
Write-Host "============================================="
Write-Host "Successful: $successCount"
Write-Host "Failed    : $failCount"
Write-Host "============================================="

if ($failCount -gt 0) {
    Write-Error "Some certificate bindings failed. Review the logs above."
    exit 1
}

Write-Host "All certificate bindings updated successfully."

#endregion
