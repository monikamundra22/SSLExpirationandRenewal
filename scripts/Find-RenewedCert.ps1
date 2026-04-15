<#
.SYNOPSIS
    Checks Azure Key Vault for renewed SSL certificates matching expired ones.

.DESCRIPTION
    For each expired certificate, searches the specified Key Vault for a newer
    certificate with a matching subject name. Returns details of renewed certs
    ready for binding.

.PARAMETER KeyVaultName
    Name of the Azure Key Vault to search for renewed certificates.

.PARAMETER ExpiredCertsJson
    JSON string of expired certificate details from Check-SSLExpiration.ps1.
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$KeyVaultName,

    [Parameter(Mandatory = $true)]
    [string]$ExpiredCertsJson
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

#region --- Functions ---

function Find-RenewedCertInKeyVault {
    <#
    .SYNOPSIS
        Searches Key Vault for a valid (non-expired) certificate matching the subject.
    #>
    param(
        [string]$KeyVaultName,
        [string]$SubjectName,
        [string]$OldThumbprint
    )

    # Get all certificates from Key Vault
    $kvCerts = Get-AzKeyVaultCertificate -VaultName $KeyVaultName

    $matchingCerts = @()

    foreach ($kvCert in $kvCerts) {
        # Get the full certificate details
        $certDetail = Get-AzKeyVaultCertificate -VaultName $KeyVaultName -Name $kvCert.Name

        if (-not $certDetail -or -not $certDetail.Certificate) {
            continue
        }

        $x509 = $certDetail.Certificate

        # Match by subject name (normalize CN= prefix)
        $kvSubject = $x509.Subject -replace "^CN=", ""
        $targetSubject = $SubjectName -replace "^CN=", ""

        # Support wildcard matching (e.g. *.example.com matches example.com certs)
        $isMatch = ($kvSubject -eq $targetSubject) -or
                   ($kvSubject -like "*$targetSubject*") -or
                   ($targetSubject -like "*$kvSubject*")

        if (-not $isMatch) {
            continue
        }

        # Skip if same thumbprint as the expired cert
        if ($x509.Thumbprint -eq $OldThumbprint) {
            Write-Host "  Skipping same certificate (thumbprint match): $($kvCert.Name)"
            continue
        }

        # Check if this cert is still valid
        if ($x509.NotAfter -gt (Get-Date)) {
            $matchingCerts += [PSCustomObject]@{
                KeyVaultCertName = $kvCert.Name
                SecretId         = $certDetail.SecretId
                CertId           = $certDetail.Id
                Thumbprint       = $x509.Thumbprint
                Subject          = $x509.Subject
                NotBefore        = $x509.NotBefore
                NotAfter         = $x509.NotAfter
                DaysRemaining    = [math]::Floor(($x509.NotAfter - (Get-Date)).TotalDays)
            }
        }
    }

    if ($matchingCerts.Count -gt 0) {
        # Return the certificate with the latest expiration
        return $matchingCerts | Sort-Object NotAfter -Descending | Select-Object -First 1
    }

    return $null
}

#endregion

#region --- Main ---

Write-Host "============================================="
Write-Host "Key Vault Certificate Renewal Check"
Write-Host "============================================="
Write-Host "Key Vault: $KeyVaultName"
Write-Host "============================================="

$expiredCerts = $ExpiredCertsJson | ConvertFrom-Json

if (-not $expiredCerts -or $expiredCerts.Count -eq 0) {
    Write-Host "No expired certificates to process."
    Write-Host "##vso[task.setvariable variable=HasRenewedCerts;isOutput=true]false"
    exit 0
}

$renewalResults = @()

foreach ($expired in $expiredCerts) {
    Write-Host "`nSearching Key Vault for renewed cert matching: $($expired.SubjectName)"
    Write-Host "  Old Thumbprint: $($expired.Thumbprint)"
    Write-Host "  Host: $($expired.HostName)"

    $renewed = Find-RenewedCertInKeyVault `
        -KeyVaultName $KeyVaultName `
        -SubjectName $expired.SubjectName `
        -OldThumbprint $expired.Thumbprint

    if ($renewed) {
        Write-Host "  [FOUND] Renewed certificate: $($renewed.KeyVaultCertName)"
        Write-Host "    New Thumbprint : $($renewed.Thumbprint)"
        Write-Host "    Valid Until    : $($renewed.NotAfter)"
        Write-Host "    Days Remaining : $($renewed.DaysRemaining)"

        $renewalResults += [PSCustomObject]@{
            # Original cert info
            AppType            = $expired.AppType
            AppName            = $expired.AppName
            ResourceGroup      = $expired.ResourceGroup
            HostName           = $expired.HostName
            OldThumbprint      = $expired.Thumbprint
            OldExpirationDate  = $expired.ExpirationDate
            # New cert info from Key Vault
            KeyVaultCertName   = $renewed.KeyVaultCertName
            KeyVaultSecretId   = $renewed.SecretId
            KeyVaultCertId     = $renewed.CertId
            NewThumbprint      = $renewed.Thumbprint
            NewExpirationDate  = $renewed.NotAfter
            NewDaysRemaining   = $renewed.DaysRemaining
        }
    }
    else {
        Write-Warning "  [NOT FOUND] No renewed certificate found for: $($expired.SubjectName)"
    }
}

if ($renewalResults.Count -gt 0) {
    Write-Host "`n============================================="
    Write-Host "Renewed Certificates Found: $($renewalResults.Count)"
    Write-Host "============================================="
    $renewalResults | Format-Table AppName, HostName, KeyVaultCertName, NewThumbprint, NewExpirationDate -AutoSize

    $renewedJson = $renewalResults | ConvertTo-Json -Compress
    Write-Host "##vso[task.setvariable variable=RenewedCerts;isOutput=true]$renewedJson"
    Write-Host "##vso[task.setvariable variable=HasRenewedCerts;isOutput=true]true"
}
else {
    Write-Warning "No renewed certificates found in Key Vault for any expired certificate."
    Write-Host "##vso[task.setvariable variable=HasRenewedCerts;isOutput=true]false"
}

#endregion
