# SSL Expiration Check & Auto-Renewal Pipeline

Automated Azure DevOps pipeline that checks SSL certificate expiration on Azure Web Apps and Container Apps, finds renewed certificates in Key Vault, and rebinds them to App Service (ASE/ACE) and Application Gateway.

## Pipeline Flow

```
┌─────────────────────┐     ┌──────────────────────┐     ┌──────────────────────┐     ┌──────────┐
│  1. Check SSL       │────▶│  2. Search Key Vault │────▶│  3. Bind Renewed     │────▶│ 4. Notify│
│     Expiration      │     │     for Renewed Cert │     │     Certificates     │     │          │
│                     │     │                      │     │  (ASE/ACE + AppGW)   │     │          │
│  Scans Web Apps &   │     │  Runs only if        │     │  Runs only if        │     │  Always  │
│  Container Apps     │     │  expired certs found │     │  renewed certs found │     │  runs    │
└─────────────────────┘     └──────────────────────┘     └──────────────────────┘     └──────────┘
```

## Prerequisites

### Azure Service Connection
Create an Azure Resource Manager service connection in Azure DevOps with permissions to:
- **Read** App Service and Container App configurations
- **Read** Key Vault certificates and secrets
- **Write** App Service SSL bindings
- **Write** Application Gateway configuration

### Pipeline Variables
Set these variables in your pipeline (or variable group):

| Variable | Description | Required |
|----------|-------------|----------|
| `AzureServiceConnection` | Name of your Azure DevOps service connection | Yes |
| `ApprovalNotifyUsers` | Email(s) for manual approval notifications | Yes |

### Pipeline Parameters (set at run time)

| Parameter | Description | Default |
|-----------|-------------|---------|
| `subscriptionId` | Azure Subscription ID | — |
| `resourceGroupName` | Resource Group (empty = scan entire subscription) | *(empty)* |
| `keyVaultName` | Key Vault with renewed certs | — |
| `appGatewayName` | Application Gateway name | *(empty = skip)* |
| `appGatewayResourceGroup` | App Gateway RG (defaults to same RG) | *(empty)* |
| `expirationThresholdDays` | Treat as expired if within N days | `30` |
| `appNames` | Comma-separated app names (empty = all) | *(empty)* |

## Files

```
├── azure-pipelines.yml                 # Pipeline definition (4 stages)
└── scripts/
    ├── Check-SSLExpiration.ps1         # Stage 1: Scan SSL certs on Web/Container Apps
    ├── Find-RenewedCert.ps1           # Stage 2: Search Key Vault for valid replacements
    └── Bind-RenewedCert.ps1           # Stage 3: Bind new certs to ASE/ACE + App Gateway
```

## How It Works

### Stage 1 — Check SSL Expiration
- Scans all App Services and Container Apps across the entire subscription (or a specific Resource Group if provided)
- Collects SSL binding details: thumbprint, expiration date, hostname
- Marks certificates as expired if they're past expiry or within the threshold
- Outputs `HasExpiredCerts` and `ExpiredCerts` (JSON) for downstream stages

### Stage 2 — Search Key Vault
- Runs **only** if expired certificates were found
- For each expired cert, searches Key Vault for a certificate with matching subject name
- Skips certs with the same thumbprint (same old cert)
- Picks the cert with the longest remaining validity
- Outputs `HasRenewedCerts` and `RenewedCerts` (JSON)

### Stage 3 — Bind Renewed Certificates
- Runs **only** if renewed certificates were found in Key Vault
- **Manual approval gate** before making any changes
- For **Web Apps (ASE/ACE)**: imports the Key Vault cert and creates an SNI SSL binding
- For **Container Apps**: updates the managed environment certificate
- For **Application Gateway**: adds/updates the SSL certificate and updates the HTTPS listener
- Reports success/failure counts

### Stage 4 — Notification
- Always runs regardless of previous stage outcomes
- Summarizes the pipeline result:
  - **Healthy** — all certs valid
  - **ActionRequired** — expired certs found but no renewals in Key Vault
  - **Renewed** — certs successfully rebound
  - **Failed** — binding failed or approval was rejected

## Schedule

The pipeline runs automatically **every Monday at 6:00 AM UTC**. You can also trigger it manually from Azure DevOps.

## Service Principal Permissions

The service principal behind the Azure service connection needs:

```
Microsoft.Web/sites/Read
Microsoft.Web/sites/Write
Microsoft.Web/certificates/Read
Microsoft.Web/certificates/Write
Microsoft.KeyVault/vaults/certificates/read
Microsoft.KeyVault/vaults/secrets/read
Microsoft.Network/applicationGateways/read
Microsoft.Network/applicationGateways/write
Microsoft.App/managedEnvironments/read
Microsoft.App/managedEnvironments/certificates/read
Microsoft.App/managedEnvironments/certificates/write
```

Or assign **Contributor** on the Resource Group and **Key Vault Certificates Officer** + **Key Vault Secrets User** on the Key Vault.
