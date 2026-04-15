# SSL Expiration Check & Auto-Renewal Pipeline

GitHub Actions workflow that checks SSL certificate expiration on Azure Web Apps and Container Apps, finds renewed certificates in Key Vault, and rebinds them to App Service (ASE/ACE) and Application Gateway.

## Workflow Flow

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

### Azure Credentials
Create a service principal and store its credentials as a GitHub repository secret named `AZURE_CREDENTIALS` (JSON format from `az ad sp create-for-rbac`). The service principal needs permissions to:
- **Read** App Service and Container App configurations
- **Read** Key Vault certificates and secrets
- **Write** App Service SSL bindings
- **Write** Application Gateway configuration

### GitHub Repository Configuration

**Secrets** (Settings → Secrets and variables → Actions):

| Secret | Description | Required |
|--------|-------------|----------|
| `AZURE_CREDENTIALS` | Service principal credentials JSON (`az ad sp create-for-rbac --sdk-auth`) | Yes |

**Variables** (Settings → Secrets and variables → Actions → Variables):

| Variable | Description | Required |
|----------|-------------|----------|
| `AZURE_SUBSCRIPTION_ID` | Default Azure Subscription ID (used for scheduled runs) | For scheduled runs |
| `AZURE_KEY_VAULT_NAME` | Default Key Vault name (used for scheduled runs) | For scheduled runs |

**Environment** (Settings → Environments):

Create an environment named `production` with **required reviewers** to enable the manual approval gate before certificate binding.

### Workflow Inputs (set when triggering manually)

| Input | Description | Default |
|-------|-------------|---------|
| `subscriptionId` | Azure Subscription ID | — |
| `resourceGroupName` | Resource Group (empty = scan entire subscription) | *(empty)* |
| `keyVaultName` | Key Vault with renewed certs | — |
| `appGatewayName` | Application Gateway name | *(empty = skip)* |
| `appGatewayResourceGroup` | App Gateway RG (defaults to same RG) | *(empty)* |
| `expirationThresholdDays` | Treat as expired if within N days | `30` |
| `appNames` | Comma-separated app names (empty = all) | *(empty)* |

## Files

```
├── .github/workflows/
│   └── ssl-check-and-renew.yml        # GitHub Actions workflow (4 jobs)
└── scripts/
    ├── Check-SSLExpiration.ps1         # Job 1: Scan SSL certs on Web/Container Apps
    ├── Find-RenewedCert.ps1           # Job 2: Search Key Vault for valid replacements
    └── Bind-RenewedCert.ps1           # Job 3: Bind new certs to ASE/ACE + App Gateway
```

## How It Works

### Job 1 — Check SSL Expiration
- Scans all App Services and Container Apps across the entire subscription (or a specific Resource Group if provided)
- Collects SSL binding details: thumbprint, expiration date, hostname
- Marks certificates as expired if they're past expiry or within the threshold
- Outputs `has_expired_certs` and `expired_certs` (JSON) for downstream jobs

### Job 2 — Search Key Vault
- Runs **only** if expired certificates were found
- For each expired cert, searches Key Vault for a certificate with matching subject name
- Skips certs with the same thumbprint (same old cert)
- Picks the cert with the longest remaining validity
- Outputs `has_renewed_certs` and `renewed_certs` (JSON)

### Job 3 — Bind Renewed Certificates
- Runs **only** if renewed certificates were found in Key Vault
- **Manual approval gate** via GitHub Environment protection rules (`production` environment)
- For **Web Apps (ASE/ACE)**: imports the Key Vault cert and creates an SNI SSL binding
- For **Container Apps**: updates the managed environment certificate
- For **Application Gateway**: adds/updates the SSL certificate and updates the HTTPS listener
- Reports success/failure counts

### Job 4 — Notification
- Always runs regardless of previous job outcomes
- Writes a summary to the **GitHub Actions Job Summary**
- Reports the pipeline result:
  - **Healthy** — all certs valid
  - **ActionRequired** — expired certs found but no renewals in Key Vault
  - **Renewed** — certs successfully rebound
  - **Failed** — binding failed or approval was rejected

## Schedule

The workflow runs automatically **every Monday at 6:00 AM UTC**. You can also trigger it manually via **Actions → SSL Expiration Check & Auto-Renewal → Run workflow**.

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
