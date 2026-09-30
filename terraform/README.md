# Terraform / OpenTofu provider for the Matii Secret Service

```hcl
terraform {
  required_providers {
    matii = { source = "matii-org/matii" }
  }
}

provider "matii" {
  host = "https://secrets.example.com"   # or MATII_HOST
  # token = "pss_service:v2:..."         # or MATII_TOKEN; or workload identity:
  # service_account_id = "..."           # MATII_SERVICE_ACCOUNT_ID
  # oidc_token_file    = "/var/run/..."  # MATII_OIDC_TOKEN_FILE
}

# Read an environment (server-side or end-to-end encrypted apps).
data "matii_secrets" "prod" {
  app  = "Payments"
  env  = "production"
  path = "/backend"          # optional
}

# Manage a secret (server-side encrypted apps).
resource "matii_secret" "db" {
  app     = "Payments"
  env     = "production"
  path    = "/backend"
  key     = "DATABASE_URL"   # upper-case
  value   = var.database_url
  comment = "managed by terraform"
}
```

`data.matii_secrets.prod.values` is a sensitive map. Values end up in the
Terraform state: store state encrypted and restrict who can read it. Import an
existing secret with `terraform import matii_secret.db Payments/production/backend/DATABASE_URL`.

Build: `go build -o terraform-provider-matii .`, then install it through a
[filesystem mirror](https://opentofu.org/docs/cli/config/config-file/#provider-installation)
until the provider is published to a registry. Tests (`TF_ACC=1`,
`TF_ACC_TERRAFORM_PATH=<terraform or tofu>`) run real plans against an
in-memory API.
