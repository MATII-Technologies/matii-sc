# Matii Secret Service clients

| Directory | What |
|---|---|
| `go/matii` | Go SDK: SSE and end-to-end encrypted apps, workload identity, fail-static cache |
| `go/cmd/adera` | `adera` CLI: `secrets list/get/export`, `run -- cmd` |
| `go/cmd/matii-operator` + `deploy/kubernetes` | Kubernetes operator: `MatiiSecret` → `Secret` |
| `action/` | GitHub Action: load secrets into a job with GitHub OIDC |
| `ts/` | TypeScript SDK (`@matii/secrets`) |
| `python/` | Python SDK (`matii-secrets`) |
| `terraform/` | Terraform / OpenTofu provider (`matii_secret`, `data.matii_secrets`) |
| `csi/` + `deploy/csi` | Secrets Store CSI Driver provider: secrets as files, never in etcd |

All clients read secrets the same way:

* **SSE apps:** `GET /v1/secrets/`; the server decrypts and applies `Secrets:reveal`.
* **End-to-end encrypted apps:** encrypted values are fetched and decrypted
  locally with the token's key shares. References such as `${KEY}`,
  `${env.KEY}` and `${app::env.KEY}` are resolved by the client.

## CLI

The `adera` CLI covers the whole secrets workflow: sign in, link a project,
read, write and import secrets, and run programs with secrets injected.

Install it with Go 1.26 or newer (macOS, Linux, Windows):

```bash
go install github.com/MATII-Technologies/matii-sc/go/cmd/adera@latest
adera version
```

The binary lands in `$(go env GOPATH)/bin`; add that folder to your `PATH`.
Pin a release with `@v1.0.0`.

```bash
adera auth login --host https://secrets.example.com   # browser sign-in; or --token to paste a token
adera init                                            # pick an app and default environment → .adera.json
adera secrets create DATABASE_URL                     # value from a hidden prompt or stdin
adera secrets create JWT_SECRET --random key256       # generated: hex|alphanumeric|base64|base64url|key128|key256
adera secrets list [--show]                           # table; values hidden unless --show
adera secrets get DATABASE_URL [--format json]
adera secrets update DATABASE_URL                     # new value; or --updated-path /db, --comment, --tags, --type
adera secrets update DATABASE_URL --override          # your personal value (people only); --toggle-override
adera secrets delete OLD_KEY OTHER_KEY
adera secrets import .env                             # creates new keys, updates existing ones
adera secrets export [KEYS...] --format dotenv|json|csv|yaml|xml|toml|hcl|ini|java_properties|kv|shell|github
adera run -- npm start                                # or: adera run "npm start"
adera shell                                           # a shell with the secrets in its environment
adera users whoami | switch | logout [--purge]        # several accounts can be signed in
adera console | docs | update | completion bash|zsh|fish
```

Every secrets command takes `--app APP` (or `--app-id`), `--env ENV` (a unique
prefix such as `prod` is enough), `--path /folder` and `--tags a,b`. Without
flags, `ADERA_APP` / `ADERA_APP_ID` / `ADERA_ENV` are used, then `.adera.json`
from `adera init`. `.adera.json` holds no secrets and can be committed; with
`adera init --monorepo` it also applies to subdirectories. Writes work for both
server-side and end-to-end encrypted apps; for end-to-end encrypted apps the
CLI encrypts locally before sending.

Accounts are stored in `~/.config/adera/credentials.json` (mode 0600).
Machines use a service account token or workload identity instead:

```bash
export ADERA_HOST=https://secrets.example.com
export ADERA_TOKEN=pss_service:v2:...          # or workload identity, below
adera secrets export --app Payments --env production --format dotenv
adera run --app Payments --env production -- ./server
adera dynamic list --app Payments --env production
adera dynamic lease deploy --app Payments --env production --ttl 30m     # temporary AWS credentials
adera dynamic leases deploy --app Payments --env production
adera run --app Payments --env production --dynamic deploy -- ./deploy.sh
```

## Releasing

Tag `go/vX.Y.Z` (for `go install` / Go modules) and `vX.Y.Z` to publish `adera_<os>_<arch>` binaries, `SHA256SUMS` and
`install.sh` as release assets (`.github/workflows/release.yml`). Mirror them
and set `MATII_CLI_DOWNLOAD_URL` on the console; users then run
`curl -fsSL https://<console>/cli/install.sh | sh`, which verifies the checksum.

**Workload identity (no stored token).** Set `ADERA_SERVICE_ACCOUNT_ID` and
either `ADERA_OIDC_TOKEN_FILE` (e.g. a Kubernetes projected token) or
`ADERA_OIDC_PROVIDER=github-actions`. The token is exchanged at
`/identities/external/v1/oidc/auth/` and refreshed before it expires.

Exit codes: 0 ok, 1 error, 2 usage, 3 authentication/authorization; `run` exits
with the command's own code.

## GitHub Action

```yaml
permissions: { id-token: write, contents: read }
steps:
  - uses: MATII-Technologies/matii-sc/action@v1
    with:
      host: https://secrets.example.com
      service-account-id: ${{ vars.MATII_SA_ID }}
      app: Payments
      env: production
  - run: ./deploy.sh   # secrets are in the environment, masked in logs
```

Values are masked line by line before they reach the job environment.

## Kubernetes operator

```bash
kubectl apply -f deploy/kubernetes/crd.yaml -f deploy/kubernetes/operator.yaml
kubectl apply -f deploy/kubernetes/example.yaml
```

For each `MatiiSecret`, the operator:

* requests a 10-minute token for the named ServiceAccount (TokenRequest API);
* exchanges it with the Secret Service, which decides what that ServiceAccount
  may read (a Kubernetes OIDC identity trusting
  `system:serviceaccount:NAMESPACE:NAME`);
* writes the target `Secret` with server-side apply;
* optionally restarts Deployments, StatefulSets or DaemonSets when the values
  change.

It never overwrites a Secret it does not manage. Enable etcd encryption at rest
for Secrets.

## SDKs

```go
tokens := &matii.OIDCTokenSource{APIBase: "https://secrets.example.com/service",
    ServiceAccountID: saID, JWT: matii.FileJWT("/var/run/secrets/tokens/matii")}
client, _ := matii.New(matii.Config{Host: "https://secrets.example.com", Tokens: tokens})
cached := &matii.CachedClient{Client: client, TTL: time.Minute, MaxStale: 15 * time.Minute}
dbURL, _, err := cached.Get(ctx, matii.Query{AppName: "Payments", Env: "production"}, "DATABASE_URL")
```

```ts
import { MatiiClient, toMap } from '@matii/secrets'
const client = new MatiiClient({ host: 'https://secrets.example.com', token: process.env.MATII_TOKEN })
const env = toMap(await client.secrets({ appName: 'Payments', env: 'production' }))
```

Secret values never appear in logs: `Secret.String()` and the token types
redact themselves.

## Development

```bash
(cd go && go vet ./... && go test ./...)
(cd ts && npm ci && npm test && npm run build)
```

See [PROVENANCE.md](PROVENANCE.md) for how this code was written and licensed.
