# Matii provider for the Secrets Store CSI Driver

Mounts secrets into pods as files on a tmpfs volume: they are never stored as
Kubernetes Secrets or in etcd. Each mount exchanges the pod's own projected
service account token (audience `matii-secret-service`) for a short-lived
Secret Service token through workload identity, so no credential is stored in
the cluster.

1. Install the Secrets Store CSI Driver with
   `tokenRequests[0].audience=matii-secret-service`.
2. Deploy the provider: `kubectl apply -f deploy/csi/provider.yaml` (set
   `MATII_ALLOWED_HOSTS`; mounts pointing at other hosts are refused).
3. In the Secret Service, create a Kubernetes OIDC identity for the pod's
   service account and attach it to a Matii service account with access to the
   environment.
4. Create a `SecretProviderClass` (`deploy/csi/example.yaml`) and mount it.

Parameters: `host`, `serviceAccountId`, `app`, `env` (required); `path`,
`audience`, `objects` (JSON list of `{key, file}`), `format` (`files`,
`dotenv`, `json`) and `fileName`. Values the service account may not reveal
are not mounted; asking for one by name fails the mount. File names are
restricted to `[A-Za-z0-9._-]`. Rotation: enable the driver's
`--enable-secret-rotation` to refresh mounted files.

Known advisory: GO-2026-6443 (grpc server panic on a missing authority
header) is fixed only in an unreleased grpc 1.85. The provider serves a
node-local Unix socket (mode 0600) reachable only by the CSI driver; upgrade
grpc when 1.85 is released.
