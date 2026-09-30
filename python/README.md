# matii-secrets (Python)

Client for the Matii Secret Service: server-side and end-to-end encrypted apps,
references, workload identity (OIDC) and dynamic credentials.

```python
import os
from matii_secrets import Client, oidc_token_source, file_jwt, to_dict

client = Client(host="https://secrets.example.com", token=os.environ["MATII_TOKEN"])
config = to_dict(client.secrets(app="Payments", env="production"))

# Workload identity instead of a stored token (e.g. a Kubernetes projected token):
tokens = oidc_token_source("https://secrets.example.com/service", os.environ["MATII_SERVICE_ACCOUNT_ID"],
                           file_jwt("/var/run/secrets/matii/token"))
client = Client(host="https://secrets.example.com", token_source=tokens)

# Short-lived AWS credentials:
lease = client.lease_dynamic("deploy", app="Payments", env="production", ttl_seconds=1800)
```

Values the caller may list but not reveal come back with `redacted=True` and
an empty value. `repr()` of secrets, leases, tokens and key pairs never shows
secret material. Tests: `pip install -e .[test] && pytest`.
