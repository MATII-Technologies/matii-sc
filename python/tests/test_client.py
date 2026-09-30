import io
import json
import pathlib
import urllib.error

import pytest

from matii_secrets import ApiError, Client, oidc_token_source, parse_token, to_dict, to_dotenv
from matii_secrets.crypto import encrypt_asymmetric, kx_seed_keypair, recover_token_key

V = json.loads((pathlib.Path(__file__).parents[2] / "go/matii/testdata/vectors.json").read_text())


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class Server:
    def __init__(self, routes):
        self.routes, self.requests = routes, []

    def __call__(self, req, timeout=None):
        self.requests.append(req)
        url = req.full_url.split("?")[0]
        handler = self.routes.get((req.get_method(), url))
        if handler is None:
            raise urllib.error.HTTPError(req.full_url, 404, "Not Found", {}, io.BytesIO(b'{"error":"nope"}'))
        status, body = handler(req) if callable(handler) else handler
        if status >= 400:
            raise urllib.error.HTTPError(req.full_url, status, "err", {}, io.BytesIO(json.dumps(body).encode()))
        return FakeResponse(json.dumps(body).encode())


BASE = "http://localhost:8000/service"


def e2ee_world():
    env = kx_seed_keypair(bytes.fromhex(V["env_seed"]))
    first = V["secrets"][0]
    boot = {"wrapped_key_share": V["wrapped_key_share"], "apps": [
        {"id": "a1", "name": "Mobile", "encryption": "E2E", "environment_keys": [
            {"environment": {"id": "e1", "name": "production"}, "wrapped_seed": V["wrapped_seed"], "wrapped_salt": V["wrapped_salt"]}]},
        {"id": "a2", "name": "Billing", "encryption": "SSE", "environment_keys": [{"environment": {"id": "e2", "name": "production"}}]},
    ]}
    items = [{"key": s["key_ciphertext"], "value": s["value_ciphertext"], "path": "/", "comment": ""} for s in V["secrets"]]
    items.append({"key": encrypt_asymmetric("REF", env.public), "value": encrypt_asymmetric("x-${%s}-y" % first["key"], env.public),
                  "path": "/", "comment": ""})
    return Server({
        ("GET", f"{BASE}/secrets/tokens/"): (200, boot),
        ("GET", f"{BASE}/secrets/"): (200, items),
        ("GET", f"{BASE}/v1/secrets/"): (200, [{"key": "K", "value": "v", "path": "/"},
                                             {"key": "HIDDEN", "value": None, "path": "/", "valueRedacted": True}]),
        ("POST", f"{BASE}/v1/dynamic-secrets/lease/"): lambda req: (
            201, {"leaseId": "l1", "expiresAt": "2030-01-01T00:00:00Z", "credentials": {"AWS_ACCESS_KEY_ID": "ASIA"},
                  "echo": json.loads(req.data)}),
    }), first


def test_e2ee_secrets_decrypt_and_resolve_references():
    server, first = e2ee_world()
    client = Client(host="http://localhost:8000", token=V["token"], opener=server)
    values = to_dict(client.secrets(app="mobile", env="Production"))
    for s in V["secrets"]:
        assert values[s["key"]] == s["value"]
    assert values["REF"] == f"x-{first['value']}-y"
    assert server.requests[1].get_header("Environment") == "e1"
    assert server.requests[0].get_header("Authorization") == f"Bearer ServiceAccount {parse_token(V['token']).value}"
    assert "<redacted>" in repr(client.secrets(app="Mobile", env="production")[0])


def test_sse_secrets_and_redaction():
    server, _ = e2ee_world()
    client = Client(host="http://localhost:8000", token=V["token"], opener=server)
    secrets = client.secrets(app="Billing", env="production")
    assert to_dict(secrets) == {"K": "v"}
    assert to_dotenv(secrets) == 'K="v"\n'
    assert client.get("HIDDEN", app="Billing", env="production") is None


def test_dynamic_lease_and_errors():
    server, _ = e2ee_world()
    client = Client(host="http://localhost:8000", token=V["token"], opener=server)
    lease = client.lease_dynamic("deploy", app="Billing", env="production", path="/ops", ttl_seconds=1800)
    assert lease.credentials == {"AWS_ACCESS_KEY_ID": "ASIA"} and lease.expires_at.year == 2030
    req = server.requests[-1]
    assert "app_id=a2" in req.full_url and json.loads(req.data) == {"name": "deploy", "path": "/ops", "ttlSeconds": 1800}
    assert "ASIA" not in repr(lease)
    server.routes[("POST", f"{BASE}/v1/dynamic-secrets/lease/")] = (403, {"error": "reveal needed"})
    with pytest.raises(ApiError) as exc:
        client.lease_dynamic("deploy", app="Billing", env="production")
    assert exc.value.status == 403 and "reveal needed" in str(exc.value)
    with pytest.raises(ApiError):
        client.secrets(app="Unknown", env="production")


def test_client_refuses_plain_http_and_bad_tokens():
    with pytest.raises(ValueError):
        Client(host="http://secrets.example.com", token=V["token"])
    with pytest.raises(ValueError):
        Client(host="https://secrets.example.com", token="pss_service:v1:x")


def test_oidc_token_source_exchanges_and_caches():
    calls = []

    def opener(req, timeout=None):
        calls.append(json.loads(req.data))
        return FakeResponse(json.dumps({"authentication": {"token": V["token"], "TTL": 600}}).encode())

    source = oidc_token_source("https://secrets.example.com/service", "sa-1", lambda: "workload-jwt", opener=opener)
    assert source() == V["token"] and source() == V["token"]
    assert len(calls) == 1 and calls[0]["oidc"]["token"] == "workload-jwt" and calls[0]["account"]["id"] == "sa-1"


def test_token_key_recovery_matches_vectors():
    kp = recover_token_key(parse_token(V["token"]), V["wrapped_key_share"])
    assert kp.private.hex() == V["kx_private"] and "redacted" in repr(kp)
