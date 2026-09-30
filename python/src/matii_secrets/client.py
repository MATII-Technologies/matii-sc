"""Matii Secret Service client.

    from matii_secrets import Client

    client = Client(host="https://secrets.example.com", token=os.environ["MATII_TOKEN"])
    for s in client.secrets(app="Payments", env="production"):
        ...
    creds = client.lease_dynamic(app="Payments", env="production", name="deploy", ttl_seconds=1800)

Server-side encrypted apps: values arrive decrypted (and redacted where the
caller may not reveal them). End-to-end encrypted apps: values are decrypted
locally with the token's key shares and references are resolved locally.
"""

import json
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Dict, List, Optional

from nacl import bindings  # noqa: F401 (import early: fail fast without PyNaCl)

from .crypto import KeyPair, Token, decrypt_asymmetric, kx_seed_keypair, parse_token, recover_token_key

USER_AGENT = "matii-secrets-python/0.1.0"
REFERENCE = re.compile(r"\$\{([^{}]+)\}")
MAX_REFERENCE_DEPTH = 25


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(f"matii: HTTP {status}: {message}")
        self.status = status
        self.message = message


@dataclass
class Secret:
    key: str
    value: str
    path: str = "/"
    comment: str = ""
    tags: List[str] = field(default_factory=list)
    redacted: bool = False  # the caller may list but not reveal this value

    def __repr__(self):
        return f"Secret({self.path.rstrip('/')}/{self.key}=<redacted>)"


@dataclass
class DynamicLease:
    id: str
    expires_at: datetime
    credentials: Dict[str, str]

    def __repr__(self):
        return f"DynamicLease({self.id}, expires {self.expires_at.isoformat()}, <redacted>)"


TokenSource = Callable[[], str]


def static_token(raw: str) -> TokenSource:
    parse_token(raw)
    return lambda: raw


def oidc_token_source(api_base: str, service_account_id: str, jwt: Callable[[], str], ttl_seconds: int = 0,
                      opener=None) -> TokenSource:
    """Exchange a workload identity JWT (e.g. a Kubernetes projected token) for a service account token."""
    lock = threading.Lock()
    state = {"token": None, "renew_at": 0.0}
    open_url = opener or urllib.request.urlopen

    def source() -> str:
        with lock:
            if state["token"] and time.time() < state["renew_at"]:
                return state["token"]
            body = {"account": {"type": "service", "id": service_account_id}, "oidc": {"token": jwt()}}
            if ttl_seconds:
                body["tokenRequest"] = {"ttl": ttl_seconds}
            req = urllib.request.Request(
                api_base.rstrip("/") + "/identities/external/v1/oidc/auth/", data=json.dumps(body).encode(),
                headers={"Content-Type": "application/json", "User-Agent": USER_AGENT}, method="POST")
            payload = _send(open_url, req)
            auth = payload["authentication"]
            state["token"] = auth["token"]
            state["renew_at"] = time.time() + auth.get("TTL", 600) * 0.8
            return state["token"]

    return source


def file_jwt(path: str) -> Callable[[], str]:
    def read() -> str:
        with open(path) as fh:
            return fh.read().strip()

    return read


def _send(open_url, req):
    try:
        with open_url(req, timeout=30) as resp:
            raw = resp.read(32 << 20)
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        try:
            body = json.loads(exc.read() or b"{}")
        except ValueError:
            body = {}
        raise ApiError(exc.code, body.get("error") or body.get("detail") or exc.reason) from None


def _is_local(host: str) -> bool:
    return host in ("localhost", "127.0.0.1", "::1")


class Client:
    def __init__(self, host: str = "", token: str = "", token_source: Optional[TokenSource] = None,
                 api_base: str = "", opener=None):
        base = (api_base or (host.rstrip("/") + "/service" if host else "")).rstrip("/")
        parsed = urllib.parse.urlparse(base)
        if not parsed.hostname:
            raise ValueError("matii: host or api_base is required")
        if parsed.scheme != "https" and not _is_local(parsed.hostname):
            raise ValueError("matii: the API must use https (plain http only for localhost)")
        if not token and token_source is None:
            raise ValueError("matii: token or token_source is required")
        self._base = base
        self._tokens = token_source or static_token(token)
        self._open = opener or urllib.request.urlopen
        self._lock = threading.Lock()
        self._boot = None  # (raw token, info, token key, {env id: KeyPair})

    # --- plumbing ---------------------------------------------------------------------

    def _request(self, path, query=None, headers=None, method="GET", body=None):
        token: Token = parse_token(self._tokens())
        url = self._base + path + ("?" + urllib.parse.urlencode(query) if query else "")
        data = json.dumps(body).encode() if body is not None else None
        hdrs = {"Authorization": token.authorization, "Accept": "application/json", "User-Agent": USER_AGENT}
        if data is not None:
            hdrs["Content-Type"] = "application/json"
        hdrs.update(headers or {})
        return _send(self._open, urllib.request.Request(url, data=data, headers=hdrs, method=method))

    def _bootstrap(self):
        raw = self._tokens()
        with self._lock:
            if self._boot and self._boot[0] == raw:
                return self._boot
        info = self._request("/secrets/tokens/")
        token_key = recover_token_key(parse_token(raw), info["wrapped_key_share"])
        boot = (raw, info, token_key, {})
        with self._lock:
            self._boot = boot
        return boot

    def _resolve(self, app: Optional[str], app_id: Optional[str], env: str):
        _, info, _, _ = self._bootstrap()
        for a in info.get("apps", []):
            if (app_id and a["id"] == app_id) or (not app_id and app and a["name"].lower() == app.lower()):
                for key in a.get("environment_keys", []):
                    if key["environment"]["name"].lower() == env.lower():
                        return a, key
                raise ApiError(403, f"this token has no access to environment {env!r} of app {a['name']!r}")
        raise ApiError(403, "this token has no access to that app")

    def _env_keys(self, key) -> KeyPair:
        _, _, token_key, cache = self._bootstrap()
        env_id = key["environment"]["id"]
        if env_id not in cache:
            seed = decrypt_asymmetric(key["wrapped_seed"], token_key)
            cache[env_id] = kx_seed_keypair(bytes.fromhex(seed))
        return cache[env_id]

    # --- secrets ----------------------------------------------------------------------------

    def _raw(self, app, key, path=None) -> List[Secret]:
        if app["encryption"] == "SSE":
            query = {"app_id": app["id"], "env": key["environment"]["name"]}
            if path:
                query["path"] = path
            items = self._request("/v1/secrets/", query=query)
            return [Secret(i["key"], i.get("value") or "", i.get("path") or "/", i.get("comment") or "", i.get("tags") or [],
                           i.get("value") is None or bool(i.get("valueRedacted"))) for i in items]
        keys = self._env_keys(key)
        headers = {"Environment": key["environment"]["id"]}
        if path:
            headers["Path"] = path
        items = self._request("/secrets/", headers=headers)
        out = []
        for i in items:
            out.append(Secret(
                decrypt_asymmetric(i["key"], keys),
                decrypt_asymmetric(i["value"], keys) if i.get("value") else "",
                i.get("path") or "/",
                decrypt_asymmetric(i["comment"], keys) if i.get("comment") else "",
                i.get("tags") or [],
            ))
        return out

    def secrets(self, env: str, app: Optional[str] = None, app_id: Optional[str] = None,
                path: Optional[str] = None) -> List[Secret]:
        """Secrets of one environment (optionally one folder), references resolved."""
        a, key = self._resolve(app, app_id, env)
        secrets = self._raw(a, key, path)
        if a["encryption"] == "SSE":
            return secrets  # the server resolves references for SSE apps
        return self._resolve_references(secrets, a)

    def get(self, key: str, env: str, app: Optional[str] = None, app_id: Optional[str] = None,
            path: Optional[str] = None) -> Optional[str]:
        for s in self.secrets(env, app, app_id, path):
            if s.key == key and not s.redacted:
                return s.value
        return None

    def _resolve_references(self, secrets: List[Secret], app) -> List[Secret]:
        cache = {"": _index(secrets)}

        def fetch(app_name, env_name):
            a, key = self._resolve(app_name or None, None if app_name else app["id"], env_name)
            return self._raw(a, key)

        def resolve(value, depth):
            if depth > MAX_REFERENCE_DEPTH or "${" not in value:
                return value

            def repl(match):
                ref = match.group(1)
                app_name = env_name = ""
                scope = ""
                if "::" in ref:
                    app_name, ref = ref.split("::", 1)
                    scope = app_name + "::"
                if "." in ref and not ref.startswith("/"):
                    env_name, name = ref.split(".", 1)
                    scope += env_name
                else:
                    name = ref
                if app_name and not env_name:
                    return match.group(0)
                if scope not in cache:
                    try:
                        cache[scope] = _index(fetch(app_name, env_name))
                    except Exception:
                        cache[scope] = None
                values = cache[scope]
                if values is None or _normalize(name) not in values:
                    return match.group(0)
                return resolve(values[_normalize(name)], depth + 1)

            return REFERENCE.sub(repl, value)

        return [Secret(s.key, resolve(s.value, 0), s.path, s.comment, s.tags, s.redacted) for s in secrets]

    # --- dynamic credentials ---------------------------------------------------------------

    def lease_dynamic(self, name: str, env: str, app: Optional[str] = None, app_id: Optional[str] = None,
                      path: str = "/", ttl_seconds: int = 0) -> DynamicLease:
        a, key = self._resolve(app, app_id, env)
        body = {"name": name, "path": path or "/"}
        if ttl_seconds:
            body["ttlSeconds"] = int(ttl_seconds)
        r = self._request("/v1/dynamic-secrets/lease/", query={"app_id": a["id"], "env": key["environment"]["name"]},
                          method="POST", body=body)
        expires = datetime.fromisoformat(r["expiresAt"].replace("Z", "+00:00"))
        return DynamicLease(r["leaseId"], expires, r["credentials"])


def _normalize(name: str) -> str:
    name = name.strip()
    while "//" in name:
        name = name.replace("//", "/")
    return name.lstrip("/")


def _index(secrets: List[Secret]) -> Dict[str, str]:
    out = {}
    for s in secrets:
        out[_normalize(f"{s.path}/{s.key}")] = s.value
        if s.path in ("/", ""):
            out[_normalize(s.key)] = s.value
    return out


def to_dict(secrets: List[Secret]) -> Dict[str, str]:
    """key -> value, skipping values the caller may not reveal."""
    return {s.key: s.value for s in secrets if not s.redacted}


def to_dotenv(secrets: List[Secret]) -> str:
    def esc(v):
        return '"' + v.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'

    return "".join(f"{k}={esc(v)}\n" for k, v in sorted(to_dict(secrets).items()))
