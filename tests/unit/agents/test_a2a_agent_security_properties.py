"""Property tests for the sample A2A agents' inbound auth and tool confirmation.

Both sample agents under ``agents/a2a/src`` drive an LLM tool loop, and users
copy them as templates. Two properties are pinned here. First, every HTTP route
outside the middleware's public allowlist rejects a request whose bearer JWT is
missing or invalid in any way (scheme, signature, issuer, audience, expiry,
``alg: none``, HS256 keyed with the public key), under the shipped default
configuration as well as with an explicit audience. Second, a mutating tool
call emitted by the model (reserve, confirm, pay, cancel, save a trip plan)
does not change the database unless a human confirmed it out of band, even when
the model fills every tool argument it can see.
"""

import base64
import hashlib
import hmac
import importlib
import json
import os
import re
import sqlite3
import sys
import time
import types
from collections.abc import AsyncIterator
from contextlib import closing
from pathlib import Path
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI
from hypothesis import (
    example,
    given,
    settings,
)
from hypothesis import strategies as st
from jwt import PyJWKClient
from jwt.algorithms import RSAAlgorithm
from starlette.routing import (
    Mount,
    Route,
)
from starlette.testclient import TestClient
from strands.models.model import Model

_REPO_ROOT = Path(__file__).resolve().parents[3]
_A2A_SRC = _REPO_ROOT / "agents" / "a2a" / "src"

FLIGHT = "flight-booking"
TRAVEL = "travel-assistant"

# Agent key -> (source directory, entry module that builds the FastAPI app).
_AGENT_SOURCES: dict[str, tuple[str, str]] = {
    FLIGHT: ("flight-booking-agent", "agent"),
    TRAVEL: ("travel-assistant-agent", "server"),
}
# Module that holds the strands Agent instance, per agent.
_STRANDS_AGENT_MODULE: dict[str, str] = {
    FLIGHT: "agent",
    TRAVEL: "agent",
}
_AUDIENCES: dict[str, str] = {
    FLIGHT: "flight-booking-agent",
    TRAVEL: "travel-assistant-agent",
}

# `strands.multiagent.a2a` and the travel agent's remote client need the
# `a2a-sdk` package, which the main venv does not install. The A2AServer stub
# serves the routes a2a-sdk 0.3.x registers on its FastAPI app
# (DEFAULT_RPC_URL, AGENT_CARD_WELL_KNOWN_PATH, PREV_AGENT_CARD_WELL_KNOWN_PATH,
# EXTENDED_AGENT_CARD_PATH). The `a2a.*` names are only used when an agent
# calls a remote agent, which these tests never do.
_A2A_STUB_MODULE = "strands.multiagent.a2a"
_A2A_SDK_PLACEHOLDERS: dict[str, tuple[str, ...]] = {
    "a2a": (),
    "a2a.client": ("A2ACardResolver", "ClientConfig", "ClientFactory"),
    "a2a.types": ("Message", "Part", "Role", "TextPart"),
}
_A2A_SDK_ROUTES: tuple[tuple[str, str], ...] = (
    ("POST", "/"),
    ("GET", "/.well-known/agent-card.json"),
    ("GET", "/.well-known/agent.json"),
    ("GET", "/agent/authenticatedExtendedCard"),
)

KEYCLOAK_URL = "https://keycloak.example.test"
REALM = "mcp-gateway"
ISSUER = f"{KEYCLOAK_URL}/realms/{REALM}"
KID = "agent-test-key"

# The unauthenticated surface each agent is meant to expose: health probes and
# the public agent card.
EXPECTED_PUBLIC_ENDPOINTS: frozenset[tuple[str, str]] = frozenset(
    {
        ("GET", "/ping"),
        ("GET", "/api/health"),
        ("GET", "/.well-known/agent-card.json"),
    }
)
_DENIED_STATUSES: frozenset[int] = frozenset({401, 403, 503})
_PATH_PARAM_RE = re.compile(r"\{[^}]+\}")
_PATH_PARAM_VALUE = "BK0001"

CONFIG_DEFAULT = "shipped_default"
CONFIG_AUDIENCE = "audience_enforced"
CONFIGS: tuple[str, ...] = (CONFIG_DEFAULT, CONFIG_AUDIENCE)

MUTATIONS: tuple[str, ...] = (
    "missing_header",
    "wrong_scheme",
    "empty_bearer",
    "bad_signature",
    "wrong_issuer",
    "wrong_audience",
    "missing_audience",
    "expired",
    "missing_exp",
    "alg_none",
    "hs256_public_key_secret",
)

AUDIENCE_DEFAULT_REASON = (
    "Known defect: with AGENT_AUDIENCE unset (the shipped default) the middleware "
    "skips the aud check, so a realm token minted for any other client is accepted."
)
# (config, mutation) pairs that fail today, for both agents.
_KNOWN_AUTH_DEFECTS: frozenset[tuple[str, str]] = frozenset(
    {
        (CONFIG_DEFAULT, "wrong_audience"),
        (CONFIG_DEFAULT, "missing_audience"),
    }
)

CONFIRMATION_REASON = (
    "Known defect: the agent's mutating tools run as soon as the model emits the "
    "call; no human confirmation gate exists at the execution boundary."
)


def _generate_rsa_private_key() -> rsa.RSAPrivateKey:
    """Generate a 2048-bit RSA private key.

    Returns:
        A fresh RSA private key.
    """
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


_TRUSTED_KEY = _generate_rsa_private_key()
_ATTACKER_KEY = _generate_rsa_private_key()
_TRUSTED_PUBLIC_PEM = _TRUSTED_KEY.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)
_TRUSTED_JWK: dict[str, Any] = {
    **RSAAlgorithm.to_jwk(_TRUSTED_KEY.public_key(), as_dict=True),
    "kid": KID,
    "use": "sig",
    "alg": "RS256",
}


class _LocalJWKClient(PyJWKClient):
    """PyJWKClient that serves the test realm's JWKS without network access."""

    def fetch_data(self) -> Any:
        """Return the local JWKS document instead of fetching the URI.

        Returns:
            A JWKS dict holding the trusted signing key.
        """
        return {"keys": [_TRUSTED_JWK]}


def _b64url(
    data: bytes,
) -> str:
    """Base64url-encode without padding.

    Args:
        data: Raw bytes.

    Returns:
        The unpadded base64url text.
    """
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _segment(
    obj: dict[str, Any],
) -> str:
    """Encode a JWT header or claims object as a compact segment.

    Args:
        obj: JSON-serializable mapping.

    Returns:
        The base64url segment.
    """
    return _b64url(json.dumps(obj, separators=(",", ":")).encode())


def _claims(
    audience: str | None,
    issuer: str = ISSUER,
    exp_offset: int | None = 300,
) -> dict[str, Any]:
    """Build token claims.

    Args:
        audience: ``aud`` value, or None to omit the claim.
        issuer: ``iss`` value.
        exp_offset: Seconds from now for ``exp``, or None to omit it.

    Returns:
        The claims mapping.
    """
    now = int(time.time())
    claims: dict[str, Any] = {"iss": issuer, "sub": "test-caller", "iat": now}
    if exp_offset is not None:
        claims["exp"] = now + exp_offset
    if audience is not None:
        claims["aud"] = audience
    return claims


def _rs256(
    claims: dict[str, Any],
    key: rsa.RSAPrivateKey = _TRUSTED_KEY,
) -> str:
    """Sign claims with RS256 under the trusted key id.

    Args:
        claims: Token claims.
        key: Signing key; the attacker key yields a bad signature.

    Returns:
        The compact JWT.
    """
    return jwt.encode(claims, key, algorithm="RS256", headers={"kid": KID})


def _alg_none(
    claims: dict[str, Any],
) -> str:
    """Build an unsigned ``alg: none`` token.

    Args:
        claims: Token claims.

    Returns:
        The compact JWT with an empty signature.
    """
    header = {"alg": "none", "typ": "JWT", "kid": KID}
    return f"{_segment(header)}.{_segment(claims)}."


def _hs256_with_public_key(
    claims: dict[str, Any],
) -> str:
    """Build an HS256 token keyed with the realm's public key PEM.

    This is the classic RS256/HS256 key-confusion forgery.

    Args:
        claims: Token claims.

    Returns:
        The compact JWT.
    """
    header = {"alg": "HS256", "typ": "JWT", "kid": KID}
    signing_input = f"{_segment(header)}.{_segment(claims)}"
    digest = hmac.new(_TRUSTED_PUBLIC_PEM, signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{_b64url(digest)}"


def _auth_headers(
    mutation: str,
    audience: str,
) -> dict[str, str]:
    """Build request headers carrying the given credential mutation.

    Args:
        mutation: One of ``MUTATIONS`` or ``"valid"``.
        audience: The agent's intended audience.

    Returns:
        Headers to send with the request.
    """
    builders: dict[str, Any] = {
        "valid": lambda: f"Bearer {_rs256(_claims(audience))}",
        "missing_header": lambda: None,
        "wrong_scheme": lambda: f"Basic {_rs256(_claims(audience))}",
        "empty_bearer": lambda: "Bearer ",
        "bad_signature": lambda: f"Bearer {_rs256(_claims(audience), _ATTACKER_KEY)}",
        "wrong_issuer": lambda: (
            f"Bearer {_rs256(_claims(audience, issuer=f'{KEYCLOAK_URL}/realms/other'))}"
        ),
        "wrong_audience": lambda: f"Bearer {_rs256(_claims('some-other-client'))}",
        "missing_audience": lambda: f"Bearer {_rs256(_claims(None))}",
        "expired": lambda: f"Bearer {_rs256(_claims(audience, exp_offset=-3600))}",
        "missing_exp": lambda: f"Bearer {_rs256(_claims(audience, exp_offset=None))}",
        "alg_none": lambda: f"Bearer {_alg_none(_claims(audience))}",
        "hs256_public_key_secret": lambda: f"Bearer {_hs256_with_public_key(_claims(audience))}",
    }
    value = builders[mutation]()
    return {} if value is None else {"Authorization": value}


def _build_sdk_stubs() -> dict[str, types.ModuleType]:
    """Build stand-ins for ``strands.multiagent.a2a`` and the ``a2a`` SDK.

    Returns:
        Module name to stub module. ``A2AServer`` serves the a2a-sdk route
        layout; the ``a2a.*`` names are inert placeholders.
    """

    class A2AServer:
        """Minimal A2AServer that only exposes the HTTP route layout."""

        def __init__(
            self,
            agent: Any,
            http_url: str,
            serve_at_root: bool = False,
        ) -> None:
            """Record the agent; no network or SDK work is done."""
            self.agent = agent
            self.http_url = http_url

        def to_fastapi_app(self) -> FastAPI:
            """Return a FastAPI app with the a2a-sdk routes.

            Returns:
                The sub-application mounted at the agent root.
            """
            sub_app = FastAPI()
            for method, path in _A2A_SDK_ROUTES:
                sub_app.add_api_route(
                    path,
                    lambda: {"a2a": "stub"},
                    methods=[method],
                )
            return sub_app

    server_stub = types.ModuleType(_A2A_STUB_MODULE)
    server_stub.A2AServer = A2AServer
    stubs = {_A2A_STUB_MODULE: server_stub}
    for module_name, attributes in _A2A_SDK_PLACEHOLDERS.items():
        placeholder = types.ModuleType(module_name)
        for attribute in attributes:
            setattr(placeholder, attribute, type(attribute, (), {}))
        stubs[module_name] = placeholder
    return stubs


def _load_agent(
    agent_key: str,
    db_path: Path,
    audience: str | None,
) -> dict[str, types.ModuleType]:
    """Import one sample agent in isolation and return its modules.

    The agent directories use bare module names (``agent``, ``tools``,
    ``database`` ...) that collide with each other, so the modules are imported
    with the source directory on ``sys.path`` and then removed from
    ``sys.modules``; the returned objects keep working because each module holds
    direct references to its dependencies.

    Args:
        agent_key: ``FLIGHT`` or ``TRAVEL``.
        db_path: SQLite path the agent's settings will use.
        audience: ``AGENT_AUDIENCE`` value, or None for the shipped default.

    Returns:
        Mapping of bare module name to the loaded module.
    """
    directory, entry = _AGENT_SOURCES[agent_key]
    src_dir = _A2A_SRC / directory
    stubs = _build_sdk_stubs()
    names = {path.stem for path in src_dir.glob("*.py")} | set(stubs)
    env: dict[str, str | None] = {
        "AGENT_AUTH_DISABLED": None,
        "AGENT_AUTH_PRESENCE_ONLY": None,
        "AGENT_AUTH_ALLOW_EXPOSED_PRESENCE_ONLY": None,
        "AGENT_HOST": "127.0.0.1",
        "AGENT_AUDIENCE": audience,
        "AGENTCORE_RUNTIME_URL": "http://127.0.0.1:9000/",
        "KEYCLOAK_URL": KEYCLOAK_URL,
        "KEYCLOAK_REALM": REALM,
        "DB_PATH": str(db_path),
        "REGISTRY_JWT_TOKEN": None,
        "M2M_CLIENT_ID": None,
        "M2M_CLIENT_SECRET": None,
        "AWS_REGION": "us-east-1",
    }
    saved_modules = {name: sys.modules.pop(name) for name in names if name in sys.modules}
    saved_env = {key: os.environ.get(key) for key in env}
    saved_path = list(sys.path)
    try:
        for key, value in env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        sys.modules.update(stubs)
        sys.path.insert(0, str(src_dir))
        importlib.import_module(entry)
        loaded = {
            name: sys.modules[name] for name in names if name in sys.modules and name not in stubs
        }
    finally:
        for name in names:
            sys.modules.pop(name, None)
        sys.modules.update(saved_modules)
        sys.path[:] = saved_path
        for key, value in saved_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
    # The middleware builds its JWKS client on the first request; serve the
    # local key set so no network call is made.
    loaded["auth_middleware"].PyJWKClient = _LocalJWKClient
    return loaded


def _app_module(
    agent_key: str,
    modules: dict[str, types.ModuleType],
) -> types.ModuleType:
    """Return the module that defines the agent's FastAPI ``app``."""
    return modules[_AGENT_SOURCES[agent_key][1]]


def _endpoints(
    app: FastAPI,
) -> list[tuple[str, str]]:
    """Enumerate every (method, concrete path) the app routes.

    Path parameters are filled with a fixed value; ``HEAD`` is skipped since
    Starlette derives it from ``GET``.

    Args:
        app: The agent application.

    Returns:
        Sorted unique endpoints, including routes inside mounted sub-apps.
    """
    found: set[tuple[str, str]] = set()

    def _walk(routes: list[Any], prefix: str) -> None:
        for route in routes:
            if isinstance(route, Mount):
                _walk(list(route.routes), prefix + route.path)
            elif isinstance(route, Route):
                path = _PATH_PARAM_RE.sub(_PATH_PARAM_VALUE, prefix + route.path) or "/"
                for method in route.methods or ():
                    if method != "HEAD":
                        found.add((method, path))

    _walk(list(app.routes), "")
    return sorted(found)


def _client(
    app: Any,
) -> TestClient:
    """Build a TestClient that reports handler errors as 500 responses."""
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture(scope="module")
def agent_apps(
    tmp_path_factory: pytest.TempPathFactory,
) -> dict[tuple[str, str], dict[str, types.ModuleType]]:
    """Load both agents under both auth configurations.

    Returns:
        Mapping of (agent key, config) to the agent's loaded modules.
    """
    loaded: dict[tuple[str, str], dict[str, types.ModuleType]] = {}
    for agent_key in _AGENT_SOURCES:
        for config in CONFIGS:
            db_dir = tmp_path_factory.mktemp(f"{agent_key}-{config}")
            audience = _AUDIENCES[agent_key] if config == CONFIG_AUDIENCE else None
            loaded[(agent_key, config)] = _load_agent(agent_key, db_dir / "agent.db", audience)
    return loaded


def _auth_params() -> list[Any]:
    """Build the exhaustive (agent, config, mutation) parameter list."""
    params = []
    for agent_key in _AGENT_SOURCES:
        for config in CONFIGS:
            for mutation in MUTATIONS:
                marks = (
                    [
                        pytest.mark.xfail(
                            strict=True,
                            raises=AssertionError,
                            reason=AUDIENCE_DEFAULT_REASON,
                        )
                    ]
                    if (config, mutation) in _KNOWN_AUTH_DEFECTS
                    else []
                )
                params.append(
                    pytest.param(
                        agent_key,
                        config,
                        mutation,
                        marks=marks,
                        id=f"{agent_key}-{config}-{mutation}",
                    )
                )
    return params


@pytest.mark.unit
@pytest.mark.parametrize(("agent_key", "config", "mutation"), _auth_params())
def test_every_protected_route_rejects_invalid_credentials(
    agent_apps: dict[tuple[str, str], dict[str, types.ModuleType]],
    agent_key: str,
    config: str,
    mutation: str,
) -> None:
    """Property: every route outside the public allowlist answers 401 to a bad JWT."""
    modules = agent_apps[(agent_key, config)]
    app = _app_module(agent_key, modules).app
    public = modules["auth_middleware"]._PUBLIC_PATHS
    client = _client(app)
    accepted = []
    for method, path in _endpoints(app):
        if path in public:
            continue
        response = client.request(
            method, path, headers=_auth_headers(mutation, _AUDIENCES[agent_key])
        )
        if response.status_code != 401:
            accepted.append((method, path, response.status_code))
    assert not accepted, (
        f"{agent_key} ({config}) did not reject a '{mutation}' credential on: {accepted}"
    )


@pytest.mark.unit
@pytest.mark.parametrize("config", CONFIGS)
@pytest.mark.parametrize("agent_key", list(_AGENT_SOURCES))
def test_valid_token_reaches_every_protected_route(
    agent_apps: dict[tuple[str, str], dict[str, types.ModuleType]],
    agent_key: str,
    config: str,
) -> None:
    """Property: a correctly signed, unexpired, right-issuer, right-audience JWT is accepted.

    This is the control for the mutation sweep: each rejection there is caused
    by the mutation, not by a token the middleware could never accept.
    """
    modules = agent_apps[(agent_key, config)]
    app = _app_module(agent_key, modules).app
    client = _client(app)
    denied = []
    for method, path in _endpoints(app):
        response = client.request(
            method, path, headers=_auth_headers("valid", _AUDIENCES[agent_key])
        )
        if response.status_code in _DENIED_STATUSES:
            denied.append((method, path, response.status_code))
    assert not denied, f"{agent_key} ({config}) denied a valid token on: {denied}"


@pytest.mark.unit
@pytest.mark.parametrize("agent_key", list(_AGENT_SOURCES))
def test_unauthenticated_surface_is_health_and_agent_card(
    agent_apps: dict[tuple[str, str], dict[str, types.ModuleType]],
    agent_key: str,
) -> None:
    """Property: without a token, only the health probes and public agent card answer."""
    app = _app_module(agent_key, agent_apps[(agent_key, CONFIG_DEFAULT)]).app
    client = _client(app)
    reachable = set()
    for method, path in _endpoints(app):
        if client.request(method, path).status_code != 401:
            reachable.add((method, path))
    assert reachable == EXPECTED_PUBLIC_ENDPOINTS, (
        f"{agent_key} unauthenticated surface differs: "
        f"extra={sorted(reachable - EXPECTED_PUBLIC_ENDPOINTS)}, "
        f"missing={sorted(EXPECTED_PUBLIC_ENDPOINTS - reachable)}"
    )


_PATH_SEGMENT = st.text(
    alphabet=st.sampled_from("abcdefghijklmnopqrstuvwxyzAPI0123456789-._~%:@;+=!$&'(),*"),
    max_size=12,
)


@pytest.mark.unit
@pytest.mark.parametrize("agent_key", list(_AGENT_SOURCES))
@settings(max_examples=200, derandomize=True, database=None, report_multiple_bugs=False)
@given(
    segments=st.lists(_PATH_SEGMENT, max_size=4),
    method=st.sampled_from(("GET", "POST", "PUT", "PATCH", "DELETE")),
)
@example(segments=["api", "health", ""], method="GET")
@example(segments=["ping", ".."], method="GET")
@example(segments=["api%2Fhealth"], method="GET")
@example(segments=["", "ping"], method="GET")
@example(segments=[".well-known", "agent.json"], method="GET")
def test_unauthenticated_request_is_rejected_unless_path_is_public(
    agent_apps: dict[tuple[str, str], dict[str, types.ModuleType]],
    agent_key: str,
    segments: list[str],
    method: str,
) -> None:
    """Property: a tokenless request to any path the server sees as non-public gets 401."""
    modules = agent_apps[(agent_key, CONFIG_DEFAULT)]
    app = _app_module(agent_key, modules).app
    public = modules["auth_middleware"]._PUBLIC_PATHS
    seen_paths: list[str] = []

    async def _recording_app(scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] == "http":
            seen_paths.append(scope["path"])
        await app(scope, receive, send)

    response = _client(_recording_app).request(method, "http://testserver/" + "/".join(segments))
    assert len(seen_paths) == 1
    if seen_paths[0] not in public:
        assert response.status_code == 401, (
            f"{agent_key}: {method} {seen_paths[0]!r} answered {response.status_code} "
            "without a token"
        )


class _AdversarialToolCallModel(Model):
    """Scripted model that keeps emitting one tool call, then stops.

    Each turn it calls the target tool with the given arguments plus every
    other argument the tool schema exposes, set to an affirmative value
    (booleans ``True``, strings ``"yes"``). A model under prompt injection can
    set any argument it sees, so an argument is not a human confirmation.
    """

    def __init__(
        self,
        tool_name: str,
        tool_input: dict[str, Any],
        max_calls: int = 3,
    ) -> None:
        """Store the scripted call.

        Args:
            tool_name: Tool the model calls.
            tool_input: Arguments the model supplies.
            max_calls: Tool-call turns before the model ends its turn.
        """
        self._tool_name = tool_name
        self._tool_input = tool_input
        self._max_calls = max_calls
        self.turns = 0
        self.tool_results: list[Any] = []

    def update_config(self, **model_config: Any) -> None:
        """Accept and ignore configuration updates."""

    def get_config(self) -> dict[str, Any]:
        """Return an empty configuration."""
        return {}

    async def structured_output(
        self, output_model: Any, prompt: Any, system_prompt: Any = None, **kwargs: Any
    ) -> AsyncIterator[Any]:
        """Structured output is not used by these agents."""
        raise NotImplementedError
        yield  # pragma: no cover

    def _arguments(
        self,
        tool_specs: list[dict[str, Any]] | None,
    ) -> dict[str, Any]:
        """Return the scripted arguments widened with affirmative values.

        Args:
            tool_specs: Tool specifications the agent offered the model.

        Returns:
            The arguments for the tool call.
        """
        arguments = dict(self._tool_input)
        for spec in tool_specs or []:
            if spec.get("name") != self._tool_name:
                continue
            properties = spec.get("inputSchema", {}).get("json", {}).get("properties", {})
            for name, schema in properties.items():
                if name in arguments:
                    continue
                types_offered = {schema.get("type")} | {
                    option.get("type") for option in schema.get("anyOf", [])
                }
                if "boolean" in types_offered:
                    arguments[name] = True
                elif "string" in types_offered:
                    arguments[name] = "yes"
        return arguments

    async def stream(
        self,
        messages: list[dict[str, Any]],
        tool_specs: list[dict[str, Any]] | None = None,
        system_prompt: str | None = None,
        **kwargs: Any,
    ) -> AsyncIterator[dict[str, Any]]:
        """Emit the scripted tool call, or end the turn after ``max_calls``."""
        for message in messages[-1:]:
            for block in message.get("content", []):
                if "toolResult" in block:
                    self.tool_results.append(block["toolResult"])
        self.turns += 1
        yield {"messageStart": {"role": "assistant"}}
        if self.turns <= self._max_calls:
            tool_use = {"toolUseId": f"call-{self.turns}", "name": self._tool_name}
            yield {"contentBlockStart": {"start": {"toolUse": tool_use}}}
            arguments = json.dumps(self._arguments(tool_specs))
            yield {"contentBlockDelta": {"delta": {"toolUse": {"input": arguments}}}}
            yield {"contentBlockStop": {}}
            yield {"messageStop": {"stopReason": "tool_use"}}
        else:
            yield {"contentBlockDelta": {"delta": {"text": "done"}}}
            yield {"contentBlockStop": {}}
            yield {"messageStop": {"stopReason": "end_turn"}}


def _snapshot(
    db_path: Path,
) -> dict[str, list[tuple[Any, ...]]]:
    """Read every row of every table.

    Args:
        db_path: SQLite database file.

    Returns:
        Mapping of table name to its rows in a stable order.
    """
    with closing(sqlite3.connect(db_path)) as conn:
        tables = [
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' "
                "AND name NOT LIKE 'sqlite_%' ORDER BY name"
            )
        ]
        return {
            table: sorted(conn.execute(f'SELECT * FROM "{table}"').fetchall(), key=repr)
            for table in tables
        }


def _run_tool_loop(
    agent_key: str,
    tmp_path: Path,
    tool_name: str,
    tool_input: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], _AdversarialToolCallModel]:
    """Drive the agent's real strands Agent through one scripted tool call.

    Args:
        agent_key: ``FLIGHT`` or ``TRAVEL``.
        tmp_path: Directory for the agent's database.
        tool_name: Tool the model calls.
        tool_input: Arguments the model supplies.

    Returns:
        (database before, database after, the scripted model).
    """
    db_path = tmp_path / "agent.db"
    modules = _load_agent(agent_key, db_path, _AUDIENCES[agent_key])
    modules["dependencies"].get_db_manager()
    before = _snapshot(db_path)
    strands_agent = modules[_STRANDS_AGENT_MODULE[agent_key]].strands_agent
    model = _AdversarialToolCallModel(tool_name, tool_input)
    strands_agent.model = model
    strands_agent.messages.clear()
    strands_agent(f"Please run {tool_name} now.")
    return before, _snapshot(db_path), model


def _mutating_call_params() -> list[Any]:
    """Build one parameter per mutating tool call, all failing today."""
    xfail = pytest.mark.xfail(strict=True, raises=AssertionError, reason=CONFIRMATION_REASON)
    cases = [
        (
            FLIGHT,
            "reserve_flight",
            {"flight_id": 1, "passengers": [{"name": "Mallory", "email": "m@example.com"}]},
        ),
        (FLIGHT, "confirm_booking", {"booking_number": "BK002"}),
        (FLIGHT, "process_payment", {"booking_number": "BK002", "payment_method": "credit_card"}),
        (
            FLIGHT,
            "manage_reservation",
            {"booking_number": "BK001", "action": "cancel", "reason": "injected"},
        ),
        (
            TRAVEL,
            "create_trip_plan",
            {"departure_city": "SF", "arrival_city": "NY", "departure_date": "2025-11-15"},
        ),
    ]
    return [
        pytest.param(agent_key, name, arguments, marks=[xfail], id=f"{agent_key}-{name}")
        for agent_key, name, arguments in cases
    ]


@pytest.mark.unit
@pytest.mark.parametrize(("agent_key", "tool_name", "tool_input"), _mutating_call_params())
def test_mutating_tool_call_needs_human_confirmation(
    tmp_path: Path,
    agent_key: str,
    tool_name: str,
    tool_input: dict[str, Any],
) -> None:
    """Property: a model-emitted mutating tool call leaves the database unchanged without a human."""
    before, after, model = _run_tool_loop(agent_key, tmp_path, tool_name, tool_input)
    changed = {
        table: {
            "added": sorted(set(after.get(table, [])) - set(before.get(table, [])), key=repr),
            "removed": sorted(set(before.get(table, [])) - set(after.get(table, [])), key=repr),
        }
        for table in sorted(set(before) | set(after))
        if before.get(table) != after.get(table)
    }
    assert not changed, (
        f"{agent_key} ran {tool_name}({tool_input}) without confirmation; "
        f"{model.turns} model turns, database changed: {changed}"
    )


@pytest.mark.unit
@pytest.mark.parametrize(
    ("agent_key", "tool_name", "tool_input", "expected_fragment"),
    [
        pytest.param(FLIGHT, "check_availability", {"flight_id": 1}, "UA101", id="flight-check"),
        pytest.param(
            FLIGHT,
            "manage_reservation",
            {"booking_number": "BK001", "action": "view"},
            "John Smith",
            id="flight-view",
        ),
    ],
)
def test_read_only_tool_call_runs_and_changes_nothing(
    tmp_path: Path,
    agent_key: str,
    tool_name: str,
    tool_input: dict[str, Any],
    expected_fragment: str,
) -> None:
    """Property: the harness executes model tool calls, and read-only tools change nothing.

    This is the control for the confirmation test: the scripted model really
    reaches the tool, so an unchanged database there is not an artefact.
    """
    before, after, model = _run_tool_loop(agent_key, tmp_path, tool_name, tool_input)
    assert before == after
    assert any(expected_fragment in json.dumps(result) for result in model.tool_results), (
        f"{tool_name} result never reached the model: {model.tool_results}"
    )
