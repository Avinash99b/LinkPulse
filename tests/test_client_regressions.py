"""Client configuration / identity / process-management regression tests.

These exercise the client's pure helpers and CLI-resolution logic.  They never
contact a server and never write to global user state (every path is redirected
through the ``iso_env`` fixture).
"""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _linkpulse_harness as H  # noqa: E402

sys.path.insert(0, str(H.CLIENT_DIR))
import my_proxy  # noqa: E402


@pytest.fixture
def iso_env(monkeypatch, tmp_path):
    state_dir = tmp_path / "state"
    logs_dir = tmp_path / "logs"
    config_home = tmp_path / "config"
    monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))
    monkeypatch.setenv("LINKPULSE_STATE_DIR", str(state_dir))
    monkeypatch.setenv("LINKPULSE_LOGS_DIR", str(logs_dir))
    for name in ("MY_PROXY_TOKEN", "MY_PROXY_SERVER", "MY_PROXY_TLS",
                 "MY_PROXY_CA_CERT", "MY_PROXY_RETRY_INTERVAL",
                 "MY_PROXY_GRACE_TIME", "MY_PROXY_DASHBOARD",
                 "MY_PROXY_STATE_FILE"):
        monkeypatch.delenv(name, raising=False)
    return tmp_path


# ---------------------------------------------------------------------------
# identifiers / addresses
# ---------------------------------------------------------------------------

def test_validate_client_id_accepts_32_hex_and_lowercases():
    cid = "AABBCCDDEEFF00112233445566778899"
    assert my_proxy._validate_client_id(cid) == cid.lower()


@pytest.mark.parametrize("bad", ["", "abc", "z" * 32, "a" * 31, "a" * 33,
                                 "../../etc/passwd", "0x" + "a" * 30])
def test_validate_client_id_rejects_bad_values(bad):
    with pytest.raises(my_proxy.ConfigError):
        my_proxy._validate_client_id(bad)


def test_parse_host_port_supports_ipv6_and_validation():
    assert my_proxy._parse_host_port("[::1]:9000") == ("::1", 9000)
    assert my_proxy._parse_host_port("[::1]") == ("::1", 9000)
    assert my_proxy._parse_host_port("::1") == ("::1", 9000)
    assert my_proxy._parse_host_port("example.test:1234") == ("example.test", 1234)
    with pytest.raises(my_proxy.ConfigError):
        my_proxy._parse_host_port("host:notaport")
    with pytest.raises(my_proxy.ConfigError):
        my_proxy._parse_host_port("host:70000")


def test_parse_target_supports_ipv6():
    assert my_proxy._parse_target("[::1]:8080") == ("::1", 8080)
    assert my_proxy._parse_target("8080") == ("localhost", 8080)
    assert my_proxy._parse_target("localhost:5173") == ("localhost", 5173)
    with pytest.raises(my_proxy.ConfigError):
        my_proxy._parse_target("nope")


def test_normalize_server_address_keeps_ipv6_bracketed():
    assert my_proxy._normalize_server_address("[::1]") == "[::1]:9000"
    assert my_proxy._normalize_server_address("https://proxy.example/") == "proxy.example:9000"
    assert my_proxy._normalize_server_address("host:1234") == "host:1234"
    with pytest.raises(my_proxy.ConfigError):
        my_proxy._normalize_server_address("")


# ---------------------------------------------------------------------------
# finite numeric env values
# ---------------------------------------------------------------------------

def test_env_float_rejects_non_finite_and_garbage(iso_env, monkeypatch):
    monkeypatch.setenv("MY_PROXY_RETRY_INTERVAL", "nan")
    with pytest.raises(my_proxy.ConfigError):
        my_proxy._env_float("MY_PROXY_RETRY_INTERVAL")
    monkeypatch.setenv("MY_PROXY_RETRY_INTERVAL", "inf")
    with pytest.raises(my_proxy.ConfigError):
        my_proxy._env_float("MY_PROXY_RETRY_INTERVAL")
    monkeypatch.setenv("MY_PROXY_RETRY_INTERVAL", "2.5")
    assert my_proxy._env_float("MY_PROXY_RETRY_INTERVAL") == 2.5
    monkeypatch.delenv("MY_PROXY_RETRY_INTERVAL")
    assert my_proxy._env_float("MY_PROXY_RETRY_INTERVAL") is None


# ---------------------------------------------------------------------------
# state-file safety (traversal / symlink refusal)
# ---------------------------------------------------------------------------

def test_find_client_state_file_rejects_traversal_and_absolute_paths(iso_env):
    state_dir = iso_env / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    outside = iso_env / "evil.json"
    outside.write_text(json.dumps({"client_id": "evil"}))

    found, err = my_proxy._find_client_state_file("../evil")
    assert found is None and err
    found, err = my_proxy._find_client_state_file(str(outside))
    assert found is None and err


def test_find_client_state_file_refuses_symlinks(iso_env):
    state_dir = iso_env / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    secret = iso_env / "secret.json"
    secret.write_text(json.dumps({"client_id": "secret", "pid": os.getpid()}))
    link = state_dir / "linked.json"
    link.symlink_to(secret)

    found, err = my_proxy._find_client_state_file("linked")
    assert found is None
    assert err


def test_safe_state_file_accepts_real_file_inside_base(iso_env):
    state_dir = iso_env / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    real = state_dir / "abc.json"
    real.write_text("{}")
    assert my_proxy._safe_state_file(real, state_dir) is True
    assert my_proxy._safe_state_file(state_dir / "missing.json", state_dir) is False


# ---------------------------------------------------------------------------
# atomic / private credential + state writes
# ---------------------------------------------------------------------------

def test_atomic_write_json_is_private_and_leaves_no_temp(iso_env):
    target = iso_env / "nested" / "data.json"
    my_proxy._atomic_write_json(target, {"a": 1})
    assert json.loads(target.read_text()) == {"a": 1}
    mode = stat.S_IMODE(target.stat().st_mode)
    assert mode == 0o600, f"state file mode is {oct(mode)}, expected 0o600"
    leftovers = [p.name for p in target.parent.iterdir() if p.name.endswith(".tmp")]
    assert leftovers == []


def test_save_config_writes_private_token_file(iso_env, monkeypatch):
    token_file = iso_env / "config" / "linkpulse" / "authtoken.json"
    monkeypatch.setattr(my_proxy, "DEFAULT_TOKEN_FILE", token_file)
    my_proxy._save_config(token="very-secret-token")
    assert json.loads(token_file.read_text())["token"] == "very-secret-token"
    mode = stat.S_IMODE(token_file.stat().st_mode)
    assert mode == 0o600, f"authtoken.json mode is {oct(mode)}, expected 0o600"
    leftovers = [p.name for p in token_file.parent.iterdir() if p.name.endswith(".tmp")]
    assert leftovers == []


# ---------------------------------------------------------------------------
# process verification (fail closed, PID + boot id guards)
# ---------------------------------------------------------------------------

def test_verify_client_process_accepts_matching_start_time():
    state = {"start_time": my_proxy._proc_start_time(os.getpid())}
    assert state["start_time"] is not None
    assert my_proxy._verify_client_process(os.getpid(), state) is True


def test_verify_client_process_rejects_reused_or_missing_start_time():
    assert my_proxy._verify_client_process(
        os.getpid(), {"start_time": 1}) is False
    # No recorded start time -> cannot verify -> fail closed.
    assert my_proxy._verify_client_process(os.getpid(), {}) is False


def test_verify_client_process_rejects_pid_from_a_different_boot():
    boot = my_proxy._read_boot_id()
    if boot is None:
        pytest.skip("boot id unavailable on this platform")
    state = {"start_time": my_proxy._proc_start_time(os.getpid()),
             "boot_id": "00000000-0000-0000-0000-000000000000"}
    assert my_proxy._verify_client_process(os.getpid(), state) is False


def test_verify_client_process_fails_closed_when_start_time_unreadable(monkeypatch):
    """If the platform cannot provide a start time, identity must not be assumed."""
    monkeypatch.setattr(my_proxy, "_proc_start_time", lambda pid: None)
    state = {"start_time": 12345}
    assert my_proxy._verify_client_process(os.getpid(), state) is False


def test_is_pid_alive_basic():
    assert my_proxy._is_pid_alive(os.getpid()) is True
    assert my_proxy._is_pid_alive(0) is False
    assert my_proxy._is_pid_alive(-1) is False
    assert my_proxy._is_pid_alive(9_999_999) is False


# ---------------------------------------------------------------------------
# CLI parsing: TLS + tracked explicit values
# ---------------------------------------------------------------------------

def test_cli_parser_supports_tls_and_ca_cert():
    parser = my_proxy._build_arg_parser()
    args = parser.parse_args(["http", "8080", "--tls", "--no-dashboard"])
    assert args.tls is True
    args = parser.parse_args(["http", "8080", "--ca-cert", "/tmp/ca.pem", "--no-dashboard"])
    assert args.ca_cert == "/tmp/ca.pem"
    assert getattr(args, "_exp_ca_cert", False) is True


def test_cli_explicit_flag_tracking_distinguishes_defaults():
    parser = my_proxy._build_arg_parser()
    args = parser.parse_args(["http", "8080", "--server", "127.0.0.1:9000", "--no-dashboard"])
    # Explicitly passing the default value is still "explicit".
    assert getattr(args, "_exp_server", False) is True


# ---------------------------------------------------------------------------
# precedence: explicit CLI > environment > config file > saved > defaults
# ---------------------------------------------------------------------------

def _resolve(*argv, cfg=None, env=None, monkeypatch=None, saved=None):
    parser = my_proxy._build_arg_parser()
    args = parser.parse_args(list(argv) + ["--no-dashboard"])
    if saved is not None:
        token_file = Path(os.environ["XDG_CONFIG_HOME"]) / "linkpulse" / "authtoken.json"
        token_file.parent.mkdir(parents=True, exist_ok=True)
        token_file.write_text(json.dumps(saved))
        monkeypatch.setattr(my_proxy, "DEFAULT_TOKEN_FILE", token_file)
    else:
        monkeypatch.setattr(my_proxy, "DEFAULT_TOKEN_FILE",
                            Path(os.environ["XDG_CONFIG_HOME"]) / "linkpulse" / "authtoken.json")
    for key, value in (env or {}).items():
        monkeypatch.setenv(key, value)
    my_proxy._resolve_runtime_config(args, cfg or {})
    return args


def test_precedence_cli_beats_environment(iso_env, monkeypatch):
    args = _resolve("http", "8080", "--token", "cli-token", "--server", "cli.example:9000",
                    env={"MY_PROXY_TOKEN": "env-token", "MY_PROXY_SERVER": "env.example:9000"},
                    monkeypatch=monkeypatch)
    assert args.token == "cli-token"
    assert args.server == "cli.example:9000"


def test_precedence_environment_beats_config(iso_env, monkeypatch):
    args = _resolve("http", "8080",
                    cfg={"token": "cfg-token", "server": "cfg.example:9000"},
                    env={"MY_PROXY_TOKEN": "env-token", "MY_PROXY_SERVER": "env.example:9000"},
                    monkeypatch=monkeypatch)
    assert args.token == "env-token"
    assert args.server == "env.example:9000"


def test_config_only_token_is_accepted(iso_env, monkeypatch):
    args = _resolve("http", "8080",
                    cfg={"token": "cfg-token", "server": "cfg.example:9000"},
                    monkeypatch=monkeypatch)
    assert args.token == "cfg-token"
    assert args.server == "cfg.example:9000"


def test_saved_token_used_when_nothing_else_provided(iso_env, monkeypatch):
    args = _resolve("http", "8080",
                    saved={"token": "saved-token", "server": "saved.example:9000"},
                    monkeypatch=monkeypatch)
    assert args.token == "saved-token"
    assert args.server == "saved.example:9000"


def test_missing_token_stays_missing(iso_env, monkeypatch):
    args = _resolve("http", "8080", monkeypatch=monkeypatch)
    assert args.token is None


def test_non_finite_retry_env_aborts_resolution(iso_env, monkeypatch):
    monkeypatch.setenv("MY_PROXY_RETRY_INTERVAL", "inf")
    parser = my_proxy._build_arg_parser()
    args = parser.parse_args(["http", "8080", "--no-dashboard"])
    monkeypatch.setattr(my_proxy, "DEFAULT_TOKEN_FILE",
                        Path(os.environ["XDG_CONFIG_HOME"]) / "none.json")
    with pytest.raises(my_proxy.ConfigError):
        my_proxy._resolve_runtime_config(args, {})


def test_ca_cert_implies_tls_and_must_exist(iso_env, monkeypatch):
    ca = iso_env / "ca.pem"
    ca.write_text("dummy")
    args = _resolve("http", "8080", "--ca-cert", str(ca), monkeypatch=monkeypatch)
    assert args.tls is True and args.ca_cert == str(ca)

    parser = my_proxy._build_arg_parser()
    bad = parser.parse_args(["http", "8080", "--ca-cert", str(iso_env / "missing.pem"),
                             "--no-dashboard"])
    monkeypatch.setattr(my_proxy, "DEFAULT_TOKEN_FILE",
                        Path(os.environ["XDG_CONFIG_HOME"]) / "none.json")
    with pytest.raises(my_proxy.ConfigError):
        my_proxy._resolve_runtime_config(bad, {})


def test_env_tls_enables_tls(iso_env, monkeypatch):
    args = _resolve("http", "8080", env={"MY_PROXY_TLS": "true"}, monkeypatch=monkeypatch)
    assert args.tls is True


# ---------------------------------------------------------------------------
# multi-tunnel config schema
# ---------------------------------------------------------------------------

def test_build_specs_from_config_validates_schema(iso_env):
    with pytest.raises(my_proxy.ConfigError):
        my_proxy._build_specs_from_config({}, False, "cfg")
    with pytest.raises(my_proxy.ConfigError):
        my_proxy._build_specs_from_config({"tunnels": "nope"}, False, "cfg")
    with pytest.raises(my_proxy.ConfigError):
        my_proxy._build_specs_from_config({"tunnels": [{"type": "smtp", "local": 1}]},
                                          False, "cfg")
    with pytest.raises(my_proxy.ConfigError):
        my_proxy._build_specs_from_config({"tunnels": [{"type": "tcp"}]}, False, "cfg")


def test_build_specs_from_config_parses_valid_tunnels(iso_env):
    specs = my_proxy._build_specs_from_config({
        "tunnels": [
            {"type": "http", "local": "8080", "subdomain": "app"},
            {"type": "tcp", "local": "localhost:22", "remote_port": 20022},
            {"type": "udp", "local": "[::1]:5353", "remote_port": 20053},
        ]
    }, False, "cfg")
    assert [s.type for s in specs] == ["http", "tcp", "udp"]
    assert specs[1].remote_port == 20022
    assert specs[2].local_host == "::1"


# ---------------------------------------------------------------------------
# identity: machine client_id shared, per-process managed/instance ids distinct
# ---------------------------------------------------------------------------

def test_machine_identity_shared_but_process_identity_distinct(iso_env):
    state_file = iso_env / "machine-state.json"
    cid = "0123456789abcdef0123456789abcdef"
    state_file.write_text(json.dumps({"client_id": cid}))

    client_a = my_proxy.TunnelClient(
        specs=[], server_host="127.0.0.1", server_port=1, secret="s",
        grace_time=1, state_file=state_file, log=__import__("logging").getLogger("a"),
        recent_logs=__import__("collections").deque(),
    )
    client_b = my_proxy.TunnelClient(
        specs=[], server_host="127.0.0.1", server_port=1, secret="s",
        grace_time=1, state_file=state_file, log=__import__("logging").getLogger("b"),
        recent_logs=__import__("collections").deque(),
    )
    assert client_a.client_id == cid == client_b.client_id
    assert client_a.instance_id != client_b.instance_id
    assert client_a.managed_id != client_b.managed_id

    # The shared machine-identity file must not carry per-process runtime state
    # that two processes would clobber.
    raw = my_proxy._read_state_raw(state_file)
    assert raw.get("client_id") == cid
    assert "pid" not in raw and "status" not in raw and "instance_id" not in raw


def test_managed_state_file_is_private(iso_env):
    client = my_proxy.TunnelClient(
        specs=[], server_host="127.0.0.1", server_port=1, secret="s",
        grace_time=1, state_file=iso_env / "machine.json",
        log=__import__("logging").getLogger("c"),
        recent_logs=__import__("collections").deque(),
    )
    managed = client._managed_state_path()
    assert managed.exists()
    assert stat.S_IMODE(managed.stat().st_mode) == 0o600
    data = json.loads(managed.read_text())
    assert data["managed_id"] == client.managed_id
    assert data["instance_id"] == client.instance_id