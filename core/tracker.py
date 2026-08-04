"""
Optional run tracking against a shared Ephemeral Enhancement server.

Join once with ``--join-network <token>``; the token is written to
``~/.ee/config`` and reused on every later run.

**Every network call fails open.** A missing server, bad token or timeout must
never stop local cracking — the tracker degrades to a no-op and the pipeline
runs exactly as it would offline.

Fingerprints
------------
Runs are identified by a hash of the *entire searched parameter space*, not the
pipeline string. The hash covers the stage list, each stage's axis size, the
ciphertext, the dictionary contents, the key count and the case-variation flag.

This matters because axis sizes change as stages gain parameters. When extra
alphabets were added to the polyalphabetic stages, ``beaufort>b64`` grew from 24
to 120 combinations. Keying on the pipeline string alone would have reported
that pipeline as "already run" and silently hidden 96 untested combinations.
Because the axis sizes feed the hash, the fingerprint changes and the larger
space is offered again.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

CONFIG_DIR = Path(os.getenv("EE_CONFIG_DIR", Path.home() / ".ee"))
CONFIG_PATH = CONFIG_DIR / "config"
DEFAULT_SERVER = "http://127.0.0.1:8000"
TIMEOUT = 5.0

# Bump when a stage's behaviour changes without changing its axis size, so old
# runs stop matching. (Example: CHARSET_ALL moved from 1 to 2 when the shared
# alpha/alphanumeric/all charset modes were introduced — same count of modes
# for some stages, different meaning.)
SEMANTICS_VERSION = 3


# ---------------------------------------------------------------------------
# Config file
# ---------------------------------------------------------------------------

@dataclass
class TrackerConfig:
    token: str = ""
    server: str = DEFAULT_SERVER
    runner: str = ""   # pseudonymous machine id, see machine_id()

    @property
    def enabled(self) -> bool:
        return bool(self.token)


def load_config() -> TrackerConfig:
    """Read ``~/.ee/config``; return an empty config when absent."""
    cfg = TrackerConfig()
    if not CONFIG_PATH.exists():
        return cfg
    try:
        for line in CONFIG_PATH.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key, value = key.strip(), value.strip()
            if hasattr(cfg, key):
                setattr(cfg, key, value)
    except OSError:
        return TrackerConfig()
    return cfg


def save_config(token: str, server: str | None = None, runner: str | None = None) -> Path:
    """Persist the join token (file is chmod 600 — it is a shared secret)."""
    cfg = load_config()
    cfg.token = token
    if server:
        cfg.server = server
    if runner:
        cfg.runner = runner
    if not cfg.runner:
        cfg.runner = machine_id()

    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(
        "# Ephemeral Enhancement client config\n"
        f"token={cfg.token}\n"
        f"server={cfg.server}\n"
        f"runner={cfg.runner}\n"
    )
    try:
        CONFIG_PATH.chmod(0o600)
    except OSError:
        pass
    return CONFIG_PATH


def _raw_machine_id() -> str:
    """
    Best-effort stable hardware identifier for this machine.

    Falls back through platform-specific sources to the NIC MAC address. The
    raw value never leaves the machine — `machine_id()` hashes it.
    """
    system = platform.system()
    try:
        if system == "Darwin":
            out = subprocess.run(
                ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                capture_output=True, text=True, timeout=5,
            ).stdout
            for line in out.splitlines():
                if "IOPlatformUUID" in line:
                    return line.split('"')[3]
        elif system == "Linux":
            for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
                candidate = Path(path)
                if candidate.exists():
                    value = candidate.read_text().strip()
                    if value:
                        return value
        elif system == "Windows":
            out = subprocess.run(
                ["reg", "query",
                 r"HKLM\SOFTWARE\Microsoft\Cryptography", "/v", "MachineGuid"],
                capture_output=True, text=True, timeout=5,
            ).stdout
            for line in out.splitlines():
                if "MachineGuid" in line:
                    return line.split()[-1]
    except Exception:
        pass
    # Universal fallback: the primary NIC's MAC address.
    return f"mac-{uuid.getnode():012x}"


def machine_id() -> str:
    """
    Pseudonymous, stable client identifier used to attribute runs.

    The hardware ID is hashed, so the dashboard shows a consistent handle for
    each machine without exposing a username, hostname, MAC or hardware UUID.
    """
    digest = hashlib.sha256(_raw_machine_id().encode()).hexdigest()[:12]
    return f"ee-{digest}"


# ---------------------------------------------------------------------------
# Fingerprint
# ---------------------------------------------------------------------------

def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def file_sha256(path: str | None) -> str | None:
    if not path:
        return None
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except OSError:
        return None


def compute_fingerprint(
    *,
    stages: list[str],
    axes: list[tuple[str, int]],
    ciphertext: str,
    dictionary_sha: str | None,
    n_keys: int,
    vary_case: bool,
) -> str:
    """Hash the whole searched space into a stable identifier."""
    spec = {
        "stages": stages,
        "axes": [[name, size] for name, size in axes],
        "ciphertext_sha": sha256_text(ciphertext),
        "dictionary_sha": dictionary_sha,
        "n_keys": n_keys,
        "vary_case": bool(vary_case),
        "semantics": SEMANTICS_VERSION,
    }
    return hashlib.sha256(
        json.dumps(spec, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _git(*args: str) -> subprocess.CompletedProcess[str] | None:
    """Run a git command in the project root, or None if git is unavailable."""
    try:
        return subprocess.run(
            ["git", *args],
            cwd=Path(__file__).resolve().parent.parent,
            capture_output=True, text=True, timeout=5,
        )
    except Exception:
        return None


def git_commit() -> str | None:
    """Short commit of the working tree, so odd results stay traceable."""
    out = _git("rev-parse", "--short", "HEAD")
    return out.stdout.strip() if out and out.stdout.strip() else None


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

class Tracker:
    """Thin, fail-open HTTP client for the tracker server."""

    def __init__(self, config: TrackerConfig | None = None):
        self.config = config or load_config()
        # EE_SERVER is an escape hatch for testing; normal use relies on the
        # URL stored at join time.
        override = os.getenv("EE_SERVER")
        if override:
            self.config.server = override

    @property
    def enabled(self) -> bool:
        return self.config.enabled

    def _request(self, method: str, path: str, payload: Any = None) -> Any:
        if not self.enabled:
            return None
        try:
            import httpx
        except ImportError:
            return None
        url = f"{self.config.server.rstrip('/')}{path}"
        headers = {"Authorization": f"Bearer {self.config.token}"}
        try:
            with httpx.Client(timeout=TIMEOUT) as client:
                r = client.request(method, url, json=payload, headers=headers)
                if r.status_code >= 400:
                    return None
                return r.json()
        except Exception:
            return None  # fail open: never block local work

    def lookup(self, fingerprint: str) -> dict[str, Any] | None:
        """Return a previously recorded run for this exact search space."""
        data = self._request("GET", f"/api/runs/{fingerprint}")
        if data and data.get("found"):
            return data["run"]
        return None

    def submit(self, payload: dict[str, Any]) -> bool:
        return self._request("POST", "/api/runs", payload) is not None

    def upstream_version(self) -> dict[str, Any] | None:
        return self._request("GET", "/api/version")

    def check_for_updates(self) -> str | None:
        """
        Warn only when the local checkout is genuinely *behind* upstream.

        Comparing SHAs alone only proves they differ — a local commit that is
        ahead of upstream, or a cached upstream response, would otherwise
        produce a bogus "run git pull".  When the upstream commit is present
        locally we can tell the two apart; when it is not, we say so neutrally
        instead of guessing.
        """
        info = self.upstream_version()
        if not info or "sha" not in info:
            return None
        local = git_commit()
        if not local:
            return None
        remote_sha = info["sha"]
        if remote_sha.startswith(local):
            return None  # up to date

        have = _git("cat-file", "-e", f"{remote_sha}^{{commit}}")
        if have is not None and have.returncode == 0:
            # We have the upstream commit locally, so the relationship is knowable.
            behind = _git("merge-base", "--is-ancestor", "HEAD", remote_sha)
            if behind is not None and behind.returncode == 0:
                return (
                    f"[update] behind upstream {info['short_sha']} "
                    f"({info.get('message', '')[:60]}). Run: git pull"
                )
            return None  # ahead of, or diverged from, upstream: not a problem
        return (
            f"[update] upstream is at {info['short_sha']}; local {local} "
            f"differs. Run: git fetch to compare."
        )
