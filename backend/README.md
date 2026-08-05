# Ephemeral Enhancement — run tracker

A small FastAPI + SQLite service that records which pipelines have been run
against which ciphertexts, so a group can split the search space instead of
repeating each other's work.

- **Dashboard** — every run, per-target coverage, and any hits.
- **Skip work already done** — the client asks before running and stops early.
- **Update banner** — polls the public GitHub API (no token needed) so runners
  know when their checkout is stale.

## Run the server

```bash
cd backend
python3 -m venv .venv
./.venv/bin/pip install -r requirements.txt

cp .env.example .env
# edit .env and set EE_TOKEN to a long random string

./.venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000
```

Dashboard at `http://localhost:8000`, API docs at `/api/docs`.

`.env` and `runs.db` are gitignored — the token is a shared secret, keep it out
of the repo.

## Join from a client

Once per machine:

```bash
python run_pipeline.py --join-network <token> --server https://your-host:8000
```

That writes `~/.ee/config` (mode 600). Every later run uses it automatically:

```bash
python run_pipeline.py --pipeline "beaufort>b64" --dictionary dicts/druon.txt --vary-case
```

If someone already covered that exact space you get:

```
[network] already searched by alice@box on 2026-08-04 22:56:59 - 540 combos, 0 hits
[network] skipping (use --force to run anyway)
```

| Flag | Effect |
|------|--------|
| `--join-network TOKEN` | Save token (and `--server`) then exit |
| `--server URL` | Server to join. **Only valid with `--join-network`** — it is stored in `~/.ee/config` and reused automatically |
| `--no-track` | Ignore the tracker for this run |
| `--force` | Run even if already covered |

After joining, normal runs need no network flags at all.

## Runner identity

Runs are attributed to a pseudonymous machine id such as `ee-dd15aae12a40`.
It is `sha256(hardware id)` truncated to 12 hex characters, sourced from:

| OS | Source |
|----|--------|
| macOS | `IOPlatformUUID` |
| Linux | `/etc/machine-id` |
| Windows | registry `MachineGuid` |
| any | MAC address fallback |

The raw hardware id never leaves the machine — only the hash is sent — so the
dashboard gets a stable per-machine handle without exposing a username,
hostname, MAC or hardware UUID. Set `runner=` in `~/.ee/config` to override.

## Why runs are keyed by fingerprint, not pipeline name

The dedup key is a SHA-256 of the **whole searched space**: stage list, each
stage's axis size, ciphertext, dictionary contents, key count, `--vary-case`,
and a `SEMANTICS_VERSION`.

Pipeline string alone is not enough. When extra alphabets were added to the
polyalphabetic stages, `beaufort>b64` grew from 24 to 120 combinations. Keyed on
the name, the server would have said "already run" and hidden 96 untested
combinations. Because axis sizes feed the hash, the fingerprint changes and the
larger space becomes runnable again.

Bump `SEMANTICS_VERSION` in `core/tracker.py` when a stage changes *behaviour*
without changing its axis *size*.

## Failure behaviour

Every network call fails open. A dead server, bad token or timeout prints a
warning and the pipeline runs anyway — tracking never blocks cracking.

## API

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| `GET` | `/api/runs/{fingerprint}` | none | Has this space been searched? |
| `POST` | `/api/runs` | Bearer | Record a run |
| `GET` | `/api/stats` | none | Totals |
| `GET` | `/api/version` | none | Latest upstream commit (cached 10 min) |

`GET /api/version` proxies the unauthenticated GitHub API (60 req/hour per IP)
and caches for 10 minutes, so many clients cost one upstream request.

## Deploying

SQLite in WAL mode is fine for a handful of runners. For anything busier, put it
behind a real host and consider Postgres. To expose it quickly:

```bash
./.venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000
# then a tunnel, e.g.  cloudflared tunnel --url http://localhost:8000
```

Note the API has no rate limiting and clients self-report their counts, so only
hand the token to people you trust. Each run stores the client's git commit so
odd numbers stay traceable.
