# Mitigata backend — how to run it

The UI is unchanged. The real backend is FastAPI + DuckDB in `backend/`
(restored from the old Python backend and fixed; the Rust path was removed
entirely). The Node `server.ts` still exists but serves the OLD in-memory
API — do not use it for real data. Use one of the two setups below.

## Option A — two dev servers (recommended for the hackathon demo)

```bash
cd ~/workspace/mitigata
python3 -m venv .venv && .venv/bin/pip install -r backend/requirements.txt
# Optional, heavy (~500 MB): real Qiskit QAOA. Without it, the quantum
# endpoint returns engine='qiskit-unavailable' with a classical fallback.
.venv/bin/pip install qiskit qiskit-aer scipy

# Terminal 1: backend on :8000
.venv/bin/uvicorn backend.main:app --host 0.0.0.0 --port 8000
# Terminal 2: frontend on :5173 (vite.config.ts proxies /api -> :8000)
npm run frontend
```

Or with the package scripts: `npm run backend` (needs uvicorn on PATH or
in the venv) and `npm run frontend`.

## Option B — docker compose (backend only; build the frontend separately)

```bash
docker compose up --build   # backend on :8000, data in a named volume
# then, for the UI: npm run build && run uvicorn — backend/main.py serves
# dist/ statically if it exists.
```

## Sarvam AI key — environment only, never committed

```bash
cp backend/.env.example backend/.env   # then edit it
# SARVAM_API_KEY=<your key here>
```

The backend reads `SARVAM_API_KEY` from the environment at call time only.
Without it, reports fall back to local Ollama (`OLLAMA_API_URL`,
`OLLAMA_MODEL`, default `llama3`), then to a deterministic template built
from real aggregate numbers. No key is stored in any file in this repo.

## How a 6 GB upload flows

1. `POST /api/ingest?job_id=...` (multipart field `file`) streams the
   upload in 1 MB chunks with an incremental UTF-8 decoder (split lines and
   split multi-byte characters are handled; gzip is detected by magic bytes).
2. Each line is parsed (nested ECS JSONL, flat JSON, syslog/plain text,
   CEF-ish, CSV with header skipped), stamped with Sigma/MITRE rules at
   ingest time, and bulk-inserted in batches of 5,000 via PyArrow
   (vectorized; the old `executemany` path measured ~500 rows/s and is only
   a fallback if pyarrow is missing).
3. After the stream ends, one post-load UPDATE stamps failed-logon rows
   from sources with >= 10 failed logons as SIGMA-003/T1110. It is an
   UPDATE, not a second ingestion, so rows are never double-counted.
4. `GET /api/ingest/progress?job_id=...` reports bytes actually read
   (not the unreliable `file.size`), percent, rows ingested and elapsed
   time, updated after every batch.
5. The dashboard payload (`/api/sample/load`, `/api/ingest` response,
   `/api/analyze`) is built from DuckDB aggregates over ALL rows
   (GROUP BY source/destination, tactic and severity counts, top edges),
   never from a 500-row sample. Graph nodes/edges follow
   `src/types/index.ts` exactly.

## Crazy-fast path for a 6 GB .log file (firex-10G.log and any .log)

Do NOT upload a 6 GB file through the browser. Put it in the repo root
on your PC and use the parallel local path:

```bash
# 1. Confirm the format mapping first (no data loaded)
python -m backend.ingest_file firex-10G.log --detect-only
#    prints jsonl / apache / syslog / cef / csv / plain + 5 parsed rows

# 2. Full parallel run (4 workers max, Parquet shards -> DuckDB)
python -m backend.ingest_file firex-10G.log
#    or via the API: POST /api/ingest/local?path=firex-10G.log
#    or check first: GET /api/ingest/detect?path=firex-10G.log
```

How it maps a .log file, automatically:
- FortiGate UTM (firex-10G.log, exact sample mapping):
  date+time -> timestamp (eventtime, epoch nanoseconds, is fallback only)
  srcip -> source_ip, dstip -> destination_ip, dstport -> port,
  subtype dns -> DNS_QUERY (traffic -> TRAFFIC, webfilter -> WEB_FILTER,
  ...), service -> event_type if subtype unknown, action pass -> ACCEPT
  and deny/block/drop/reset -> DENY, sentbyte+rcvdbyte -> bytes,
  hostname= -> domain (nytimes.com, aljazeera.com), devname= -> device_name.
  host_name is deliberately left empty: hostname= is the queried DNS
  domain, not the source host, and devname= is the firewall, not an
  endpoint. Quoted key=value values with spaces are parsed correctly.
  Sample logs show the domain in notes, e.g. notes = "nytimes.com".
- JSONL (ECS/EDR): source.ip, destination.ip, host.name, user.name,
  event.action, rule.name/id, threat.technique.id -> Mitigata schema.
- Apache/Nginx access log: IP, user, timestamp, method, status code
  (>=400 = DENY), byte count -> HTTP_REQUEST.
- Syslog / plain text: timestamp, IPs, host, ssh/login/auth/dns/
  kerberos/http/firewall keywords -> event type and DENY on fail/deny.
- CEF key=value and CSV: src/dst/user/host/action/status positionally
  or by key.
- Sigma/MITRE stamping is the same for all formats (see below).

Why it is fast on an 8 GB PC:
- File is split into byte ranges (aligned to line boundaries, so no
  row is lost or double-counted), each range is parsed in its own
  process to a Parquet shard, then DuckDB loads the shards with its
  C++ Parquet reader. No Python process ever holds the whole file.
- Workers are capped at 4 (~400-500 MB each) + DuckDB capped at 4 GB,
  so peak stays under 8 GB. Set MITIGATA_WORKERS=2 if you want less.
- For files over 500 MB, benign rows drop their raw_message copy
  (threat rows keep it); the dashboard does not use raw_message.
  Override with MITIGATA_STORE_RAW=all.
- Gzip files and files under 100 MB fall back to the single-threaded
  streaming path, which is still the 12,866 rows/s JSONL path below.

## Speed on an 8 GB PC (measured, not promised)

- Old code: 200,000 sample rows in 49.2 s = 4,068 rows/s, RSS 289 MB.
- Fast code (orjson + direct ECS fields + one combined keyword regex +
  20,000-row batches + DuckDB memory = half RAM, max 4 GB): the same
  200,000 rows in 15.5 s = 12,866 rows/s, RSS 472 MB, with identical
  counts (200,000 rows, 10,020 alerts; 10,000-row sample = 501 alerts).
- Parallel path, same 200,000-row file: 17,546 rows/s in 11.4 s
  (main-process RSS 331 MB; workers are additional, capped at 4).
  Extrapolating a 6.1 GB JSONL log (~8-9M rows at ~700 bytes/line):
  roughly 8-9 minutes of ingestion with the parallel path, plus the
  post-load brute-force UPDATE and the dashboard aggregates. The DB
  file will be roughly 2-4 GB (less with raw dropped for benign rows),
  so keep disk free; RAM stays under 8 GB total with 4 workers.
- If your 6 GB file is NOT JSONL (syslog/CSV/CEF), the generic parser
  is used and will be slower than the JSONL fast path; the batch and
  memory settings still apply. Tell Wally the format if it is slow.

## Memory / disk expectations (measured, not promised)

- 10,000 sample rows: ingest ~2.2 s, dashboard ~2.4 s.
- 300,000 rows / 244 MB synthetic log: ingest ~80 s (~3,750 rows/s,
  parse-bound), progress updated every batch, server RSS ~360 MB,
  DuckDB file ~161 MB. Rows and alerts matched exactly (300,000 rows,
  15,030 alerts = 30 x 501), no double counting.
- Extrapolating (not tested — the 6 GB file was not supplied): a 6 GB
  log at the same rate takes roughly 30–35 minutes and produces roughly
  a 4 GB DuckDB file. Keep the machine's disk free accordingly and do
  not run anything else memory-heavy in parallel. No secondary indexes
  are created during load; aggregates are full GROUP BY scans, which is
  what DuckDB is built for.

## Endpoints

- `GET /api/health` — real row count, alert count, DB size, RSS.
- `POST /api/sample/load` — clears the DB, streams `edr_events.json`
  through the same ingestion path as uploads, returns the dashboard payload.
- `POST /api/ingest?job_id=...`, `GET /api/ingest/progress?job_id=...`
- `GET /api/logs/sample?limit=50`, `DELETE /api/logs`
- `POST /api/analyze`, `GET /api/graph/topology`, `POST /api/risk-scores`,
  `POST /api/quantum-predict`
- `POST /api/reports/generate`, `GET /api/reports/download/{report_id}`

## Risk & quantum, honestly

- Risk: weighted multi-factor heuristic, weights severity 0.30, tactic
  0.25, frequency 0.20, graph centrality 0.15, confidence 0.10, plus a
  JEV layer (verified only with >= 2 tactics and >= 2 sources, or
  lateral/exfiltration presence; merged alert count is reported).
- Quantum: QAOA (p=2) on a MaxCut Hamiltonian built from the attack-graph
  adjacency (current node + its neighbours as qubits), COBYLA on the
  statevector simulator. The optimal cut bitstring and its probability
  are reported; candidate next-hop probabilities are a classical softmax
  over graph weights, labelled as such in the engine string. If Qiskit is
  not installed, `quantum_engine` is exactly `qiskit-unavailable`.


## Complete push: what is in the repo, and what cannot be pushed this way
- All code, backend, frontend, Dockerfile, docker-compose, requirements,
  RUNNING_LOCALLY.md and this README are on GitHub (amoghvd/mitigata2).
- `edr_events.json` (7.2 MB) and the PNG images cannot be pushed through
  the GitHub snapshot route: it only accepts UTF-8 text and returns 413
  for the 7.2 MB sample, and rejects PNGs as "not UTF-8". They are NOT
  needed to run: the logo is now `public/logo.svg` (text, in the repo),
  and `POST /api/sample/load` auto-generates a 10,000-event sample with
  `edr_log_generator.py` if `edr_events.json` is missing. If you want
  the exact original sample, run that generator yourself, or upload
  `edr_events.json` via the GitHub web UI.
- Uploading a 6 GB file: do NOT use the browser upload as the only path.
  Put the file in the repo root and use `python -m backend.ingest_file
  firex-10G.log` (parallel) or `POST /api/ingest/local?path=firex-10G.log`.
  The browser upload (`POST /api/ingest`) now returns after parsing and
  the frontend fetches `GET /api/dashboard` separately, and the Vite
  proxy timeout is set to 1 hour, so a long upload is not dropped by
  the proxy. A DuckDB 2.0 quirk was fixed in this push: `fetchone()`
  left a result open and blocked the next PyArrow batch insert with
  "Resource In Use" -- all counts now use `fetchall()`.


## Attack paths, confidence, and the Sarvam story
- `GET /api/paths` returns every ranked attack path (up to 10, up to 4 hops)
  with a confidence score each. Confidence = geometric mean of
  (threat_count + 0.5) / (count + 1) per hop. The top path is flagged
  `is_most_likely`. Benign-only flows are never listed as attack paths.
- `GET /api/story` returns a short story of the most likely path, plus
  `provider` / `is_sarvam`. If `SARVAM_API_KEY` is not set in
  `backend/.env`, the provider is honestly reported as Ollama fallback
  or deterministic template -- the UI labels it "NOT Sarvam AI" in that
  case, instead of pretending it is Sarvam.
- `POST /api/sample/demo` loads `sample_demo.jsonl` (5 rows, one clear
  chain) for demos. The dashboard also has a "Tiny Demo (5 rows)" button.


## Logo: where to put logo.png, and removing its white background
- Proper location: `public/logo.png` in the repo root (next to
  `public/logo.svg`). The navbar tries `/logo.png` first and falls back
  to `/logo.svg` if it is missing, so the site never shows a broken
  image. For the favicon, after you add `logo.png`, change one line in
  `index.html` from
  `<link rel="icon" type="image/svg+xml" href="/logo.svg" />`
  to
  `<link rel="icon" type="image/png" href="/logo.png" />`
  (browsers do not fall back on favicons, so this swap is manual).
- White background: after putting `logo.png` in `public/`, run, from
  the repo root:
  ```
  pip install pillow
  python scripts/remove_white_bg.py
  ```
  That makes near-white pixels transparent, in place, without changing
  any other colour. Do NOT commit a logo.png with a white background
  if you want it to sit cleanly on the dark navbar.
- Note: `logo.png` is a binary file and cannot be pushed through the
  GitHub snapshot route used here, so it must be added on your PC (or
  via the GitHub web UI) after pulling -- it will not appear in a
  snapshot push from Muse.
