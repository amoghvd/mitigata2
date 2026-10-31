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

## Speed on an 8 GB PC (measured, not promised)

- Old code: 200,000 sample rows in 49.2 s = 4,068 rows/s, RSS 289 MB.
- Fast code (orjson + direct ECS fields + one combined keyword regex +
  20,000-row batches + DuckDB memory = half RAM, max 4 GB): the same
  200,000 rows in 15.5 s = 12,866 rows/s, RSS 472 MB, with identical
  counts (200,000 rows, 10,020 alerts; 10,000-row sample = 501 alerts).
- Extrapolating a 6 GB JSONL log (~8-9M rows at ~700 bytes/line):
  roughly 11-12 minutes of ingestion, plus the post-load brute-force
  UPDATE and the dashboard aggregates. The DB file will be roughly
  3-4 GB, so keep disk free; RAM stays under ~1 GB for the Python
  process + DuckDB's 4 GB cap, well under 8 GB total.
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
