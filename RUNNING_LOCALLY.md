# Run Mitigata locally after cloning

Prerequisites: Python 3.12+, Node.js 20+, Git. No Docker needed for this path.

## 1. Clone

```bash
git clone https://github.com/amoghvd/mitigata2.git
cd mitigata2
```

## 2. Backend (FastAPI + DuckDB)

```bash
# Windows (PowerShell)
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# macOS / Linux
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Optional, for real Qiskit QAOA (otherwise the quantum endpoint reports
`qiskit-unavailable` and uses a classical fallback):

```bash
pip install qiskit qiskit-aer scipy
```

Optional, for Sarvam AI narratives (otherwise reports fall back to local
Ollama, then to a deterministic template built from real numbers):

```bash
copy backend\.env.example backend\.env   # Windows
cp backend/.env.example backend/.env     # macOS / Linux
# then edit backend/.env and put your key in SARVAM_API_KEY.
# Never commit backend/.env.
```

Run the backend (keep this terminal open):

```bash
uvicorn backend.main:app --host 0.0.0.0 --port 8000
# or: npm run backend   (only if uvicorn is on your PATH / in the venv)
```

## 3. Frontend (React + Vite)

In a second terminal, from the repo root:

```bash
npm install
npm run frontend
```

Open http://localhost:5173 — Vite proxies `/api` to the backend on :8000.

Do NOT use `npm run dev` / `server.ts` for real data: that is the old
in-memory Node API. The real path is `npm run frontend` + the FastAPI
backend above.

## 4. Try it

- Sample load: click the sample option in the dashboard. If
  `edr_events.json` is missing in your clone, the backend auto-generates
  an equivalent 10,000-event sample with `edr_log_generator.py`
  (generated events are random, so counts will differ from the original
  sample, but the shape is the same).
- Your own log, best for a 6 GB file: do NOT upload it through the
  browser. Put `firex-10G.log` in the repo root, then, with the venv
  activated, from the repo root:
  ```bash
  python -m backend.ingest_file firex-10G.log --detect-only
  python -m backend.ingest_file firex-10G.log
  ```
  Or, with the backend running: `POST /api/ingest/local?path=firex-10G.log`.
  The parallel path measured ~17,500 rows/s on a 200k-row test, so a
  6.1 GB JSONL log (~8-9M rows) is roughly 8-9 minutes, and the DuckDB
  file (`mitigata_logs.duckdb`) is roughly 2-4 GB -- keep 10 GB free.
  A browser upload also works (`POST /api/ingest`), then the frontend
  fetches `GET /api/dashboard` separately.
- Reports: `POST /api/reports/generate`, then download the PDF from
  `GET /api/reports/download/{report_id}`.

## Notes

- The logo is now `public/logo.svg` (a text file, so it pushes fine).
  The original `public/logo.png` and the unreferenced images under
  `public/assets/aistudio/` are not in this repo snapshot: the snapshot
  push route only handles text files, and is not needed to run.
- `mitigata_logs.duckdb`, `.venv/`, `__pycache__/`, `uploads/` and
  `backend/.env` are git-ignored and are created locally when you run it.
