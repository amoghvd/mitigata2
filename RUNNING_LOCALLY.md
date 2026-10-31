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

- Sample load: click the sample option in the dashboard. It streams
  `edr_events.json` through the same ingestion path as an upload.
  If that file is missing in your clone, regenerate an equivalent
  10,000-event sample with the generator already in the repo:
  ```bash
  python edr_log_generator.py --count 10000 --output file --file edr_events.json
  ```
  (Generated events are random, so counts will differ from the original
  sample, but the shape is the same.)
- Your own log: use the dashboard upload (multipart field `file`,
  `POST /api/ingest`), then poll `GET /api/ingest/progress`.
  A 6 GB log takes roughly 30–35 minutes at the measured ~3,750 rows/s
  and produces roughly a 4 GB DuckDB file (`mitigata_logs.duckdb`),
  so keep disk free.
- Reports: `POST /api/reports/generate`, then download the PDF from
  `GET /api/reports/download/{report_id}`.

## Notes

- `public/logo.png` (navbar logo / favicon) and the unreferenced images
  under `public/assets/aistudio/` are not in this repo snapshot: the
  snapshot push route only handles text files. The app still runs
  without them; the logo will just be a broken image until you add a
  `public/logo.png` of your own.
- `mitigata_logs.duckdb`, `.venv/`, `__pycache__/`, `uploads/` and
  `backend/.env` are git-ignored and are created locally when you run it.
