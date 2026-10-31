"""CLI for fast local ingestion (avoids a 6 GB browser upload).

Usage, from the repo root:
    python -m backend.ingest_file firex-10G.log
    python -m backend.ingest_file firex-10G.log --workers 4 --detect-only
    python -m backend.ingest_file firex-10G.log --single

--detect-only reads the first 200 lines, prints the detected format and
the first 5 parsed rows, and exits without loading anything. Use it to
confirm the mapping for a new .log dataset before a full run.
"""
import argparse
import os
import sys
import time


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--workers", type=int, default=None)
    ap.add_argument("--single", action="store_true",
                    help="single-threaded ingest_path instead of parallel")
    ap.add_argument("--detect-only", action="store_true")
    args = ap.parse_args()

    from backend.ingestion import detect_format, ingest_path, ingest_path_parallel, parse_line

    if args.detect_only:
        with open(args.path, "rb") as fh:
            head = [fh.readline().decode("utf-8", errors="replace")
                    for _ in range(200)]
        fmt = detect_format(head)
        print(f"detected_format={fmt} size_bytes={os.path.getsize(args.path)}")
        for line in head[:5]:
            if line.strip():
                print(parse_line(line.rstrip("\n")))
        return 0

    from backend.database import clear_logs
    # Do not auto-clear: the caller can DELETE /api/logs first if wanted.
    start = time.time()
    if args.single:
        rows, alerts, size, dur = ingest_path(args.path)
    else:
        rows, alerts, size, dur = ingest_path_parallel(args.path, workers=args.workers)
    print(f"rows={rows} alerts={alerts} bytes={size} "
          f"duration_s={dur:.1f} rows_per_s={rows / dur:.0f}" if dur else f"rows={rows}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
