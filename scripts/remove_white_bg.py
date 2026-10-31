"""Remove a white background from public/logo.png, in place.

Usage, from the repo root, after putting your logo.png in public/:
    python scripts/remove_white_bg.py
    python scripts/remove_white_bg.py public/logo.png

White (or near-white) pixels become transparent. No other colours are
changed. Requires Pillow: pip install pillow.
"""
import sys
from pathlib import Path

def main() -> int:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("public/logo.png")
    if not path.exists():
        print(f"Not found: {path} -- put your logo.png there first.")
        return 1
    try:
        from PIL import Image
    except ImportError:
        print("Pillow is not installed. Run: pip install pillow")
        return 1
    img = Image.open(path).convert("RGBA")
    out = []
    for r, g, b, a in img.getdata():
        if r >= 245 and g >= 245 and b >= 245:
            out.append((r, g, b, 0))
        else:
            out.append((r, g, b, a))
    img.putdata(out)
    img.save(path)
    print(f"Saved transparent-background logo: {path} ({img.size[0]}x{img.size[1]})")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
