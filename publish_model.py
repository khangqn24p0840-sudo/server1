"""Publish a TFLite model to the integrated ScamShield Flask server.

Usage:
  python publish_model.py --model ../ml/exports/scam_text.tflite --version 2

The script writes to MODEL_DIR (default: data/models) atomically and creates
the manifest used by the Android app.
"""
from pathlib import Path
import argparse, hashlib, json, os, re, tempfile, shutil
from datetime import datetime

ROOT = Path(__file__).resolve().parent
MODEL_DIR = Path(os.environ.get("MODEL_DIR", str(ROOT / "data" / "models")))
MODEL_DIR.mkdir(parents=True, exist_ok=True)
MAX_BYTES = int(os.environ.get("MAX_MODEL_BYTES", str(50 * 1024 * 1024)))

ap = argparse.ArgumentParser()
ap.add_argument("--model", required=True)
ap.add_argument("--version", required=True)
args = ap.parse_args()

src = Path(args.model).resolve()
version = args.version.strip()
if not re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z._-]{0,31}", version):
    raise SystemExit("Version không hợp lệ")
if not src.is_file() or src.stat().st_size <= 0:
    raise SystemExit(f"Không tìm thấy model: {src}")
if src.stat().st_size > MAX_BYTES:
    raise SystemExit("Model quá lớn")
with src.open("rb") as f:
    if f.read(8)[4:8] != b"TFL3":   # định danh FlatBuffer nằm ở byte 4..8
        raise SystemExit("File không có chữ ký TFL3 của TensorFlow Lite")

dst = MODEL_DIR / "scam_text.tflite"
tmp = MODEL_DIR / f".scam_text.{os.getpid()}.tmp"
shutil.copy2(src, tmp)
os.replace(tmp, dst)

h = hashlib.sha256()
with dst.open("rb") as f:
    for chunk in iter(lambda: f.read(1024 * 1024), b""):
        h.update(chunk)
digest = h.hexdigest()

(MODEL_DIR / "scam_text.version").write_text(version, encoding="utf-8")
manifest = {
    "version": version,
    "filename": "scam_text.tflite",
    "size": dst.stat().st_size,
    "sha256": digest,
    "updated_at": datetime.now().astimezone().isoformat(),
}
m_tmp = MODEL_DIR / f".manifest.{os.getpid()}.tmp"
m_tmp.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
os.replace(m_tmp, MODEL_DIR / "scam_text.manifest.json")
print(f"Đã publish model v{version}: {dst}")
print(f"SHA-256: {digest}")