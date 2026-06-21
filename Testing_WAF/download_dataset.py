import sys
from pathlib import Path

import requests

DATA_DIR = Path(__file__).parent.parent / "dataset"
DATA_DIR.mkdir(exist_ok=True)
DEST = DATA_DIR / "data_capec_multilabel.csv"
URL = "https://dataverse.harvard.edu/api/access/datafile/6319496"
EXPECTED = 436_000_000


def main():
    if DEST.exists() and DEST.stat().st_size > EXPECTED * 0.95:
        print(f"Already downloaded: {DEST} ({DEST.stat().st_size/1e6:.1f} MB)")
        return
    print(f"Downloading SR-BH 2020 -> {DEST}")
    with requests.get(URL, stream=True, timeout=120, headers={"User-Agent": "Mozilla/5.0"}) as r:
        r.raise_for_status()
        total = int(r.headers.get("Content-Length", 0))
        done = 0
        with open(DEST, "wb") as f:
            for chunk in r.iter_content(chunk_size=1 << 20):
                f.write(chunk)
                done += len(chunk)
                if total:
                    sys.stdout.write(f"\r  {done/1e6:7.1f} / {total/1e6:7.1f} MB ({done*100//total}%)")
                    sys.stdout.flush()
    print(f"\nDone: {DEST.stat().st_size/1e6:.1f} MB")


if __name__ == "__main__":
    main()
