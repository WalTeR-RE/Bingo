import os
import time

_ENV_VAR = "BINGO_PROGRESS_FILE"


def set_progress(message: str) -> None:
    path = os.environ.get(_ENV_VAR)
    if not path:
        return
    try:
        line = f"{int(time.time())}\t{str(message)[:300]}"
        with open(path, "w", encoding="utf-8") as f:
            f.write(line)
    except Exception:
        pass


def read_progress(path: str):
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as f:
            raw = f.read().strip()
        ts, _, message = raw.partition("\t")
        return {"ts": int(ts), "message": message}
    except Exception:
        return None
