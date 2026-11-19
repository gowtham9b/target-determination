import subprocess
from pathlib import Path


def main():
    raw = Path("data/events.csv").read_text()
    if not raw:
        raise RuntimeError("empty file")
    if len(raw.encode()) > 1048576:
        raise RuntimeError("file too large")
    lines = subprocess.run(["wc", "-l", "data/events.csv"], capture_output=True, text=True, check=True).stdout
    if not lines:
        raise RuntimeError("no output from wc")
    return {"lines": lines, "size": len(raw)}


if __name__ == "__main__":
    print(main())
