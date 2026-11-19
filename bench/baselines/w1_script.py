import json
from pathlib import Path

import requests


def main():
    resp = requests.get("https://api.example.com/orders")
    if not 200 <= resp.status_code <= 299:
        raise RuntimeError(f"unexpected status {resp.status_code}")
    if len(resp.content) > 65536:
        raise RuntimeError("response too large")
    orders = json.loads(resp.text).get("orders")
    if not orders:
        raise RuntimeError("no orders")
    n = len(orders)
    if n > 1000:
        raise RuntimeError("too many orders")
    Path("out").mkdir(exist_ok=True)
    Path("out/count.txt").write_text(str(n))
    return n


if __name__ == "__main__":
    print(main())
