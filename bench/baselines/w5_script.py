import json
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import requests


def get_with_retry(url, retries=3):
    for attempt in range(retries + 1):
        resp = requests.get(url)
        if 200 <= resp.status_code <= 299:
            return json.loads(resp.text)
        if attempt < retries:
            time.sleep(1)
    raise RuntimeError(f"{url}: unexpected status {resp.status_code}")


def main():
    with ThreadPoolExecutor() as pool:
        users = pool.submit(get_with_retry, "https://api.example.com/v1/users")
        orders = pool.submit(get_with_retry, "https://api.example.com/v1/orders")
        u = users.result().get("users")
        o = orders.result().get("orders")
    if not u:
        raise RuntimeError("no users")
    if not o:
        raise RuntimeError("no orders")
    joined = {"users": len(u), "orders": len(o)}
    if joined["users"] < 1 or joined["orders"] < 1:
        raise RuntimeError("empty join")
    Path("out").mkdir(exist_ok=True)
    Path("out/summary.json").write_text(json.dumps(joined))
    return joined


if __name__ == "__main__":
    print(main())
