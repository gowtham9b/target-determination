import json

from policy import Step


def main():
    with Step("fetch", net=["https://api.example.com/*"]) as s:
        resp = s.get("https://api.example.com/orders")
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
    with Step("save", write="out") as s:
        s.write_text("out/count.txt", str(n))
    return n


if __name__ == "__main__":
    print(main())
