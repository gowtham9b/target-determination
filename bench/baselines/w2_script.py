import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import requests

from llm import complete


def get_json(url):
    resp = requests.get(url)
    if not 200 <= resp.status_code <= 299:
        raise RuntimeError(f"{url}: unexpected status {resp.status_code}")
    return json.loads(resp.text)


def main():
    with ThreadPoolExecutor() as pool:
        sales = pool.submit(get_json, "https://api.example.com/sales")
        news = pool.submit(get_json, "https://news.example.org/top")
        total = sales.result().get("total")
        headline = news.result().get("headline")
    if total is None or total < 0:
        raise RuntimeError("invalid total")
    if not headline:
        raise RuntimeError("missing headline")
    brief = f"Sales {total}; news: {headline}"
    summary = complete(model="mock-1", prompt="Summarize: " + brief, max_tokens=2000)
    if len(summary.encode()) > 2048:
        raise RuntimeError("summary too long")
    Path("out").mkdir(exist_ok=True)
    Path("out/brief.txt").write_text(summary)
    return summary


if __name__ == "__main__":
    print(main())
