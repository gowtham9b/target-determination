import json
from concurrent.futures import ThreadPoolExecutor

from policy import Step


def get_json(name, url):
    with Step(name, net=[url]) as s:
        resp = s.get(url)
    if not 200 <= resp.status_code <= 299:
        raise RuntimeError(f"{url}: unexpected status {resp.status_code}")
    return json.loads(resp.text)


def main():
    with ThreadPoolExecutor() as pool:
        sales = pool.submit(get_json, "a", "https://api.example.com/sales")
        news = pool.submit(get_json, "b", "https://news.example.org/top")
        total = sales.result().get("total")
        headline = news.result().get("headline")
    if total is None or total < 0:
        raise RuntimeError("invalid total")
    if not headline:
        raise RuntimeError("missing headline")
    brief = f"Sales {total}; news: {headline}"
    with Step("summary", model="mock-1", tokens=2000) as s:
        summary = s.complete("mock-1", "Summarize: " + brief)
    if len(summary.encode()) > 2048:
        raise RuntimeError("summary too long")
    with Step("save", write="out") as s:
        s.write_text("out/brief.txt", summary)
    return summary


if __name__ == "__main__":
    print(main())
