import json
import time

import requests

from policy import Step


def fetch_tickets(retries=2):
    with Step("fetch", net=["https://api.example.com/tickets"]) as s:
        for attempt in range(retries + 1):
            try:
                resp = s.get("https://api.example.com/tickets")
                break
            except requests.RequestException:
                if attempt == retries:
                    raise
                time.sleep(1)
    if not 200 <= resp.status_code <= 299:
        raise RuntimeError(f"unexpected status {resp.status_code}")
    return json.loads(resp.text).get("open")


def main():
    tickets = fetch_tickets()
    n = len(tickets)
    if n > 5:
        with Step("triage", model="mock-1", tokens=500) as s:
            return s.complete("mock-1", "Triage these tickets: " + json.dumps(tickets))
    return f"{n} open tickets"


if __name__ == "__main__":
    print(main())
