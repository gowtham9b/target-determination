import json
import time

import requests

from llm import complete


def fetch_tickets(retries=2):
    for attempt in range(retries + 1):
        try:
            resp = requests.get("https://api.example.com/tickets")
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
        return complete(model="mock-1", prompt="Triage these tickets: " + json.dumps(tickets), max_tokens=500)
    return f"{n} open tickets"


if __name__ == "__main__":
    print(main())
