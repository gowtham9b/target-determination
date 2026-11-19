import json
from datetime import timedelta

import pendulum
import requests
from airflow.decorators import dag, task

from llm import complete


@dag(schedule=None, start_date=pendulum.datetime(2026, 1, 1), catchup=False)
def w3_ticket_triage():
    @task(retries=2, retry_delay=timedelta(seconds=1))
    def fetch():
        resp = requests.get("https://api.example.com/tickets")
        if not 200 <= resp.status_code <= 299:
            raise ValueError(f"unexpected status {resp.status_code}")
        return json.loads(resp.text).get("open")

    @task.branch
    def choose(tickets):
        return "triage" if len(tickets) > 5 else "quiet"

    @task
    def triage(tickets):
        return complete(model="mock-1", prompt="Triage these tickets: " + json.dumps(tickets), max_tokens=500)

    @task
    def quiet(tickets):
        return f"{len(tickets)} open tickets"

    tickets = fetch()
    choose(tickets) >> [triage(tickets), quiet(tickets)]


w3_ticket_triage()
