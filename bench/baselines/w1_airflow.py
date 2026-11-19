import json
from pathlib import Path

import pendulum
import requests
from airflow.decorators import dag, task


@dag(schedule=None, start_date=pendulum.datetime(2026, 1, 1), catchup=False)
def w1_order_count():
    @task
    def fetch():
        resp = requests.get("https://api.example.com/orders")
        if not 200 <= resp.status_code <= 299:
            raise ValueError(f"unexpected status {resp.status_code}")
        if len(resp.content) > 65536:
            raise ValueError("response too large")
        return resp.text

    @task
    def orders(text):
        items = json.loads(text).get("orders")
        if not items:
            raise ValueError("no orders")
        return items

    @task
    def count(items):
        n = len(items)
        if n > 1000:
            raise ValueError("too many orders")
        return n

    @task
    def save(n):
        Path("out").mkdir(exist_ok=True)
        Path("out/count.txt").write_text(str(n))
        return n

    save(count(orders(fetch())))


w1_order_count()
