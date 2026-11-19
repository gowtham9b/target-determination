import json
from datetime import timedelta
from pathlib import Path

import pendulum
import requests
from airflow.decorators import dag, task


@dag(schedule=None, start_date=pendulum.datetime(2026, 1, 1), catchup=False)
def w5_user_order_summary():
    @task(retries=3, retry_delay=timedelta(seconds=1))
    def fetch(url):
        resp = requests.get(url)
        if not 200 <= resp.status_code <= 299:
            raise ValueError(f"{url}: unexpected status {resp.status_code}")
        return json.loads(resp.text)

    @task
    def extract(data, key):
        items = data.get(key)
        if not items:
            raise ValueError(f"no {key}")
        return items

    @task
    def count(items):
        if len(items) < 1:
            raise ValueError("empty")
        return len(items)

    @task
    def join(users, orders):
        return {"users": users, "orders": orders}

    @task
    def save(joined):
        Path("out").mkdir(exist_ok=True)
        Path("out/summary.json").write_text(json.dumps(joined))
        return joined

    users = count(extract(fetch.override(task_id="users")("https://api.example.com/v1/users"), "users"))
    orders = count(extract(fetch.override(task_id="orders")("https://api.example.com/v1/orders"), "orders"))
    save(join(users, orders))


w5_user_order_summary()
