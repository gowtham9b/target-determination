import json
from pathlib import Path

import pendulum
import requests
from airflow.decorators import dag, task

from llm import complete


@dag(schedule=None, start_date=pendulum.datetime(2026, 1, 1), catchup=False)
def w2_daily_brief():
    @task
    def fetch(url):
        resp = requests.get(url)
        if not 200 <= resp.status_code <= 299:
            raise ValueError(f"{url}: unexpected status {resp.status_code}")
        return json.loads(resp.text)

    @task
    def total(data):
        value = data.get("total")
        if value is None or value < 0:
            raise ValueError("invalid total")
        return value

    @task
    def headline(data):
        value = data.get("headline")
        if not value:
            raise ValueError("missing headline")
        return value

    @task
    def brief(total, headline):
        return f"Sales {total}; news: {headline}"

    @task
    def summarize(text):
        summary = complete(model="mock-1", prompt="Summarize: " + text, max_tokens=2000)
        if len(summary.encode()) > 2048:
            raise ValueError("summary too long")
        return summary

    @task
    def save(summary):
        Path("out").mkdir(exist_ok=True)
        Path("out/brief.txt").write_text(summary)
        return summary

    sales = total(fetch.override(task_id="sales")("https://api.example.com/sales"))
    news = headline(fetch.override(task_id="news")("https://news.example.org/top"))
    save(summarize(brief(sales, news)))


w2_daily_brief()
