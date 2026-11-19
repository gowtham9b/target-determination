from pathlib import Path

import pendulum
from airflow.decorators import dag, task
from airflow.operators.bash import BashOperator


@dag(schedule=None, start_date=pendulum.datetime(2026, 1, 1), catchup=False)
def w4_file_stats():
    @task
    def raw():
        text = Path("data/events.csv").read_text()
        if not text:
            raise ValueError("empty file")
        if len(text.encode()) > 1048576:
            raise ValueError("file too large")
        return text

    @task
    def size(text):
        return len(text)

    lines = BashOperator(task_id="lines", bash_command="wc -l data/events.csv", do_xcom_push=True)

    @task
    def result(lines, size):
        if not lines:
            raise ValueError("no output from wc")
        return {"lines": lines, "size": size}

    result(lines.output, size(raw()))


w4_file_stats()
