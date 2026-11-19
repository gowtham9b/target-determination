#!/bin/sh
# Download the TaskBench data used in RQ7 at the commit pinned in external/taskbench/COMMIT.
set -e
cd "$(dirname "$0")/external/taskbench"
SHA=$(cat COMMIT)
for d in data_dailylifeapis data_huggingface data_multimedia; do
  mkdir -p "$d"
  for f in data.json tool_desc.json alignment_ids.json; do
    curl -fsSL -o "$d/$f" "https://raw.githubusercontent.com/microsoft/JARVIS/$SHA/taskbench/$d/$f"
  done
done
echo "TaskBench data at $SHA downloaded."
