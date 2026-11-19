from policy import Step


def main():
    with Step("raw", read="data") as s:
        raw = s.read_text("data/events.csv")
    if not raw:
        raise RuntimeError("empty file")
    if len(raw.encode()) > 1048576:
        raise RuntimeError("file too large")
    with Step("lines", shell=["wc -l data/events.csv"]) as s:
        lines = s.run(["wc", "-l", "data/events.csv"])
    if not lines:
        raise RuntimeError("no output from wc")
    return {"lines": lines, "size": len(raw)}


if __name__ == "__main__":
    print(main())
