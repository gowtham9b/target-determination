"""Task specifications for the model-generation study.

Each task has an English specification, a normal world and (usually) a fault
world, the operations the task permits, and a reference TDG solution written
to check that the task is expressible and to compute the expected result.
The specification, not the reference, is what the model sees.
"""

import json


def ok(body):
    return {"status": 200, "body": json.dumps(body)}


def status(code, body=""):
    return {"status": code, "body": body}


LONG = " ".join(f"word{i}" for i in range(80))
NOTES = "tdg keeps the pipeline explicit\nso supervisors can audit it\n"

TASKS = [
    {
        "id": "T01",
        "spec": "Fetch https://api.example.com/orders, which returns JSON with an \"orders\" list. The HTTP status "
                "must be in 200-299. Count the orders; the count must not exceed 1000. Write the count to "
                "out/count.txt. The result is the count.",
        "world": {"https://api.example.com/orders": ok({"orders": [{"id": i} for i in range(42)]})},
        "fault": {"world": {"https://api.example.com/orders": status(500)}, "expect": "fail"},
        "allow": {"net": ["https://api.example.com/orders"], "write": ["out/count.txt"]},
        "files_out": {"out/count.txt": "42"},
        "ref": """cap net api{allow "https://api.example.com/orders";}
cap fs out{root "out";mode write;}
stage fetch:tool net.get{uses api;arg url="https://api.example.com/orders";check status 200..299;}
stage orders:transform field{after fetch;arg key="orders";}
stage n:transform count{after orders;check max 1000;}
stage save:tool fs.write{after n;uses out;arg path="out/count.txt";}
stage result:output{after save,n;in n;}""",
    },
    {
        "id": "T02",
        "spec": "Fetch https://api.example.com/sales (JSON with a numeric \"total\", which must be at least 0) and "
                "https://news.example.org/top (JSON with a non-empty \"headline\"); both statuses must be in 200-299. "
                "Build the text \"Sales <total>; news: <headline>\", then call model mock-1 with a prompt made of the "
                "word \"Summarize:\" followed by that text; at most 2000 prompt words may be spent. The summary must "
                "be at most 2048 bytes. Write it to out/brief.txt. The result is the summary.",
        "world": {"https://api.example.com/sales": ok({"total": 1250}),
                  "https://news.example.org/top": ok({"headline": "Markets steady"})},
        "fault": {"world": {"https://api.example.com/sales": ok({"total": 1250}),
                            "https://news.example.org/top": status(404)}, "expect": "fail"},
        "allow": {"net": ["https://api.example.com/sales", "https://news.example.org/top"], "model": ["mock-1"],
                  "write": ["out/brief.txt"]},
        "ref": """cap net sales{allow "https://api.example.com/sales";}
cap net news{allow "https://news.example.org/top";}
cap model llm{id "mock-1";tokens 2000;}
cap fs out{root "out";mode write;}
stage a:tool net.get{uses sales;arg url="https://api.example.com/sales";check status 200..299;}
stage b:tool net.get{uses news;arg url="https://news.example.org/top";check status 200..299;}
stage total:transform field{after a;arg key="total";check min 0;}
stage head:transform field{after b;arg key="headline";check nonempty;}
stage brief:transform template{after total,head;arg text="Sales {0}; news: {1}";}
stage summary:tool model.call{after brief;uses llm;arg model="mock-1",prompt="Summarize:";check maxbytes 2048;}
stage save:tool fs.write{after summary;uses out;arg path="out/brief.txt";}
stage result:output{after save,summary;in summary;}""",
    },
    {
        "id": "T03",
        "spec": "Fetch https://api.example.com/tickets, which returns JSON with an \"open\" list. If the status is not "
                "in 200-299, retry up to 2 more times before failing. Count the open tickets. If there are more than "
                "5, the result is the text \"escalate <count>\"; otherwise it is \"<count> open tickets\".",
        "world": {"https://api.example.com/tickets": ok({"open": [{"id": i} for i in range(8)]})},
        "fault": {"world": {"https://api.example.com/tickets": [status(503), status(503),
                                                                ok({"open": [{"id": 1}, {"id": 2}]})]},
                  "expect": "ok", "result": "2 open tickets"},
        "allow": {"net": ["https://api.example.com/tickets"]},
        "ref": """cap net api{allow "https://api.example.com/tickets";}
stage fetch:tool net.get{uses api;arg url="https://api.example.com/tickets";check status 200..299;viol retry 2;}
stage open:transform field{after fetch;arg key="open";}
stage n:transform count{after open;}
stage many:branch gt{after n;arg value=5;}
stage few:branch lt{after n;arg value=6;}
stage hi:transform template{after n,many;in n;when many;arg text="escalate {0}";}
stage lo:transform template{after n,few;in n;when few;arg text="{0} open tickets";}
stage r1:output{after hi;}
stage r2:output{after lo;}""",
    },
    {
        "id": "T04",
        "spec": "Run the command `wc -l data/events.csv` and read the file data/events.csv. The result is a JSON object "
                "whose key \"0\" holds the command's exact standard output and whose key \"1\" holds the number of "
                "characters in the file.",
        "world": {},
        "fault": {"remove": ["data/events.csv"], "expect": "fail"},
        "allow": {"read": ["data/events.csv"], "shell": [["wc", "-l", "data/events.csv"]]},
        "ref": """cap fs data{root "data";mode read;}
cap shell sh{allow "wc -l data/events.csv";}
stage lines:tool shell.run{uses sh;arg cmd="wc",args="-l data/events.csv";}
stage raw:tool fs.read{uses data;arg path="data/events.csv";}
stage size:transform length{after raw;}
stage both:transform merge{after lines,size;}
stage result:output{after both;}""",
    },
    {
        "id": "T05",
        "spec": "Fetch https://api.example.com/v1/users (JSON with a \"users\" list) and https://api.example.com/v1/orders "
                "(JSON with an \"orders\" list). For each, if the status is not in 200-299, retry up to 3 more times. "
                "Count each list; each count must be at least 1. Combine them into the JSON object "
                "{\"0\": <user count>, \"1\": <order count>} and write that object as JSON to out/summary.json. "
                "The result is the object.",
        "world": {"https://api.example.com/v1/users": [status(503), ok({"users": ["a", "b", "c"]})],
                  "https://api.example.com/v1/orders": ok({"orders": [1, 2, 3, 4]})},
        "fault": {"world": {"https://api.example.com/v1/users": status(503),
                            "https://api.example.com/v1/orders": ok({"orders": [1, 2, 3, 4]})}, "expect": "fail"},
        "allow": {"net": ["https://api.example.com/v1/users", "https://api.example.com/v1/orders"],
                  "write": ["out/summary.json"]},
        "ref": """cap net src{allow "https://api.example.com/v1/users" "https://api.example.com/v1/orders";}
cap fs out{root "out";mode write;}
stage users:tool net.get{uses src;arg url="https://api.example.com/v1/users";check status 200..299;viol retry 3;}
stage orders:tool net.get{uses src;arg url="https://api.example.com/v1/orders";check status 200..299;viol retry 3;}
stage u:transform field{after users;arg key="users";}
stage o:transform field{after orders;arg key="orders";}
stage nu:transform count{after u;check min 1;}
stage no:transform count{after o;check min 1;}
stage joined:transform merge{after nu,no;}
stage save:tool fs.write{after joined;uses out;arg path="out/summary.json";}
stage result:output{after joined,save;in joined;}""",
    },
    {
        "id": "T06",
        "spec": "Fetch https://api.example.com/catalog (status must be in 200-299), which returns JSON of the form "
                "{\"data\": {\"items\": [...]}}. Count the items in data.items; the count must not exceed 100. "
                "The result is the count.",
        "world": {"https://api.example.com/catalog": ok({"data": {"items": list(range(7))}})},
        "fault": {"world": {"https://api.example.com/catalog": ok({"data": {"items": list(range(150))}})},
                  "expect": "fail"},
        "allow": {"net": ["https://api.example.com/catalog"]},
        "ref": """cap net api{allow "https://api.example.com/catalog";}
stage fetch:tool net.get{uses api;arg url="https://api.example.com/catalog";check status 200..299;}
stage items:transform field{after fetch;arg key="data.items";}
stage n:transform count{after items;check max 100;}
stage result:output{after n;}""",
    },
    {
        "id": "T07",
        "spec": "Fetch https://shop.example.com/prices (status must be in 200-299), JSON with a \"prices\" list of "
                "numbers. The result is the sum of the prices, which must be at least 0.",
        "world": {"https://shop.example.com/prices": ok({"prices": [3, 4.5, 10]})},
        "fault": {"world": {"https://shop.example.com/prices": status(404)}, "expect": "fail"},
        "allow": {"net": ["https://shop.example.com/prices"]},
        "ref": """cap net shop{allow "https://shop.example.com/prices";}
stage fetch:tool net.get{uses shop;arg url="https://shop.example.com/prices";check status 200..299;}
stage prices:transform field{after fetch;arg key="prices";}
stage total:transform sum{after prices;check min 0;}
stage result:output{after total;}""",
    },
    {
        "id": "T08",
        "spec": "Read data/notes.txt, convert its text to upper case, and write the upper-case text to out/upper.txt. "
                "The result is the upper-case text.",
        "world": {},
        "files": {"data/notes.txt": NOTES},
        "fault": {"remove": ["data/notes.txt"], "expect": "fail"},
        "allow": {"read": ["data/notes.txt"], "write": ["out/upper.txt"]},
        "files_out": {"out/upper.txt": NOTES.upper()},
        "ref": """cap fs data{root "data";mode read;}
cap fs out{root "out";mode write;}
stage raw:tool fs.read{uses data;arg path="data/notes.txt";}
stage up:transform upper{after raw;}
stage save:tool fs.write{after up;uses out;arg path="out/upper.txt";}
stage result:output{after up,save;in up;}""",
    },
    {
        "id": "T09",
        "spec": "Fetch https://docs.example.com/page. The status must be in 200-299 and the body must be at most 1000 "
                "bytes. The result is the number of characters in the body.",
        "world": {"https://docs.example.com/page": status(200, "<p>" + "x" * 300 + "</p>")},
        "fault": {"world": {"https://docs.example.com/page": status(200, "y" * 5000)}, "expect": "fail"},
        "allow": {"net": ["https://docs.example.com/page"]},
        "ref": """cap net docs{allow "https://docs.example.com/page";}
stage fetch:tool net.get{uses docs;arg url="https://docs.example.com/page";check status 200..299;check maxbytes 1000;}
stage n:transform length{after fetch;}
stage result:output{after n;}""",
    },
    {
        "id": "T10",
        "spec": "Read data/notes.txt and call model mock-1 with a prompt made of the word \"Summarize:\" followed by "
                "the file's text; at most 200 prompt words may be spent. Write the summary to out/summary.txt. "
                "The result is the summary.",
        "world": {},
        "files": {"data/notes.txt": NOTES},
        "fault": {"files": {"data/notes.txt": " ".join(["long"] * 500)}, "expect": "fail"},
        "allow": {"read": ["data/notes.txt"], "model": ["mock-1"], "write": ["out/summary.txt"]},
        "ref": """cap fs data{root "data";mode read;}
cap fs out{root "out";mode write;}
cap model llm{id "mock-1";tokens 200;}
stage raw:tool fs.read{uses data;arg path="data/notes.txt";}
stage s:tool model.call{after raw;uses llm;arg model="mock-1",prompt="Summarize:";}
stage save:tool fs.write{after s;uses out;arg path="out/summary.txt";}
stage result:output{after s,save;in s;}""",
    },
    {
        "id": "T11",
        "spec": "Fetch https://api.example.com/alert (status must be in 200-299), JSON with a boolean \"urgent\" and a "
                "text \"msg\". If urgent is true, the result is the output of model mock-1 called with a prompt made "
                "of the word \"Escalate:\" followed by msg (at most 100 prompt words may be spent); otherwise the "
                "result is the text \"No action\".",
        "world": {"https://api.example.com/alert": ok({"urgent": True, "msg": "disk full on db-1"})},
        "fault": {"world": {"https://api.example.com/alert": ok({"urgent": False, "msg": "all good"})},
                  "expect": "ok", "result": "No action"},
        "allow": {"net": ["https://api.example.com/alert"], "model": ["mock-1"]},
        "ref": """cap net api{allow "https://api.example.com/alert";}
cap model llm{id "mock-1";tokens 100;}
stage fetch:tool net.get{uses api;arg url="https://api.example.com/alert";check status 200..299;}
stage urgent:transform field{after fetch;arg key="urgent";}
stage msg:transform field{after fetch;arg key="msg";}
stage yes:branch truthy{after urgent;}
stage no:branch eq{after urgent;arg value=false;}
stage esc:tool model.call{after msg,yes;in msg;when yes;uses llm;arg model="mock-1",prompt="Escalate:";}
stage quiet:transform template{after no;when no;arg text="No action";}
stage r1:output{after esc;}
stage r2:output{after quiet;}""",
    },
    {
        "id": "T12",
        "spec": "Fetch https://api.example.com/user (status must be in 200-299), JSON with text fields \"first\" and "
                "\"last\", both of which must be non-empty. The result is first and last joined by \" | \".",
        "world": {"https://api.example.com/user": ok({"first": "Ada", "last": "Lovelace"})},
        "fault": {"world": {"https://api.example.com/user": ok({"first": "Ada"})}, "expect": "fail"},
        "allow": {"net": ["https://api.example.com/user"]},
        "ref": """cap net api{allow "https://api.example.com/user";}
stage fetch:tool net.get{uses api;arg url="https://api.example.com/user";check status 200..299;}
stage f:transform field{after fetch;arg key="first";check nonempty;}
stage l:transform field{after fetch;arg key="last";check nonempty;}
stage name:transform concat{after f,l;arg sep=" | ";}
stage result:output{after name;}""",
    },
    {
        "id": "T13",
        "spec": "Fetch https://status.example.com/health. The status must be in 200-299. The result is the status "
                "code as an integer.",
        "world": {"https://status.example.com/health": status(204)},
        "fault": {"world": {"https://status.example.com/health": status(503)}, "expect": "fail"},
        "allow": {"net": ["https://status.example.com/health"]},
        "ref": """cap net st{allow "https://status.example.com/health";}
stage fetch:tool net.get{uses st;arg url="https://status.example.com/health";check status 200..299;}
stage code:transform status{after fetch;}
stage result:output{after code;}""",
    },
    {
        "id": "T14",
        "spec": "Fetch https://api.example.com/a, https://api.example.com/b and https://api.example.com/c; each returns "
                "JSON with an \"items\" list and each status must be in 200-299. The fetches are independent. The "
                "result is the JSON object {\"0\": <count of a>, \"1\": <count of b>, \"2\": <count of c>}.",
        "world": {"https://api.example.com/a": ok({"items": [1]}), "https://api.example.com/b": ok({"items": [1, 2]}),
                  "https://api.example.com/c": ok({"items": [1, 2, 3]})},
        "fault": {"world": {"https://api.example.com/a": ok({"items": [1]}), "https://api.example.com/b": status(500),
                            "https://api.example.com/c": ok({"items": [1, 2, 3]})}, "expect": "fail"},
        "allow": {"net": ["https://api.example.com/a", "https://api.example.com/b", "https://api.example.com/c"]},
        "ref": """cap net api{allow "https://api.example.com/a" "https://api.example.com/b" "https://api.example.com/c";}
stage ga:tool net.get{uses api;arg url="https://api.example.com/a";check status 200..299;}
stage gb:tool net.get{uses api;arg url="https://api.example.com/b";check status 200..299;}
stage gc:tool net.get{uses api;arg url="https://api.example.com/c";check status 200..299;}
stage ia:transform field{after ga;arg key="items";}
stage ib:transform field{after gb;arg key="items";}
stage ic:transform field{after gc;arg key="items";}
stage na:transform count{after ia;}
stage nb:transform count{after ib;}
stage nc:transform count{after ic;}
stage m:transform merge{after na,nb,nc;}
stage result:output{after m;}""",
    },
    {
        "id": "T15",
        "spec": "Run the commands `wc -l data/a.csv` and `wc -l data/b.csv`. The result is the standard output of the "
                "first followed directly by the standard output of the second, with nothing in between.",
        "world": {},
        "files": {"data/a.csv": "x\n1\n2\n", "data/b.csv": "y\n1\n"},
        "fault": {"remove": ["data/b.csv"], "expect": "fail"},
        "allow": {"shell": [["wc", "-l", "data/a.csv"], ["wc", "-l", "data/b.csv"]], "read": ["data/a.csv", "data/b.csv"]},
        "ref": """cap shell sh{allow "wc -l data/a.csv" "wc -l data/b.csv";}
stage a:tool shell.run{uses sh;arg cmd="wc",args="-l data/a.csv";}
stage b:tool shell.run{uses sh;arg cmd="wc",args="-l data/b.csv";}
stage both:transform concat{after a,b;}
stage result:output{after both;}""",
    },
    {
        "id": "T16",
        "spec": "Fetch https://api.example.com/config (status must be in 200-299), JSON with a numeric \"threshold\". "
                "If the threshold is greater than 10, write the text \"high\" to out/level.txt and the result is "
                "\"high\"; otherwise write \"low\" to out/level.txt and the result is \"low\".",
        "world": {"https://api.example.com/config": ok({"threshold": 14})},
        "fault": {"world": {"https://api.example.com/config": ok({"threshold": 3})}, "expect": "ok", "result": "low"},
        "allow": {"net": ["https://api.example.com/config"], "write": ["out/level.txt"]},
        "files_out": {"out/level.txt": "high"},
        "ref": """cap net api{allow "https://api.example.com/config";}
cap fs out{root "out";mode write;}
stage fetch:tool net.get{uses api;arg url="https://api.example.com/config";check status 200..299;}
stage t:transform field{after fetch;arg key="threshold";}
stage hi:branch gt{after t;arg value=10;}
stage lo:branch lt{after t;arg value=11;}
stage wh:tool fs.write{after hi;when hi;uses out;arg path="out/level.txt",text="high";}
stage wl:tool fs.write{after lo;when lo;uses out;arg path="out/level.txt",text="low";}
stage th:transform template{after hi,wh;in wh;when hi;arg text="high";}
stage tl:transform template{after lo,wl;in wl;when lo;arg text="low";}
stage r1:output{after th;}
stage r2:output{after tl;}""",
    },
    {
        "id": "T17",
        "spec": "Fetch https://api.example.com/team (status must be in 200-299), JSON with a \"users\" list. Count the "
                "users; the count must be at least 1. The result is the count.",
        "world": {"https://api.example.com/team": ok({"users": ["a", "b"]})},
        "fault": {"world": {"https://api.example.com/team": ok({"users": []})}, "expect": "fail"},
        "allow": {"net": ["https://api.example.com/team"]},
        "ref": """cap net api{allow "https://api.example.com/team";}
stage fetch:tool net.get{uses api;arg url="https://api.example.com/team";check status 200..299;}
stage u:transform field{after fetch;arg key="users";}
stage n:transform count{after u;check min 1;}
stage result:output{after n;}""",
    },
    {
        "id": "T18",
        "spec": "Fetch https://news.example.org/article (status must be in 200-299), JSON with a \"text\" field. Call "
                "model mock-1 with a prompt made of the word \"Summarize:\" followed by the text; at most 50 prompt "
                "words may be spent, and the call must not be made if that would exceed the budget. The result is "
                "the summary.",
        "world": {"https://news.example.org/article": ok({"text": " ".join(f"w{i}" for i in range(30))})},
        "fault": {"world": {"https://news.example.org/article": ok({"text": LONG})}, "expect": "fail"},
        "allow": {"net": ["https://news.example.org/article"], "model": ["mock-1"]},
        "ref": """cap net news{allow "https://news.example.org/article";}
cap model llm{id "mock-1";tokens 50;}
stage fetch:tool net.get{uses news;arg url="https://news.example.org/article";check status 200..299;}
stage text:transform field{after fetch;arg key="text";}
stage s:tool model.call{after text;uses llm;arg model="mock-1",prompt="Summarize:";}
stage result:output{after s;}""",
    },
    {
        "id": "T19",
        "spec": "Write the text \"ready\" to out/status.txt, then read out/status.txt back. The result is the text read "
                "back.",
        "world": {},
        "fault": None,
        "allow": {"write": ["out/status.txt"], "read": ["out/status.txt"]},
        "ref": """cap fs out{root "out";mode rw;}
stage w:tool fs.write{uses out;arg path="out/status.txt",text="ready";}
stage r:tool fs.read{after w;uses out;arg path="out/status.txt";}
stage result:output{after r;}""",
    },
    {
        "id": "T20",
        "spec": "Fetch https://api.example.com/v1/items (JSON with an \"items\" list) and https://api.example.com/v1/meta "
                "(JSON with a text \"version\"); both statuses must be in 200-299. The result is the text "
                "\"items=<number of items> version=<version>\".",
        "world": {"https://api.example.com/v1/items": ok({"items": [1, 2, 3]}),
                  "https://api.example.com/v1/meta": ok({"version": "2.1"})},
        "fault": {"world": {"https://api.example.com/v1/items": ok({"items": [1, 2, 3]}),
                            "https://api.example.com/v1/meta": status(404)}, "expect": "fail"},
        "allow": {"net": ["https://api.example.com/v1/items", "https://api.example.com/v1/meta"]},
        "ref": """cap net api{allow "https://api.example.com/v1/items" "https://api.example.com/v1/meta";}
stage gi:tool net.get{uses api;arg url="https://api.example.com/v1/items";check status 200..299;}
stage gm:tool net.get{uses api;arg url="https://api.example.com/v1/meta";check status 200..299;}
stage items:transform field{after gi;arg key="items";}
stage n:transform count{after items;}
stage v:transform field{after gm;arg key="version";}
stage text:transform template{after n,v;arg text="items={0} version={1}";}
stage result:output{after text;}""",
    },
]
