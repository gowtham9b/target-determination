"""The five evaluation workloads: TDG source, simulated endpoints and files."""

import json
import os

W1 = """cap net api{allow "https://api.example.com/*";}
cap fs out{root "out";mode write;}
stage fetch:tool net.get{uses api;arg url="https://api.example.com/orders";check status 200..299;check maxbytes 65536;viol propose;}
stage orders:transform field{after fetch;arg key="orders";check nonempty;viol propose;}
stage n:transform count{after orders;check max 1000;viol propose;}
stage save:tool fs.write{after n;uses out;arg path="out/count.txt";}
stage result:output{after save,n;in n;}
"""

W2 = """cap net sales{allow "https://api.example.com/sales";}
cap net news{allow "https://news.example.org/top";}
cap model llm{id "mock-1";tokens 2000;}
cap fs out{root "out";mode write;}
stage a:tool net.get{uses sales;arg url="https://api.example.com/sales";check status 200..299;viol propose;}
stage b:tool net.get{uses news;arg url="https://news.example.org/top";check status 200..299;viol propose;}
stage total:transform field{after a;arg key="total";check min 0;viol propose;}
stage head:transform field{after b;arg key="headline";check nonempty;viol propose;}
stage brief:transform template{after total,head;arg text="Sales {0}; news: {1}";}
stage summary:tool model.call{after brief;uses llm;arg model="mock-1",prompt="Summarize:";check maxbytes 2048;viol propose;}
stage save:tool fs.write{after summary;uses out;arg path="out/brief.txt";}
stage result:output{after save,summary;in summary;}
"""

W3 = """cap net api{allow "https://api.example.com/tickets";}
cap model llm{id "mock-1";tokens 500;}
stage fetch:tool net.get{uses api;arg url="https://api.example.com/tickets";check status 200..299;fail retry 2;viol propose;}
stage open:transform field{after fetch;arg key="open";}
stage n:transform count{after open;}
stage many:branch gt{after n;arg value=5;}
stage few:branch lt{after n;arg value=6;}
stage triage:tool model.call{after open,many;in open;when many;uses llm;arg model="mock-1",prompt="Triage these tickets:";}
stage quiet:transform template{after n,few;in n;when few;arg text="{0} open tickets";}
stage escalate:output{after triage;}
stage report:output{after quiet;}
"""

W4 = """cap fs data{root "data";mode read;}
cap shell sh{allow "wc -l data/*.csv";}
stage raw:tool fs.read{uses data;arg path="data/events.csv";check nonempty;check maxbytes 1048576;viol propose;}
stage lines:tool shell.run{uses sh;arg cmd="wc",args="-l data/events.csv";check nonempty;}
stage size:transform length{after raw;}
stage result:output{after lines,size;}
"""

W5 = """cap net src{allow "https://api.example.com/v1/*";}
cap fs out{root "out";mode write;}
stage users:tool net.get{uses src;arg url="https://api.example.com/v1/users";check status 200..299;viol retry 3;}
stage orders:tool net.get{uses src;arg url="https://api.example.com/v1/orders";check status 200..299;viol retry 3;}
stage u:transform field{after users;arg key="users";check nonempty;viol propose;}
stage o:transform field{after orders;arg key="orders";check nonempty;viol propose;}
stage nu:transform count{after u;check min 1;}
stage no:transform count{after o;check min 1;}
stage joined:transform merge{after nu,no;}
stage save:tool fs.write{after joined;uses out;arg path="out/summary.json";}
stage result:output{after joined,save;in joined;}
"""

SOURCES = {"W1": W1, "W2": W2, "W3": W3, "W4": W4, "W5": W5}


def endpoints(name: str) -> dict:
    ok = lambda body: {"status": 200, "body": json.dumps(body)}  # noqa: E731
    return {
        "W1": {"https://api.example.com/orders": ok({"orders": [{"id": i} for i in range(42)]})},
        "W2": {
            "https://api.example.com/sales": ok({"total": 1250}),
            "https://news.example.org/top": ok({"headline": "Markets steady"}),
        },
        "W3": {"https://api.example.com/tickets": ok({"open": [{"id": i} for i in range(8)]})},
        "W4": {},
        "W5": {
            "https://api.example.com/v1/users": [{"status": 503, "body": ""}, ok({"users": ["a", "b", "c"]})],
            "https://api.example.com/v1/orders": ok({"orders": [1, 2, 3, 4]}),
        },
    }[name]


def prepare_workdir(path: str) -> str:
    os.makedirs(os.path.join(path, "data"), exist_ok=True)
    os.makedirs(os.path.join(path, "out"), exist_ok=True)
    with open(os.path.join(path, "data", "events.csv"), "w") as f:
        f.write("ts,event\n" + "".join(f"{i},click\n" for i in range(100)))
    os.makedirs(os.path.join(path, "private"), exist_ok=True)
    with open(os.path.join(path, "private", "secret.txt"), "w") as f:
        f.write("not for stages\n")
    return path
