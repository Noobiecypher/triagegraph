import json
import random
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from triagegraph.models import Alert

# -- configuration ----------------------------------

@dataclass
class GeneratorConfig:
        total: int = 100
        output_path: Path = Path("data/alerts_60.json")
        high_ratio: float = 0.25 # 25% high severity
        low_ratio: float = 0.5 # 50% low severity(noise)
        # remaining 25% will be medium


# -- realistic value pools ----------------------------

MALICIOUS_IPS = [
    "203.0.113.9", "198.51.100.23", "185.220.101.47",
    "45.33.32.156", "91.108.4.0",
]

INTERNAL_IPS = [
    "10.0.0.15", "10.0.0.42", "192.168.1.101",
    "192.168.1.55", "172.16.254.3",
]

USERNAMES = ["admin", "root", "abhinav", "priya", "ganesh", "deploy", "ubuntu"]

# each template is a function that returns a raw alert dict
# we use a list of (weight, function) pairs so common events
# appear more often than rare ones

def _brute_force(ts: datetime) -> dict:
    attempts = random.randint(0,200)
    return {
            "id": str(uuid.uuid4()),
            "timestamp": ts.isoformat().replace("+00:00", "Z"), #Z is to indicaste that the timestamp is in UTC(coordinated Universal Time)
            "source": "ssh",
            "event_type": "brute_force",
            "source_ip": random.choice(MALICIOUS_IPS),
            "username": random.choice(USERNAMES),
            "message": f"{attempts} failed SSH logins followed by 1 success",
            "details": {"failed_attempts": attempts, "window_seconds": 120},
        }


def _port_scan(ts: datetime) -> dict:
    ports = random.randint(500, 5000)
    return {
        "id": str(uuid.uuid4()),
        "timestamp": ts.isoformat().replace("+00:00", "Z"),
        "source": "firewall",
        "event_type": "port_scan",
        "source_ip": random.choice(MALICIOUS_IPS),
        "message": f"Sequential connection attempts to {ports} ports",
        "details": {"ports_probed": ports},
    }

def _failed_login(ts: datetime) -> dict:
    return {
        "id": str(uuid.uuid4()),
        "timestamp": ts.isoformat().replace("+00:00", "Z"),
        "source": random.choice(["auth", "web"]),
        "event_type": "failed_login",
        "source_ip": random.choice(INTERNAL_IPS),
        "username": random.choice(USERNAMES),
        "message": "Single failed login attempt",
        "details": {"failed_attempts": 1},
    }

def _impossible_travel(ts: datetime) -> dict:
    countries = [("India", "IN"), ("Russia", "RU"), ("China", "CN"), ("Brazil", "BR")]
    c1, c2 = random.sample(countries, 2)
    return {
        "id": str(uuid.uuid4()),
        "timestamp": ts.isoformat().replace("+00:00", "Z"),
        "source": "auth",
        "event_type": "impossible_travel",
        "source_ip": random.choice(MALICIOUS_IPS),
        "username": random.choice(USERNAMES),
        "message": f"Login from {c1[0]} then {c2[0]} within 10 minutes",
        "details": {"country_1": c1[1], "country_2": c2[1], "gap_minutes": 10},
    }

def _malware_beacon(ts: datetime) -> dict:
    interval = random.randint(30, 300)
    return {
        "id": str(uuid.uuid4()),
        "timestamp": ts.isoformat().replace("+00:00", "Z"),
        "source": "endpoint",
        "event_type": "malware_beacon",
        "source_ip": random.choice(INTERNAL_IPS),
        "message": f"Repeated outbound connection every {interval}s to known C2",
        "details": {"interval_seconds": interval, "destination": "185.220.101.47"},
    }

def _normal_activity(ts: datetime) -> dict:
    return {
        "id": str(uuid.uuid4()),
        "timestamp": ts.isoformat().replace("+00:00", "Z"),
        "source": random.choice(["web", "auth"]),
        "event_type": "normal_activity",
        "source_ip": random.choice(INTERNAL_IPS),
        "username": random.choice(USERNAMES),
        "message": "Routine failed login, correct password on retry",
        "details": {"failed_attempts": 1},
    }


# weight = how often this template is picked 
# higher weight = appears more in the dataset
TEMPLATES: list[tuple[int, callable]] = [
     (5, _brute_force),
     (4, _port_scan),
     (3, _impossible_travel),
     (2, _malware_beacon),
     (20, _failed_login),
     (30, _normal_activity),
]

# -- generator ----------------------------

def generate_alerts(config: GeneratorConfig) -> list[Alert]:
    weights = [w for w, _ in TEMPLATES]
    funcs = [f for _, f in TEMPLATES]

     # spread alerts across the last 7 days
    now = datetime.now(timezone.utc)
    alerts: list[Alert] = []

    for _ in range(config.total):
        # pick a random timestamp in the last 7 days
        ts = now - timedelta(
            days = random.randint(0,6),
            hours = random.randint(0,23),
            minutes = random.randint(0,59),
        )
    
        fn = random.choices(funcs, weights = weights, k = 1)[0]
        raw = fn(ts)

        # validate through your Pydantic model
        # if this raises, there's a bug in the template above
        alert = Alert.model_validate(raw)
        alerts.append(alert)

    # sort chronologically
    alerts.sort(key = lambda a: a.timestamp)
    return alerts

def save_alerts(alerts: list[Alert], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = [json.loads(a.model_dump_json()) for a in alerts]
    path.write_text(json.dumps(raw, indent = 2, default = str))
    print(f"Saved {len(alerts)} alerts to {path}")


def summarise(alerts: list[Alert]) -> None:
    from collections import Counter
    types = Counter(a.event_type for a in alerts)
    sources = Counter(a.source for a in alerts)
    print("\nEvent Types:")
    for t, n in types.most_common():
        print(f" {t}: {n}")
    print("\nSources:")
    for s, n in sources.most_common():
        print(f" {s}: {n}")


if __name__ == "__main__":
    config = GeneratorConfig(total = 100)
    alerts = generate_alerts(config)
    summarise(alerts)
    save_alerts(alerts, config.output_path)