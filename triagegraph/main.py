import json
from collections import Counter
from pathlib import Path
from pydantic import ValidationError
from triagegraph.models import Alert

DATA_FILE = Path(__file__).parent.parent/ "data" / "sample_alerts.json"


def load_alerts(path: Path) -> list[Alert]:
    """Read JSON and keep only the alerts that pass validation."""
    raw_items = json.loads(path.read_text())
    alerts: list[Alert] = []
    for index, item in enumerate(raw_items):
        try:
            alerts.append(Alert.model_validate(item))
        except ValidationError as err:
            print(f"Skipping alert #{index}: {err.error_count()} problem(s)")
    return alerts


def main() -> None:
    alerts = load_alerts(DATA_FILE)
    print(f"Loaded {len(alerts)} valid alerts")

    counts = Counter(alert.event_type for alert in alerts)
    for event_type, n in counts.most_common():
        print(f"  {event_type}: {n}")


if __name__ == "__main__":
    main()