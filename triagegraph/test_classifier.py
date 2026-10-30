"""Manual test: run a few alerts through the classifier and print results.
Runt with: python -m triagegraph.test_classifier
"""
import json
from pathlib import Path
from triagegraph.models import Alert
from triagegraph.classifier import classify_alert

def main():
    # load your 60 alerts
    raw = json.loads(Path("data/alerts_60.json").read_text())
    alerts = [Alert.model_validate(a) for a in raw]

    # pick 5 interesting ones to test:
    # first brute_force, first port_scan, first impossible_travel,
    # first malware_beacon, and a normal_activity
    interesting_types = [
        "brute_force", "port_scan", "impossible_travel",
        "malware_beacon", "normal_activity"
    ]


    test_alerts: list[Alert] = []
    seen_types: set[str] = set()

    for alert in alerts:
        if alert.event_type in interesting_types and alert.event_type not in seen_types:
            test_alerts.append(alert)
            seen_types.add(alert.event_type)
        if len(test_alerts) == 5:
            break

    #classify each one and print
    for alert in test_alerts:
        print(f"\n{'='*60}")
        print(f"ALERT:    {alert.event_type} from {alert.source_ip}")
        print(f"MESSAGE:  {alert.message}")
        print(f"{'─'*60}")

        result = classify_alert(alert)

        print(f"SEVERITY:   {result.severity}")
        print(f"CATEGORY:   {result.category}")
        print(f"CONFIDENCE: {result.confidence:.0%}")
        print(f"REASONING:  {result.reasoning}")


if __name__ == "__main__":
    main()