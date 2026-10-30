"""
Manual test: run 3 alerts through the enricher and print tool calls + result.
Run with: python -m triagegraph.test_enricher
"""
import json
from pathlib import Path
from triagegraph.models import Alert
from triagegraph.enricher import enrich_and_classify


def main():
    raw = json.loads(Path("data/alerts_60.json").read_text())
    alerts = [Alert.model_validate(a) for a in raw]

    # pick one high severity, one low, one ambiguous
    targets = ["brute_force", "normal_activity", "impossible_travel"]
    test_alerts: list[Alert] = []
    seen: set[str] = set()

    for alert in alerts:
        if alert.event_type in targets and alert.event_type not in seen:
            test_alerts.append(alert)
            seen.add(alert.event_type)
        if len(test_alerts) == 3:
            break

    for alert in test_alerts:
        print(f"\n{'='*60}")
        print(f"ALERT:    {alert.event_type} from {alert.source_ip}")
        print(f"MESSAGE:  {alert.message}")
        print(f"{'─'*60}")
        print("TOOL CALLS:")

        classification, tool_log = enrich_and_classify(alert)

        for entry in tool_log:
            print(f"  → {entry['tool']}({entry['args']})")
            print(f"    {entry['result']}")

        print(f"{'─'*60}")
        print(f"SEVERITY:   {classification.severity}")
        print(f"CATEGORY:   {classification.category}")
        print(f"CONFIDENCE: {classification.confidence:.0%}")
        print(f"REASONING:  {classification.reasoning}")


if __name__ == "__main__":
    main()