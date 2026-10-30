import pytest
from pydantic import ValidationError
from triagegraph.models import Alert, Classification
from triagegraph.generate_alerts import GeneratorConfig, generate_alerts
from triagegraph.tools import lookup_ip_reputation, search_past_incidents, map_to_mitre

#we need this to avoid writing code repititively
def valid_alert_data() -> dict:
    return {
        "id": "t1",
        "timestamp": "2026-10-18T09:15:00Z",
        "source": "ssh",
        "event_type": "brute_force",
        "source_ip": "203.0.113.9",
        "message": "test alert",
    }


def test_valid_alert_parses():
    alert = Alert.model_validate(valid_alert_data())
    assert alert.id == "t1"
    #the line below is to basically verify that valid data is accepted and missing optional data is handled correctly
    assert alert.username is None

#rejecting an invalid IP
def test_bad_ip_is_rejected():
    data = valid_alert_data()
    data["source_ip"] = "not-an-ip"
    with pytest.raises(ValidationError):
        Alert.model_validate(data)

#testing and rejecting unknown sources
def test_unknown_source_is_rejected():
    data = valid_alert_data()
    data["source"] = "carrier-pigeon"
    with pytest.raises(ValidationError):
        Alert.model_validate(data)

#confidence is from 0 to 1 for obvious probabilistic reasons
def test_confidence_must_be_between_0_and_1():
    with pytest.raises(ValidationError):
        Classification(
            severity="high", category="brute_force", confidence=1.7, reasoning="x"
        )

def test_generator_produces_correct_count():
    config = GeneratorConfig(total=10)
    alerts = generate_alerts(config)
    assert len(alerts) == 10


def test_generator_alerts_are_valid_alert_objects():
    config = GeneratorConfig(total=5)
    alerts = generate_alerts(config)
    for alert in alerts:
        assert isinstance(alert, Alert)
        assert alert.source_ip is not None
        assert len(alert.message) > 0

def test_known_malicious_ip_returns_malicious():
    result = lookup_ip_reputation.invoke({"ip": "185.220.101.47"})
    assert result["reputation"] == "malicious"
    assert result["risk_score"] > 5


def test_unknown_ip_returns_unknown():
    result = lookup_ip_reputation.invoke({"ip": "1.2.3.4"})
    assert result["reputation"] == "unknown"
    assert result["risk_score"] == 0


def test_mitre_brute_force_maps_correctly():
    result = map_to_mitre.invoke({"event_type": "brute_force"})
    assert result["technique_id"] == "T1110"
    assert result["tactic"] == "Credential Access"


def test_search_past_incidents_returns_list():
    result = search_past_incidents.invoke({"event_type": "brute_force"})
    assert isinstance(result, list)
    assert all(r["event_type"] == "brute_force" for r in result)