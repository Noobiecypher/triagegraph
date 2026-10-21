import pytest
from pydantic import ValidationError
from triagegraph.models import Alert, Classification
from triagegraph.generate_alerts import GeneratorConfig, generate_alerts

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