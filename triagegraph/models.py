from datetime import datetime
from typing import Literal
from pydantic import BaseModel, Field, IPvAnyAddress

# Literal means "only these exact values are allowed"
Source = Literal["ssh", "web", "firewall", "auth", "endpoint"]
Severity = Literal["low", "medium", "high", "critical"]


class Alert(BaseModel):
    """A raw security alert as it arrives from a log source."""

    id: str
    timestamp: datetime
    source: Source
    event_type: str
    source_ip: IPvAnyAddress          # rejects "not-an-ip"
    username: str | None = None       # optional field
    message: str = Field(min_length=1)
    details: dict[str, str | int | float | bool] = Field(default_factory=dict)


class Classification(BaseModel):
    """What the LLM will return on Day 3: the triage judgment."""

    severity: Severity
    category: str
    confidence: float = Field(ge=0.0, le=1.0)   # must be between 0 and 1
    reasoning: str