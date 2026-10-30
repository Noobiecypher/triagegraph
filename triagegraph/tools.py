import json 
from pathlib import Path
from langchain_core.tools import tool
from triagegraph.models import Alert


# ---- data paths -----------------------------------------------------------

THREAT_FEED_PATH = Path(__file__).parent.parent / "data" / "threat_feed.json"
ALERTS_PATH = Path(__file__).parent.parent / "data" / "alerts_60.json"

# ----- MITRE ATT&CK lookup table -------------------------------------------
# real framework used by security teams worldwide
# source: https://attack.mitre.org

MITRE_MAP: dict[str, dict] = {
    "brute_force": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1110/",
    },
    "port_scan": {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": "Discovery",
        "url": "https://attack.mitre.org/techniques/T046/",
    },
    "impossible_travel": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic": "Defense Evasion",
        "url": "https://attack.mitre.org/techniques/T1078/",
    },
    "malware_beacon": {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "url": "https://attack.mitre.org/techniques/T1071/",
    },
    "failed_login": {
        "technique_id": "T1110.001",
        "technique_name": "Password Guessing",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1110/001/",
    },
    "normal_activity": {
        "technique_id": None,
        "technique_name": "No technique matched",
        "tactic": "None",
        "url": None,
    },
}


#---- tools -----------------------------------------------------------------

@tool
def lookup_ip_reputation(ip: str) -> dict:
    """"
    Look up the reputation of an IP address in the threat intelligence feed.
    Returns reputation, tags, risk score, and country if the IP is known.
    Returns unknown status if the IP is not in the feed.
    Use this for any external or suspicious IP address in an alert
    """
    feed = json.loads(THREAT_FEED_PATH.read_text())
    if ip in feed:
        return feed[ip]
    return {
        "reputation": "unknown",
        "tags": [],
        "risk_score": 0,
        "country": "unknown",
        "last_seen": None,
    }


@tool
def search_past_incidents(event_type: str, username: str = "") -> list[dict]:
    """
    Search past alerts for similar incidents.
    Useful for determining if this is a repeat pattern or a first occurence.
    Pass the event_type and optionally a username to narrow the search.
    Returns a list of matching past alerts (up to 5 most recent).
    """

    raw = json.loads(ALERTS_PATH.read_text())
    alerts = [Alert.model_validate(a) for a in raw]

    matches = []
    for alert in alerts:
        type_match  = alert.event_type == event_type
        user_match  = (username == "") or (alert.username == username)
        if type_match and user_match:
            matches.append({
                "id": alert.id,
                "timestamp": str(alert.timestamp),
                "event_type": alert.event_type,
                "source_ip": str(alert.source_ip),
                "username": alert.username,
                "message": alert.message,
            })

    # return 5 most recent

    return sorted(matches, key = lambda x: x["timestamp"], reverse=True)[:5]

@tool
def map_to_mitre(event_type: str) -> dict:
    """"
    Map an event type to the MITRE ATT&CK framework technique.
    Returns the technique ID, name, tactic, and reference URL.
    Always call this to ground th eclassification in industry terminology.
    """

    return MITRE_MAP.get(
        event_type,
        {
            "technique_id": None,
            "technique_name": "Unknown technique",
            "tactic": "Unknown",
            "url": None,
        }, 
    )

# export all tools as a list for easy import elsewhere
ALL_TOOLS = [lookup_ip_reputation, search_past_incidents, map_to_mitre]