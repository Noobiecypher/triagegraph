from langchain_core.prompts import ChatPromptTemplate
from triagegraph.llm import get_llm
from triagegraph.models import Alert, Classification

#-----prompt------------------------------------------------

SYSTEM_PROMPT = """You are a security analyst triaging alerts for a SOC team.

Your job is to classify each alert with:
- severity: one of low / medium / high / critical
- category: a short label like brute_force, port_scan, impossible_travel, malware_beacon, failed_login, or normal_activity
- confidence: a float between 0.0 and 1.0 indicating how certain you are
- reasoning: one or two sentences explaining your classification

Severity guidelines:
- critical: active breach, data exfiltration, ransomware
- high: strong indicators of attack (brute force success, port scan, C2 beacon)
- medium:   suspicious but ambiguous (unusual login location, single failed attempt on privileged account)
- low: almost certainly benign noise (single failed login on normal account)

Assign severity based on the likely impact and evidence; express uncertainty through confidence and explicit caveats."""

#C2 = command and control beacon: a communication between a compromised system and attacker controlled infra

HUMAN_PROMPT = """Alert Details:
- Source: {source}
- Event Type: {event_type}
- Source IP: {source_ip}
- Username: {username}
- Message: {message}
- Details: {details}
Classify this alert."""

prompt_template = ChatPromptTemplate.from_messages([
    ("system", SYSTEM_PROMPT),
    ("human", HUMAN_PROMPT),
])


# -- chain -----------------------------------------------------

def build_classifier_chain():
    """
    Build the classification chain.
    prompt | model | structured output parser
    """
    llm = get_llm()
    structured_llm = llm.with_structured_output(Classification)
    return prompt_template | structured_llm



def classify_alert(alert: Alert) -> Classification:
    """Classify a single alert. Returns a Classification object."""
    chain = build_classifier_chain()
    return chain.invoke({
        "source": str(alert.source),
        "event_type": alert.event_type,
        "source_ip": str(alert.source_ip),
        "username": alert.username or "unknown",
        "message": alert.message,
        "details": str(alert.details),
    })