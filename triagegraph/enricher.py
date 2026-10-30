from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage
from triagegraph.llm import get_llm
from triagegraph.models import Alert, Classification
from triagegraph.tools import ALL_TOOLS, lookup_ip_reputation, search_past_incidents, map_to_mitre

# map tool name -> actual function so we can call it
TOOL_REGISTRY = {
    "lookup_ip_reputation": lookup_ip_reputation,
    "search_past_incidents": search_past_incidents,
    "map_to_mitre": map_to_mitre,
}

SYSTEM_PROMPT = """You are a security analyst enriching alerts before triage.

For every alert you receive, you MUST use the available tools to:
1. Look up the reputation of the source IP
2. Search for similar past incidents
3. Map the event type to MITRE ATT&CK

After gathering this information, provide a final Classification with:
- severity: low / medium / high / critical
- category: the event type label
- confidence: 0.0 to 1.0
- reasoning: 2-3 sentences using the tool results as evidence

Do not guess. Use the tools first, then reason from what they return."""


def enrich_and_classify(alert: Alert) -> tuple[Classification, list[dict]]:
    """
    Run the tool-calling loop for one alert.
    Returnsthe final Classification and a log of every tool call made.
    """
    llm = get_llm()
    llm_with_tools = llm.bind_tools(ALL_TOOLS)
    structured_llm = llm.with_structured_output(Classification)

    #build the initial message
    human_message = HumanMessage(content=f"""
    Alert to enrich and classify:
    - ID: {alert.id}
    - Source: {alert.source}
    - Event type: {alert.event_type}
    - Source IP: {str(alert.source_ip)}
    - Username: {alert.username or 'unknown'}
    - Message: {alert.message}
    - Details: {str(alert.details)}
    """)

    messages = [SystemMessage(content=SYSTEM_PROMPT), human_message]
    tool_call_log: list[dict] = []

    # --- tool calling loop --------------------------------------------------
    # keep going until the LLM stops asking for tools

    while True:
        response = llm_with_tools.invoke(messages)
        messages.append(response)

        # if no tool calls, the LLM is done gathering data
        if not response.tool_calls:
            break

        # run each tool the LLM asked for
        for tool_call in response.tool_calls:
            tool_name = tool_call["name"]
            tool_args = tool_call["args"]
            tool_fn = TOOL_REGISTRY[tool_name]

            # actually run the tool
            tool_result = tool_fn.invoke(tool_args)

            #log it for visibility
            tool_call_log.append({
                "tool": tool_name,
                "args": tool_args,
                "result": tool_result,
            })

            # send result back to LLM as a ToolMessage
            messages.append(ToolMessage(
                content=str(tool_result),
                tool_call_id=tool_call["id"],
            ))

    # ── final structured classification ──────────────────────────
    # now ask for structured output based on everything gathered
    final_messages = messages + [
        HumanMessage(content="Based on the tool results above, provide your final Classification.")
    ]
    classification = structured_llm.invoke(final_messages)

    return classification, tool_call_log