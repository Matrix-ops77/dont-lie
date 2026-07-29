"""Examples for adapting common AI clients without importing their SDKs."""

from dontlie.integrations import ActionEvent, ActionRecorder, correlation_scope

recorder = ActionRecorder()


def langgraph_node(state: dict[str, object]) -> dict[str, object]:
    result: dict[str, object] = {}
    with recorder.action("tool", "langgraph.search", state) as action:
        result["documents"] = []
        action["output"] = result
        return result


def crewai_tool(query: str) -> str:
    with recorder.action("tool", "crewai.web_search", {"query": query}) as action:
        result: str = "No results"
        action["output"] = result
        return result


def openai_response(client: object, messages: list[dict[str, str]]) -> dict[str, object]:
    with correlation_scope() as correlation_id:
        response = client.chat.completions.create(model="gpt-4o-mini", messages=messages)  # type: ignore[attr-defined]
        recorder.record(
            ActionEvent(
                action="model",
                name="gpt-4o-mini",
                input={"messages": messages},
                output={"text": response.choices[0].message.content},
                correlation_id=correlation_id,
                metadata={"client": "openai"},
            )
        )
        return response


def anthropic_response(client: object, messages: list[dict[str, object]]) -> dict[str, object]:
    response = client.messages.create(
        model="claude-sonnet-4-5", max_tokens=1024, messages=messages
    )  # type: ignore[attr-defined]
    recorder.record(
        ActionEvent(
            action="model",
            name="claude-sonnet-4-5",
            input={"messages": messages},
            output={"content": response.content},
            metadata={"client": "anthropic"},
        )
    )
    return response


def approval_callback(tool_name: str, approved: bool, reason: str) -> None:
    action = "approval" if approved else "denial"
    recorder.record(
        ActionEvent(
            action=action,  # type: ignore[arg-type]
            name=tool_name,
            input={"reason": reason},
            output={"approved": approved},
        )
    )


def mcp_notification(envelope: dict[str, object]) -> None:
    recorder.callback(envelope)
