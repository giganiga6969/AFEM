"""
Tests for AFEM LangGraph agent orchestration.

These tests verify the forensic execution contract:

    one tool_call -> one tool_result

The agent must retain only the first tool call when an LLM emits multiple
calls in one response. This prevents dependent actions, such as send_email,
from using a guessed draft ID before create_draft returns the authoritative
database ID.

No Ollama server or live LLM invocation is required.
"""

from unittest.mock import MagicMock, patch

from langchain_core.messages import AIMessage, HumanMessage

from agent.langgraph_agent import agent_node


class TestAgentSequentialToolExecution:
    """Verify that AFEM permits only one tool action per LLM iteration."""

    def _make_state(self):
        collector = MagicMock()

        state = {
            "messages": [
                HumanMessage(
                    content=(
                        "Create a draft email and then send the draft."
                    )
                )
            ],
            "session_id": "test-sequential-session",
            "collector": collector,
            "iteration": 0,
        }

        return state, collector

    @patch("agent.langgraph_agent._LLM")
    def test_single_tool_call_is_preserved(self, mock_llm):
        """A normal single tool call must remain unchanged."""

        mock_llm.invoke.return_value = AIMessage(
            content="",
            tool_calls=[
                {
                    "name": "create_draft",
                    "args": {
                        "recipients": "afem-test@example.com",
                        "subject": "AFEM Test",
                        "body": "Controlled test email.",
                    },
                    "id": "call-create-1",
                    "type": "tool_call",
                }
            ],
        )

        state, collector = self._make_state()

        result = agent_node(state)

        returned_message = result["messages"][0]

        assert len(returned_message.tool_calls) == 1
        assert returned_message.tool_calls[0]["name"] == "create_draft"
        assert result["iteration"] == 1

        collector.log_tool_call.assert_called_once_with(
            tool_name="create_draft",
            input_data={
                "recipients": "afem-test@example.com",
                "subject": "AFEM Test",
                "body": "Controlled test email.",
            },
        )

        collector.log_agent_response.assert_not_called()

    @patch("agent.langgraph_agent._LLM")
    def test_multiple_tool_calls_are_reduced_to_first_call(self, mock_llm):
        """
        If the LLM emits create_draft and send_email together, AFEM must
        retain only create_draft.

        The agent can request send_email during the next iteration after
        receiving the authoritative draft ID.
        """

        mock_llm.invoke.return_value = AIMessage(
            content="",
            tool_calls=[
                {
                    "name": "create_draft",
                    "args": {
                        "recipients": "afem-test@example.com",
                        "subject": "AFEM Evaluation",
                        "body": (
                            "This is an authorized forensic "
                            "evaluation email."
                        ),
                    },
                    "id": "call-create-1",
                    "type": "tool_call",
                },
                {
                    "name": "send_email",
                    "args": {
                        "draft_id": 1,
                    },
                    "id": "call-send-1",
                    "type": "tool_call",
                },
            ],
        )

        state, collector = self._make_state()

        result = agent_node(state)

        returned_message = result["messages"][0]

        assert len(returned_message.tool_calls) == 1
        assert returned_message.tool_calls[0]["name"] == "create_draft"

        collector.log_tool_call.assert_called_once()

        logged_call = collector.log_tool_call.call_args.kwargs

        assert logged_call["tool_name"] == "create_draft"
        assert "draft_id" not in logged_call["input_data"]

        collector.log_agent_response.assert_not_called()

    @patch("agent.langgraph_agent._LLM")
    def test_text_response_is_logged_as_agent_response(self, mock_llm):
        """A final text response must be logged without a tool call."""

        mock_llm.invoke.return_value = AIMessage(
            content="The email was sent successfully."
        )

        state, collector = self._make_state()

        result = agent_node(state)

        returned_message = result["messages"][0]

        assert returned_message.tool_calls == []
        assert returned_message.content == (
            "The email was sent successfully."
        )
        assert result["iteration"] == 1

        collector.log_agent_response.assert_called_once_with(
            content="The email was sent successfully."
        )

        collector.log_tool_call.assert_not_called()