"""
AFEM agent tools — public API
==============================
Re-exports the four email tools so callers can write:

    from agent.tools import retrieve_email, search_email, create_draft, send_email

Each tool is a pure Python function that operates on mailbox.db. They have no
dependency on LangGraph or the LLM — they are wrapped in LangChain tool
decorators only inside ``agent/langgraph_agent.py``.
"""
from __future__ import annotations

from agent.tools.create_draft import create_draft
from agent.tools.retrieve_email import retrieve_email
from agent.tools.search_email import search_email
from agent.tools.send_email import send_email

__all__ = [
    "retrieve_email",
    "search_email",
    "create_draft",
    "send_email",
]