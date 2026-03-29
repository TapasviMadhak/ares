"""
ARES MCP (Model Context Protocol) Integration Module

This module provides integration with Hexstrike-AI's MCP server for executing
150+ security tools in an AI-orchestrated manner.

Components:
- hexstrike_client: Async client for communicating with Hexstrike-AI MCP server
- tool_selector: AI-powered tool selection based on scan context
- orchestrator: Multi-tool orchestration for complex attack scenarios

Author: ARES Team
Version: 1.0.0
"""

from .hexstrike_client import HexstrikeClient
from .tool_selector import ToolSelector
from .orchestrator import Orchestrator

__all__ = [
    "HexstrikeClient",
    "ToolSelector",
    "Orchestrator",
]

__version__ = "1.0.0"
