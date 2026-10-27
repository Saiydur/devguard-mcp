"""End-to-end test: launch the real server as a subprocess and talk MCP over stdio."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from tests.test_server import EXPECTED_TOOLS


async def _session_roundtrip(project: Path) -> tuple[set[str], dict[str, object]]:
    params = StdioServerParameters(command=sys.executable, args=["-m", "devguard_mcp", "serve"])
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        tools = await session.list_tools()
        result = await session.call_tool("scan_directory", {"path": str(project)})
        assert not result.is_error
        payload = json.loads(result.content[0].text)  # type: ignore[union-attr]
        return {t.name for t in tools.tools}, payload


def test_server_speaks_mcp_over_stdio(infected_project: Path) -> None:
    names, report = asyncio.run(asyncio.wait_for(_session_roundtrip(infected_project), 60))
    assert names == EXPECTED_TOOLS
    assert report["verdict"] == "likely-malicious-indicators-found"
    assert report["finding_count"] >= 4
