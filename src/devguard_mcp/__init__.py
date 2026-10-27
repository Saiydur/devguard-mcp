"""devguard-mcp: detect PolinRider and GhostAction supply-chain malware.

The scanning core depends only on the standard library. The MCP server lives in
``devguard_mcp.server`` and is imported lazily so the CLI works without it.
"""

__version__ = "0.1.0"
