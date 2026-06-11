"""MCP (Model Context Protocol) server for dexllm analysis tools.

Hosts: Claude Desktop, Cursor, Continue, any MCP client.
Transport: stdio (default).

Run as a script:
    python -m dexllm.mcp_server

Or register in Claude Desktop's ``claude_desktop_config.json``::

    {
      "mcpServers": {
        "dexllm": {
          "command": "python",
          "args": ["-m", "dexllm.mcp_server"]
        }
      }
    }

The LLM then calls tools like ``dexllm_list_classes(apk_path=..., ...)``.

Design notes
------------
- One MCP tool per entry in ``dexllm.tools.TOOL_DEFINITIONS``, prefixed
  with ``dexllm_`` for clarity in the host UI.
- Built on the low-level ``mcp.server.Server`` so the rich per-tool
  JSON-Schema from ``dexllm.tools`` is exposed verbatim as each tool's
  ``inputSchema``. (FastMCP derives the schema from the Python signature,
  which would erase the typed parameters behind a single ``**kwargs`` blob.)
- MCP calls are stateless, so every tool also takes an ``apk_path`` argument;
  it is injected into each tool's schema here. The server keeps an LRU of
  DexKit instances so reopening the same APK in a session is free after the
  first hit.
- All decompile tools go through the safe wrappers (in ``dexllm.tools``) — a
  hung method returns a ``// TIMEOUT`` marker instead of locking the server.
"""

from __future__ import annotations

import asyncio
import json
from collections import OrderedDict
from copy import deepcopy
from pathlib import Path
from typing import Any

import mcp.types as types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from . import DexKit
from . import tools as dxtools

# ─── DexKit LRU instance cache ────────────────────────────────────────────

_DK_CACHE_MAX = 4
_dk_cache: OrderedDict[str, DexKit] = OrderedDict()


def _get_dk(apk_path: str) -> DexKit:
    p = str(Path(apk_path).expanduser().resolve())
    if p in _dk_cache:
        _dk_cache.move_to_end(p)
        return _dk_cache[p]
    dk = DexKit(p)
    _dk_cache[p] = dk
    while len(_dk_cache) > _DK_CACHE_MAX:
        _dk_cache.popitem(last=False)
    return dk


# ─── Tool specs + dispatch (plain functions — shared by the MCP handlers and
#     the integration test, so the exposed schema is directly verifiable) ───

_APK_PATH_PROP = {
    "type": "string",
    "description": "Filesystem path to the APK/DEX (or any zip/dex container) to analyze.",
}


def _augment_schema(input_schema: dict) -> dict:
    """Inject the stateless-transport ``apk_path`` parameter into a schema.

    Adds ``apk_path`` first in ``properties`` and ``required``, preserving the
    tool's own typed parameters.
    """
    schema = deepcopy(input_schema)
    props = schema.get("properties", {})
    schema["properties"] = {"apk_path": _APK_PATH_PROP, **props}
    required = schema.get("required", [])
    if "apk_path" not in required:
        schema["required"] = ["apk_path", *required]
    return schema


def list_tool_specs() -> list[dict[str, Any]]:
    """Build the MCP tool specs from ``dexllm.tools``, with ``apk_path`` injected.

    Each spec is ``{name, description, inputSchema}``; the ``inputSchema`` is the
    full typed schema the LLM needs to call the tool correctly.
    """
    specs: list[dict[str, Any]] = []
    for spec in dxtools.tool_definitions():
        specs.append(
            {
                "name": f"dexllm_{spec['name']}",
                "description": f"{spec['description']}\n\n"
                "Pass `apk_path` (filesystem path to the .apk/.dex).",
                "inputSchema": _augment_schema(spec["input_schema"]),
            }
        )
    return specs


def dispatch_tool(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Open DexKit from ``apk_path`` and run the named tool.

    Dispatches through ``dexllm.tools.execute``. Returns the tool's result dict,
    or an ``{"error": ...}`` dict on a missing/unopenable APK.
    """
    tool_name = name[len("dexllm_") :] if name.startswith("dexllm_") else name
    args = dict(arguments or {})
    apk_path = args.pop("apk_path", None)
    if not apk_path:
        return {"error": "apk_path is required"}
    try:
        dk = _get_dk(apk_path)
    except Exception as e:  # noqa: BLE001 — surface any open failure to the LLM
        return {"error": f"failed to open APK '{apk_path}': {type(e).__name__}: {e}"}
    return dxtools.execute(tool_name, args, dk)


# ─── MCP server (low-level) ───────────────────────────────────────────────

server = Server("dexllm")


@server.list_tools()
async def _list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name=s["name"],
            description=s["description"],
            inputSchema=s["inputSchema"],
        )
        for s in list_tool_specs()
    ]


@server.call_tool()
async def _call_tool(name: str, arguments: dict[str, Any]) -> list[types.TextContent]:
    result = dispatch_tool(name, arguments or {})
    return [
        types.TextContent(type="text", text=json.dumps(result, indent=2, default=str))
    ]


async def _run() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream, write_stream, server.create_initialization_options()
        )


def main() -> None:
    """Entrypoint for ``python -m dexllm.mcp_server``. Runs stdio MCP."""
    asyncio.run(_run())


if __name__ == "__main__":
    main()
