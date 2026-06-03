"""MCP (Model Context Protocol) server for dexllm analysis tools.

Hosts: Claude Desktop, Cursor, Continue, any MCP client.
Transport: stdio (default).

Run as a script:
    python -m dexllm.mcp_server

Or register in Claude Desktop's `claude_desktop_config.json`:
    {
      "mcpServers": {
        "dexllm": {
          "command": "python",
          "args": ["-m", "dexllm.mcp_server"]
        }
      }
    }

The LLM then calls tools like `dexllm_list_classes(apk_path=..., ...)`.

Design notes
------------
- One MCP tool per entry in dexllm.tools.TOOL_DEFINITIONS, prefixed
  with `dexllm_` for clarity in the host UI.
- Every tool takes an `apk_path` argument; the server keeps an LRU of
  DexKit instances so opening the same APK multiple times in a session
  is free after the first hit.
- All decompile tools go through the safe wrappers — a hung method
  returns a `// TIMEOUT` marker instead of locking the MCP server.
"""
from __future__ import annotations

import json
from collections import OrderedDict
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from . import DexKit
from . import tools as dxtools

# ─── DexKit LRU instance cache ────────────────────────────────────────────

_DK_CACHE_MAX = 4
_dk_cache: "OrderedDict[str, DexKit]" = OrderedDict()


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


# ─── MCP server (FastMCP) ────────────────────────────────────────────────

mcp = FastMCP("dexllm")


def _wrap(tool_name: str):
    """Build an MCP-callable that opens DexKit from apk_path and dispatches
    through dexllm.tools.execute."""
    def call(**kwargs: Any) -> str:
        apk_path = kwargs.pop("apk_path", None)
        if not apk_path:
            return json.dumps({"error": "apk_path is required"})
        try:
            dk = _get_dk(apk_path)
        except Exception as e:
            return json.dumps({
                "error": f"failed to open APK '{apk_path}': {type(e).__name__}: {e}"
            })
        result = dxtools.execute(tool_name, kwargs, dk)
        return json.dumps(result, indent=2, default=str)
    call.__name__ = f"dexllm_{tool_name}"
    return call


# Register each tool from the shared catalog. We augment the description
# so the host UI tells the LLM to pass apk_path explicitly.
for spec in dxtools.tool_definitions():
    name = spec["name"]
    desc = spec["description"]
    full_desc = f"{desc}\n\nMUST pass `apk_path` (filesystem path to the .apk)."
    mcp.add_tool(_wrap(name), name=f"dexllm_{name}", description=full_desc)


def main() -> None:
    """Entrypoint for `python -m dexllm.mcp_server`. Runs stdio MCP."""
    mcp.run()


if __name__ == "__main__":
    main()
