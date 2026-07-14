"""Regression for the MCP server surface (dexllm.mcp_server).

Locks the tool-spec catalog (32 tools, ``dexllm_`` prefix, injected ``apk_path``), the
``dispatch_tool`` open-and-run path, the async ``list_tools`` / ``call_tool`` handlers,
and — most importantly — that the descriptor-identity contract (identity strict, name
search lenient) is preserved when a call flows through the server, not just the raw
``tools.execute``. Skips entirely when the optional ``mcp`` extra is not installed (CI
runs without it), since ``dexllm.mcp_server`` imports ``mcp.types`` at module load.
"""

import glob
import json
from pathlib import Path

import pytest

pytest.importorskip("mcp")  # the whole module needs the optional [mcp] extra

import dexllm  # noqa: E402
from dexllm import mcp_server as M  # noqa: E402

REPO = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def apk():
    apks = sorted(glob.glob(str(REPO / "test_apk" / "APK" / "*.apk")))
    pref = [p for p in apks if "a2dp.Vol" in p] + apks
    if not pref:
        pytest.skip("no bundled APK")
    return pref[0]


def test_tool_specs_match_catalog_with_apk_path_injected():
    """Every dexllm.tools entry becomes one dexllm_-prefixed spec with apk_path first."""
    from dexllm import tools

    specs = M.list_tool_specs()
    assert len(specs) == len(tools.tool_definitions())  # 1:1, no drop/dup
    for s in specs:
        assert s["name"].startswith("dexllm_")
        sc = s["inputSchema"]
        assert sc["type"] == "object" and isinstance(sc["properties"], dict)
        # apk_path injected first in properties and required
        assert "apk_path" in sc["properties"]
        assert sc["required"][0] == "apk_path"
        json.dumps(sc)  # transport-serialisable
    # names are exactly the catalog with the prefix, no collisions
    assert {s["name"] for s in specs} == {
        f"dexllm_{d['name']}" for d in tools.tool_definitions()
    }


def test_dispatch_tool_runs_and_handles_bad_apk(apk):
    """dispatch_tool opens the APK from apk_path, runs the tool, and errors cleanly."""
    r = M.dispatch_tool("dexllm_list_classes", {"apk_path": apk, "limit": 3})
    assert r["total"] > 0 and len(r["items"]) == 3
    # the dexllm_ prefix is optional on the dispatch name
    assert M.dispatch_tool("list_classes", {"apk_path": apk, "limit": 1})["total"] > 0
    # missing / unopenable apk_path → guiding error dict, never a raise
    assert M.dispatch_tool("dexllm_list_classes", {})["error"] == "apk_path is required"
    assert (
        "failed to open"
        in M.dispatch_tool("dexllm_list_classes", {"apk_path": "/no/such/file.apk"})[
            "error"
        ]
    )


def test_descriptor_contract_preserved_through_server(apk):
    """The identity-strict / search-lenient contract holds via dispatch_tool, too."""
    dk = dexllm.DexKit(apk)
    cls = next(c for c in dk.list_classes() if dk.list_class_methods(c))
    dotted = cls[1:-1].replace("/", ".")

    # identity: L-form resolves, dotted → structured ValueError (not a silent empty)
    assert "error" not in M.dispatch_tool(
        "dexllm_list_class_methods", {"apk_path": apk, "class_descriptor": cls}
    )
    bad = M.dispatch_tool(
        "dexllm_list_class_methods", {"apk_path": apk, "class_descriptor": dotted}
    )
    assert (
        bad.get("error", "").startswith("ValueError") and "descriptor" in bad["error"]
    )
    bad_api = M.dispatch_tool(
        "dexllm_find_call_sites_to_api",
        {"apk_path": apk, "api_descriptor": "android.util.Log->d(Ljava/lang/String;)I"},
    )
    assert bad_api.get("error", "").startswith("ValueError")

    # name-search stays lenient: a dotted name does not error
    assert "error" not in M.dispatch_tool(
        "dexllm_find_classes_by_name",
        {"apk_path": apk, "name": "java.lang.String", "match_type": "contains"},
    )


def test_async_handlers_list_and_call(apk):
    """The @server.list_tools / @server.call_tool handlers return proper MCP types."""
    import asyncio

    async def go():
        tl = await M._list_tools()
        assert len(tl) == len(M.list_tool_specs())
        assert all(t.name.startswith("dexllm_") for t in tl)
        out = await M._call_tool("dexllm_identify", {"apk_path": apk})
        assert len(out) == 1 and out[0].type == "text"
        payload = json.loads(out[0].text)
        assert payload["format"] in ("dex", "zip")
        # an errored tool still returns a single TextContent JSON (no exception escapes)
        err = await M._call_tool(
            "dexllm_decompile_class",
            {"apk_path": apk, "class_descriptor": "java.lang.String"},
        )
        assert json.loads(err[0].text)["error"].startswith("ValueError")

    asyncio.run(go())
