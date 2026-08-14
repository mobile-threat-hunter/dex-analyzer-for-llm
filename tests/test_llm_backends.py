"""End-to-end smoke test for the LLM-facing backends.

What this covers
----------------
1. **tools.py** — every TOOL_DEFINITIONS entry has a matching impl, and
   `execute()` round-trips on a real APK.
2. **mcp_server.py** — registers every catalog tool, whose exposed `inputSchema` carries
   the real typed params + `apk_path` (not an opaque kwargs blob), and
   `dispatch_tool` hits DexKit and returns the result dict.
3. **server.py** (FastAPI) — static endpoints (`/health`, `/tools`,
   `/upload`, `/session/{id}`) work end-to-end against a real APK. This is the
   ONLY automated coverage of that surface.
4. **server.py /analyze** — only runs if `ANTHROPIC_API_KEY` is set in
   the environment; consumes the SSE stream and asserts at least one
   `tool_use` and one `tool_result` event arrive before `done`.

This file used to be named `llm_backend_integration.py`, which is outside pytest's
`test_*.py` pattern — so it was never collected and rotted unnoticed, sitting at a
hard-coded `15` tools against a catalog of 36 (dexllm#40). Every optional dependency
(`mcp`, `fastapi`) and the corpus are SKIPs, never failures, so it runs in CI.
"""

from __future__ import annotations

import glob
import os
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def apk():
    """A corpus APK — tvleanback if present (what the assertions were written on)."""
    env = os.environ.get("DEXLLM_TEST_APK")
    if env and os.path.isfile(env):
        return env
    apks = sorted(glob.glob(str(REPO / "test_apk" / "APK" / "*.apk")))
    pref = [p for p in apks if "tvleanback" in p] + apks
    if not pref:
        pytest.skip("no bundled test APK")
    return pref[0]


# ─── Part 1: tools.py ────────────────────────────────────────────────────


def test_tools_module(apk):
    import dexllm
    from dexllm import tools as dxtools

    defs = dxtools.tool_definitions()
    impls = dxtools.TOOL_IMPLS
    # NOT a hard-coded count: a pinned number is what rotted while this file went
    # uncollected — it sat at 15 against a catalog of 36, failing before it reached
    # anything else.
    assert len(defs) == len(impls) and defs, f"catalog/impl mismatch: {len(defs)}"
    for spec in defs:
        assert spec["name"] in impls, f"missing impl for {spec['name']}"
        assert "description" in spec
        assert "input_schema" in spec

    dk = dexllm.DexKit(apk)
    want = min(5, len(dk.list_classes()))  # the corpus APK may be smaller
    r = dxtools.execute("list_classes", {"limit": want}, dk)
    assert isinstance(r.get("items"), list) and len(r["items"]) == want, r
    r = dxtools.execute("summarize_capabilities", {}, dk)
    assert isinstance(r, dict) and "error" not in r, r
    r = dxtools.execute("does_not_exist", {}, dk)
    assert "error" in r, r


# ─── Part 2: mcp_server.py ───────────────────────────────────────────────


def test_mcp_server(apk):
    pytest.importorskip("mcp")  # the optional [mcp] extra
    from dexllm import mcp_server

    # The exposed inputSchema must carry the real typed parameters + apk_path —
    # NOT a single opaque kwargs blob (the FastMCP-**kwargs regression).
    specs = mcp_server.list_tool_specs()
    from dexllm import tools as dxtools

    assert len(specs) == len(dxtools.tool_definitions()), len(specs)
    by_name = {s["name"]: s for s in specs}
    for s in specs:
        props = s["inputSchema"].get("properties", {})
        assert (
            "kwargs" not in props
        ), f"{s['name']} exposes an opaque kwargs blob: {props}"
        assert "apk_path" in props, f"{s['name']} missing apk_path in schema"
        assert "apk_path" in s["inputSchema"].get("required", []), s["name"]

    # decompile_method must expose its real typed parameter, not just apk_path.
    dm = by_name["dexllm_decompile_method"]["inputSchema"]["properties"]
    assert "method_descriptor" in dm, dm

    # dispatch round-trips on a real APK (the corpus APK may hold fewer classes)
    import dexllm

    want = min(3, len(dexllm.DexKit(apk).list_classes()))
    r = mcp_server.dispatch_tool(
        "dexllm_list_classes", {"apk_path": apk, "limit": want}
    )
    assert "items" in r and len(r["items"]) == want, r

    # missing apk_path branch
    r = mcp_server.dispatch_tool("dexllm_list_classes", {})
    assert r.get("error", "").startswith("apk_path"), r


# ─── Part 3: FastAPI static endpoints ────────────────────────────────────


def test_fastapi_static(apk):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from dexllm.server import app

    c = TestClient(app)

    h = c.get("/health").json()
    from dexllm import tools as dxtools

    assert h["ok"] is True and h["tools"] == len(dxtools.tool_definitions()), h

    tools = c.get("/tools").json()["tools"]
    assert len(tools) == len(dxtools.tool_definitions()), len(tools)

    before = h["sessions"]
    with open(apk, "rb") as f:
        r = c.post(
            "/upload",
            files={
                "apk": (
                    os.path.basename(apk),
                    f,
                    "application/vnd.android.package-archive",
                )
            },
        )
    assert r.status_code == 200, r.text
    sid = r.json()["session_id"]

    h = c.get("/health").json()
    assert h["sessions"] == before + 1, h

    r = c.delete(f"/session/{sid}").json()
    assert r["ok"] is True, r

    r = c.delete(f"/session/{sid}")
    assert r.status_code == 404, r.text

    r = c.post("/upload", files={"apk": ("foo.txt", b"hi", "text/plain")})
    assert r.status_code == 400, r.text


# ─── Part 4: FastAPI live agent (gated on ANTHROPIC_API_KEY) ─────────────


def test_fastapi_live_agent(apk):
    if not os.environ.get("ANTHROPIC_API_KEY"):
        pytest.skip("live agent — ANTHROPIC_API_KEY not set")
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from dexllm.server import app

    c = TestClient(app)
    with open(apk, "rb") as f:
        sid = c.post(
            "/upload",
            files={
                "apk": (
                    os.path.basename(apk),
                    f,
                    "application/vnd.android.package-archive",
                )
            },
        ).json()["session_id"]

    prompt = (
        "Use the dexkit tools to give me a 3-bullet capability summary of this APK. "
        "Start with summarize_capabilities. Keep the final answer under 200 words."
    )
    seen = {"tool_use": 0, "tool_result": 0, "text": 0, "error": 0, "done": False}
    with c.stream(
        "POST", "/analyze", data={"session_id": sid, "prompt": prompt}
    ) as resp:
        assert resp.status_code == 200
        for raw in resp.iter_lines():
            if not raw or not raw.startswith("event:"):
                continue
            event = raw.split(":", 1)[1].strip()
            if event in seen and isinstance(seen[event], int):
                seen[event] += 1
            if event == "done":
                seen["done"] = True
                break

    c.delete(f"/session/{sid}")
    assert seen["done"], f"never saw done event: {seen}"
    assert seen["tool_use"] >= 1, f"no tool_use: {seen}"
    assert seen["tool_result"] >= 1, f"no tool_result: {seen}"
    assert seen["error"] == 0, f"agent error: {seen}"
