"""End-to-end smoke test for the LLM-facing backends.

What this covers
----------------
1. **tools.py** — every TOOL_DEFINITIONS entry has a matching impl, and
   `execute()` round-trips on a real APK.
2. **mcp_server.py** — registers 15 tools whose exposed `inputSchema` carries
   the real typed params + `apk_path` (not an opaque kwargs blob), and
   `dispatch_tool` hits DexKit and returns the result dict.
3. **server.py** (FastAPI) — static endpoints (`/health`, `/tools`,
   `/upload`, `/session/{id}`) work end-to-end against a real APK.
4. **server.py /analyze** — only runs if `ANTHROPIC_API_KEY` is set in
   the environment; consumes the SSE stream and asserts at least one
   `tool_use` and one `tool_result` event arrive before `done`.

Run
---
    python -m tests.llm_backend_integration
    # or
    python tests/llm_backend_integration.py

Exit codes: 0 on success, non-zero on any failure.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
TEST_APK = REPO_ROOT / "test_apk" / "APK" / "com.example.android.tvleanback.apk"

if not TEST_APK.exists():
    print(f"FAIL: test APK missing: {TEST_APK}")
    sys.exit(2)


# ─── Part 1: tools.py ────────────────────────────────────────────────────


def test_tools_module() -> None:
    import dexllm
    from dexllm import tools as dxtools

    defs = dxtools.tool_definitions()
    impls = dxtools.TOOL_IMPLS
    assert len(defs) == 15, f"expected 15 tools, got {len(defs)}"
    for spec in defs:
        assert spec["name"] in impls, f"missing impl for {spec['name']}"
        assert "description" in spec
        assert "input_schema" in spec

    dk = dexllm.DexKit(str(TEST_APK))
    r = dxtools.execute("list_classes", {"limit": 5}, dk)
    assert isinstance(r.get("items"), list) and len(r["items"]) == 5, r
    r = dxtools.execute("capability_report", {}, dk)
    assert isinstance(r, dict) and "error" not in r, r
    r = dxtools.execute("does_not_exist", {}, dk)
    assert "error" in r, r
    print("[OK] tools.py — 15 tools, list_classes/cap_report/unknown all good")


# ─── Part 2: mcp_server.py ───────────────────────────────────────────────


def test_mcp_server() -> None:
    from dexllm import mcp_server

    # The exposed inputSchema must carry the real typed parameters + apk_path —
    # NOT a single opaque kwargs blob (the FastMCP-**kwargs regression).
    specs = mcp_server.list_tool_specs()
    assert len(specs) == 15, f"expected 15 MCP tools, got {len(specs)}"
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

    # dispatch round-trips on a real APK
    r = mcp_server.dispatch_tool(
        "dexllm_list_classes", {"apk_path": str(TEST_APK), "limit": 3}
    )
    assert "items" in r and len(r["items"]) == 3, r

    # missing apk_path branch
    r = mcp_server.dispatch_tool("dexllm_list_classes", {})
    assert r.get("error", "").startswith("apk_path"), r

    print(
        "[OK] mcp_server.py — 15 tools expose typed schemas (apk_path + params), dispatch good"
    )


# ─── Part 3: FastAPI static endpoints ────────────────────────────────────


def test_fastapi_static() -> None:
    from fastapi.testclient import TestClient

    from dexllm.server import app

    c = TestClient(app)

    h = c.get("/health").json()
    assert h["ok"] is True and h["tools"] == 15, h

    tools = c.get("/tools").json()["tools"]
    assert len(tools) == 15, len(tools)

    with open(TEST_APK, "rb") as f:
        r = c.post(
            "/upload",
            files={
                "apk": (TEST_APK.name, f, "application/vnd.android.package-archive")
            },
        )
    assert r.status_code == 200, r.text
    sid = r.json()["session_id"]

    h = c.get("/health").json()
    assert h["sessions"] == 1, h

    r = c.delete(f"/session/{sid}").json()
    assert r["ok"] is True, r

    r = c.delete(f"/session/{sid}")
    assert r.status_code == 404, r.text

    r = c.post("/upload", files={"apk": ("foo.txt", b"hi", "text/plain")})
    assert r.status_code == 400, r.text

    print("[OK] server.py static — /health, /tools, /upload, /session/* all good")


# ─── Part 4: FastAPI live agent (gated on ANTHROPIC_API_KEY) ─────────────


def test_fastapi_live_agent() -> None:
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("[SKIP] live agent — ANTHROPIC_API_KEY not set")
        return

    from fastapi.testclient import TestClient

    from dexllm.server import app

    c = TestClient(app)
    with open(TEST_APK, "rb") as f:
        sid = c.post(
            "/upload",
            files={
                "apk": (TEST_APK.name, f, "application/vnd.android.package-archive")
            },
        ).json()["session_id"]

    prompt = (
        "Use the dexkit tools to give me a 3-bullet capability summary of this APK. "
        "Start with capability_report. Keep the final answer under 200 words."
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
    print(
        f"[OK] live agent — tool_use={seen['tool_use']} tool_result={seen['tool_result']} text={seen['text']}"
    )


# ─── Main ────────────────────────────────────────────────────────────────


def main() -> int:
    try:
        test_tools_module()
        test_mcp_server()
        test_fastapi_static()
        test_fastapi_live_agent()
    except AssertionError as e:
        print(f"FAIL: {e}")
        return 1
    except Exception as e:
        print(f"FAIL: {type(e).__name__}: {e}")
        import traceback

        traceback.print_exc()
        return 1
    print("\nALL OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
