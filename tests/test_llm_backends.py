"""End-to-end smoke test for the LLM-facing backends.

What this covers
----------------
1. **tools.py** — every TOOL_DEFINITIONS entry has a matching impl, and
   `execute()` round-trips on a real APK.
2. **mcp_server.py** — registers every catalog tool, whose exposed `inputSchema` carries
   the real typed params + `apk_path` (not an opaque kwargs blob), and
   `dispatch_tool` hits DexKit and returns the result dict.
3. **server.py** (FastAPI) — static endpoints (`/health`, `/tools`,
   `/upload`, `/session/{id}`) work end-to-end against a real container. This is
   the ONLY automated coverage of that surface. The `/upload` contract
   (dexllm#47 — identified by CONTENT, so where the bytes land, which failure
   belongs to whom, and what the two dex counts mean) is guarded by three
   corpus-INDEPENDENT tests that run on `tests/data/multidex.apk`.
4. **server.py /analyze** — only runs if `ANTHROPIC_API_KEY` is set in
   the environment; consumes the SSE stream and asserts at least one
   `tool_use` and one `tool_result` event arrive before `done`.

This file used to be named `llm_backend_integration.py`, which is outside pytest's
`test_*.py` pattern — so it was never collected and rotted unnoticed, sitting at a
hard-coded `15` tools against a catalog of 36 (dexllm#40). Every optional dependency
(`mcp`, `fastapi`) and the corpus are SKIPs, never failures, so it runs in CI.
"""

from __future__ import annotations

import errno
import glob
import os
import tempfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def apk():
    """A corpus APK — tvleanback if present (what the assertions were written on)."""
    import dexllm

    env = os.environ.get("DEXLLM_TEST_APK")
    if env and os.path.isfile(env):
        candidates = [env]
    else:
        apks = sorted(glob.glob(str(REPO / "test_apk" / "APK" / "*.apk")))
        candidates = [p for p in apks if "tvleanback" in p] + apks
    if not candidates:
        pytest.skip("no bundled test APK")
    for path in candidates:
        try:
            if dexllm.DexKit(path).list_classes():
                return path
        except Exception:  # noqa: BLE001
            continue
    # Every leg here uploads / opens the file, so a non-container is an
    # ENVIRONMENT fact that must skip rather than fail each assertion.
    pytest.skip(f"no loadable dex container among {len(candidates)} candidate(s)")


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

    # A non-container is refused for what it IS, not for what it is called: the
    # 400 now carries the loader's own reason (dexllm#47 — the endpoint used to
    # answer "filename must end with .apk" before looking at a single byte).
    r = c.post("/upload", files={"apk": ("foo.txt", b"hi", "text/plain")})
    assert r.status_code == 400, r.text
    detail = r.json()["detail"]
    assert "failed to open upload" in detail, detail
    # The OLD gate's message, asserted gone by its own words (dexllm#47).
    assert "must end with .apk" not in detail, detail


def _committed_container() -> tuple[bytes, bytes]:
    """The zip this repo commits, and one bare dex extracted from it."""
    import zipfile

    blob = REPO / "tests" / "data" / "multidex.apk"
    if not blob.is_file():  # pragma: no cover - the file is committed
        pytest.skip("tests/data/multidex.apk missing")
    with zipfile.ZipFile(blob) as z:
        return blob.read_bytes(), z.read("classes.dex")


def test_fastapi_upload_is_content_based():
    """`/upload` identifies a container by CONTENT, like every other entry point.

    Corpus-independent: it runs on `tests/data/multidex.apk`, the one container
    this repo commits, so the guard holds under a `$DEXLLM_TEST_APK` narrowing
    and in the corpus-less CI leg too.
    """
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from dexllm import server

    zip_bytes, dex_bytes = _committed_container()
    c = TestClient(server.app)
    sids = []
    try:
        # (a) a container whose name says nothing — the disguised/dumped case.
        r = c.post("/upload", files={"apk": ("blob", zip_bytes, "application/zip")})
        assert r.status_code == 200, r.text
        body = r.json()
        sids.append(body["session_id"])
        assert body["identified"]["format"] == "zip", body
        assert body["filename"] == "blob", body

        # (b) a bare dex, and the session it yields actually analyses.
        r = c.post("/upload", files={"apk": ("dump", dex_bytes, "application/dex")})
        assert r.status_code == 200, r.text
        body = r.json()
        sids.append(body["session_id"])
        assert body["identified"] == {
            "format": "dex",
            "is_apk": False,
            "has_manifest": False,
            "dex_count": 1,
        }, body
        # Through the private session store on purpose: the only public
        # read-back is POST /analyze, which needs an ANTHROPIC_API_KEY.
        assert server._sessions[body["session_id"]].dk.list_classes(), body
    finally:
        for sid in sids:
            c.delete(f"/session/{sid}")


# An EMPTY filename is absent from the list on purpose: starlette parses such a
# part as a plain form field, so FastAPI answers 422 before the handler runs —
# framework behaviour, not this endpoint's.
@pytest.mark.parametrize("name", ["..", ".", "/", "../escaped"])
def test_fastapi_upload_lands_inside_the_session_tempdir(name, tmp_path, monkeypatch):
    """No filename decides where the bytes land — not even a traversal.

    The stored basename is a constant, so this pins the property directly
    (`_STORED_NAME` inside a `dexkit-<sid>-` tempdir) rather than pinning that
    the request merely succeeded — a name-derived path survives that.

    The session tempdir is redirected under pytest's `tmp_path` so the escape
    oracle is a fresh private path: a fixed name in the shared `/tmp` would
    make a leftover from an earlier run (or another user) fail the test on an
    ENVIRONMENT fact, and it also fixes the traversal depth, which `/tmp`
    hard-codes.
    """
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from dexllm import server

    zip_bytes, _ = _committed_container()
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    escape = tmp_path / "escaped"  # where `../escaped` lands if the name is used

    c = TestClient(server.app)
    r = c.post("/upload", files={"apk": (name, zip_bytes, "application/zip")})
    try:
        assert r.status_code == 200, r.text
        stored = Path(r.json()["apk_path"])
        assert stored.parent.parent == tmp_path, stored
        assert stored.parent.name.startswith("dexkit-"), stored
        assert not escape.exists(), f"{name!r} wrote outside the session tempdir"
        assert stored.is_file(), stored
        assert stored.name == server._STORED_NAME, stored
    finally:
        if r.status_code == 200:
            c.delete(f"/session/{r.json()['session_id']}")


def test_fastapi_upload_cleans_up_and_blames_the_right_side(tmp_path, monkeypatch):
    """Each failure class keeps its own status, and neither leaves a tempdir.

    The write is the SERVER's (a full or unwritable `$TMPDIR`), the load is the
    CALLER's. Both were unguarded: flipping the 500 to a 400, or deleting the
    load-path `rmtree`, left the rest of this suite green.
    """
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from dexllm import server

    zip_bytes, _ = _committed_container()
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    c = TestClient(server.app)

    # (1) the loader refuses the bytes — the caller's 400, nothing left behind.
    r = c.post("/upload", files={"apk": ("x", b"not a container", "text/plain")})
    assert r.status_code == 400, r.text
    assert list(tmp_path.glob("dexkit-*")) == [], "tempdir leaked on the 400 path"

    # (2) the store fails — ours, so a 500, and still nothing left behind. Both
    # calls that touch $TMPDIR are covered: a fault in either must answer the
    # same way, not depend on which libc call happened to fail first.
    def _enospc(*a, **kw):
        raise OSError(errno.ENOSPC, "No space left on device")

    for target, attr in ((server.shutil, "copyfileobj"), (server.tempfile, "mkdtemp")):
        with monkeypatch.context() as m:
            m.setattr(target, attr, _enospc)
            r = c.post("/upload", files={"apk": ("x", zip_bytes, "application/zip")})
        assert r.status_code == 500, f"{attr}: {r.text}"
        assert "failed to store upload" in r.json()["detail"], f"{attr}: {r.text}"
        assert list(tmp_path.glob("dexkit-*")) == [], f"{attr}: tempdir leaked"


def test_fastapi_upload_body_is_read_before_the_session_is_registered(
    tmp_path, monkeypatch
):
    """A raise after registration would orphan a session the client cannot delete.

    `DEXKIT_SESSION_CACHE=0` makes the LRU evict the session — and delete its
    tempdir — inside the handler, which is the reachable way to observe the
    ordering: reading `size_bytes` after that point raised an unhandled 500.
    """
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from dexllm import server

    zip_bytes, _ = _committed_container()
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    monkeypatch.setattr(server, "SESSION_CACHE_MAX", 0)

    c = TestClient(server.app)
    r = c.post("/upload", files={"apk": ("x", zip_bytes, "application/zip")})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["size_bytes"] == len(zip_bytes), body
    assert body["loaded_dex_count"] == 2, body


def test_fastapi_upload_refuses_a_zip_whose_dexes_do_not_start_at_classes_dex():
    """The accept-set is the LOADER's, and it is narrower than `classes*.dex`.

    A zip carrying only `classes2.dex` holds a file matching that glob and is
    still refused — the run must start at `classes.dex`. Pinned because the
    endpoint's docstring is what a caller reads to know what will be accepted.
    """
    pytest.importorskip("fastapi")
    import io
    import zipfile

    from fastapi.testclient import TestClient

    from dexllm import server

    _, dex_bytes = _committed_container()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("classes2.dex", dex_bytes)

    c = TestClient(server.app)
    r = c.post("/upload", files={"apk": ("x.apk", buf.getvalue(), "application/zip")})
    assert r.status_code == 400, r.text
    assert "classes" in r.json()["detail"], r.text


def test_fastapi_upload_reports_probe_and_session_dex_counts_separately():
    """`identified.dex_count` is the PROBE's; `loaded_dex_count` is the session's.

    A concatenated dump — the packer case this endpoint now accepts — probes as
    ONE dex and loads as several, so one key cannot carry both (dexllm#38).
    """
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from dexllm import server

    _, dex_bytes = _committed_container()
    c = TestClient(server.app)
    r = c.post("/upload", files={"apk": ("dump", dex_bytes * 2, "application/dex")})
    try:
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["identified"]["dex_count"] == 1, body
        assert body["loaded_dex_count"] == 2, body
        assert server._sessions[body["session_id"]].dk.dex_count() == 2, body
    finally:
        if r.status_code == 200:
            c.delete(f"/session/{r.json()['session_id']}")


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
