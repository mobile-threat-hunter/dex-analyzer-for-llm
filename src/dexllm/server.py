"""FastAPI backend that exposes DexKit analysis to a hosted LLM (Claude).

Web flow
--------
1. Browser uploads a container to `POST /upload` — an APK, a bare `.dex`, or a
   renamed/extension-less dump, identified by CONTENT like every other entry
   point. Server saves to a session-scoped tempdir, opens a DexKit instance
   (cached in an LRU), returns `session_id` and the `identify()` verdict.
2. Browser calls `POST /analyze` with `session_id` + `prompt`. Server runs a
   manual Anthropic tool-use loop against `claude-opus-4-8`, dispatching each
   `tool_use` block through `dexllm.tools.execute(name, args, dk)` and
   feeding the result back as a `tool_result`. The whole conversation is
   streamed back to the browser as SSE events.
3. `DELETE /session/{id}` cleans up.

Design notes
------------
- One `DexKit` per session, kept warm in an LRU. Opening a 50MB APK is the
  expensive operation; subsequent tool calls are cheap.
- Tool catalog comes from `dexllm.tools.tool_definitions()` — same surface
  the MCP server exposes. No duplication.
- The agentic loop is intentionally manual (not the SDK's BetaToolRunner) so
  we can stream events to the browser as they happen and gracefully cap the
  number of turns.
- We default to **adaptive thinking** (`thinking: {type: "adaptive",
  display: "summarized"}`) on Opus 4.8 — the only on-mode thinking shape
  (`budget_tokens` 400s), with `display: "summarized"` so the otherwise-omitted
  reasoning streams to the browser. No sampling params allowed.
- Tool calls hold the GIL only briefly; the underlying DexKit C++ releases
  it during decompile, so concurrent sessions can analyse in parallel.

Run
---
    uvicorn dexllm.server:app --host 0.0.0.0 --port 8000

Environment
-----------
    ANTHROPIC_API_KEY=sk-ant-...        # required
    DEXKIT_MODEL=claude-opus-4-8        # optional override
    DEXKIT_MAX_TURNS=20                 # safety cap on tool-use rounds
    DEXKIT_SESSION_CACHE=10             # how many DexKit instances to keep
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import tempfile
import uuid
from collections import OrderedDict
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from anthropic import Anthropic
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from sse_starlette.sse import EventSourceResponse

from . import DexKit
from . import tools as dxtools

# ─── Config ───────────────────────────────────────────────────────────────

MODEL = os.environ.get("DEXKIT_MODEL", "claude-opus-4-8")
MAX_TURNS = int(os.environ.get("DEXKIT_MAX_TURNS", "20"))
SESSION_CACHE_MAX = int(os.environ.get("DEXKIT_SESSION_CACHE", "10"))
MAX_TOKENS = int(os.environ.get("DEXKIT_MAX_TOKENS", "8192"))


# ─── Session state ────────────────────────────────────────────────────────


class Session:
    """One uploaded container and its open DexKit handle, keyed by session id."""

    __slots__ = ("id", "apk_path", "tmpdir", "dk")

    def __init__(self, sid: str, apk_path: str, tmpdir: str, dk: DexKit) -> None:
        """Bind the session id, stored path, scratch dir, and DexKit handle."""
        self.id = sid
        self.apk_path = apk_path
        self.tmpdir = tmpdir
        self.dk = dk

    def close(self) -> None:
        """Remove the session's scratch directory, ignoring any errors."""
        try:
            shutil.rmtree(self.tmpdir, ignore_errors=True)
        except Exception:
            pass


_sessions: OrderedDict[str, Session] = OrderedDict()


def _evict_if_needed() -> None:
    while len(_sessions) > SESSION_CACHE_MAX:
        _, victim = _sessions.popitem(last=False)
        victim.close()


def _get_session(sid: str) -> Session:
    s = _sessions.get(sid)
    if s is None:
        raise HTTPException(status_code=404, detail=f"unknown session_id: {sid}")
    _sessions.move_to_end(sid)
    return s


# ─── Anthropic client (singleton) ─────────────────────────────────────────

_client: Anthropic | None = None


def _anthropic() -> Anthropic:
    global _client
    if _client is None:
        if not os.environ.get("ANTHROPIC_API_KEY"):
            raise HTTPException(status_code=500, detail="ANTHROPIC_API_KEY not set")
        _client = Anthropic()
    return _client


# ─── FastAPI app ──────────────────────────────────────────────────────────


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    yield
    for s in list(_sessions.values()):
        s.close()
    _sessions.clear()


app = FastAPI(title="dexkit-llm-backend", lifespan=_lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health() -> dict:
    """Return service liveness and the configured model."""
    return {
        "ok": True,
        "model": MODEL,
        "sessions": len(_sessions),
        "tools": len(dxtools.tool_definitions()),
    }


# The upload is stored under a FIXED basename. The client-supplied filename is
# not load-bearing — the container is identified by content — and using it as a
# path component is the only thing that would make an attacker-chosen string
# decide where the bytes land (`Path(x).name` is `''` for `"."`/`"/"`, `'..'`
# for `".."`, and a NUL or a 300-char name is a write error, not a request the
# server should fail on). It comes back as `filename`, which is what it is:
# display metadata — unvalidated client input, echoed verbatim (markdown, path
# separators and C1 control characters all survive), so a UI escapes it.
_STORED_NAME = "upload"


@app.post("/upload")
async def upload(apk: UploadFile = File(...)) -> dict:
    """Save an uploaded container, open DexKit, return a session_id.

    The upload is identified by CONTENT, not by its filename — an `.apk`, a
    bare `.dex`, a `.jar`/`.zip` whose dexes start at `classes.dex`, or a
    renamed / extension-less dump all load, exactly as `DexKit(path)` does.
    What the loader refuses — a non-container, a zip with no `classes.dex`
    (a `classes2.dex`-only zip is refused: the run must START there), a dex no
    logical slice of which survives the structural verifier — comes back as a
    400 carrying its reason. A container whose SIBLING dex is rejected still
    loads its survivors (dexllm#25), so it is a 200; `loaded_dex_count` is
    then the honest count, and the per-dex verdicts are in `verify_report()`.

    The file lives in a session-scoped tempdir until DELETE /session/{id}
    or LRU eviction. Opening DexKit can take several seconds for large
    APKs, so the cost is paid here, once, instead of on every /analyze.
    """
    sid = uuid.uuid4().hex
    tmpdir = ""

    # Both calls fail on the SAME condition — a full or unwritable $TMPDIR —
    # so they answer with the same 500 and the same reason. That is ours, not
    # the caller's; the loader's refusal below is the caller's 400.
    try:
        tmpdir = tempfile.mkdtemp(prefix=f"dexkit-{sid}-")
        apk_path = str(Path(tmpdir) / _STORED_NAME)
        with open(apk_path, "wb") as f:
            shutil.copyfileobj(apk.file, f)
    except Exception as e:
        shutil.rmtree(tmpdir, ignore_errors=True)
        raise HTTPException(
            status_code=500,
            detail=f"failed to store upload: {type(e).__name__}: {e}",
        )

    try:
        dk = await asyncio.to_thread(DexKit, apk_path)
        # The loader already probed this file to decide how to read it, so take
        # ITS record rather than reading the path a second time (dexllm#42) —
        # applying here the same rule that change made for the MCP tool: a fact
        # about the session comes from the session.
        verdict = dk.source_info()[0]
    except Exception as e:
        shutil.rmtree(tmpdir, ignore_errors=True)
        raise HTTPException(
            status_code=400,
            detail=f"failed to open upload: {type(e).__name__}: {e}",
        )

    # Everything the response needs is read BEFORE the session is registered:
    # a raise after that point would orphan a session whose id the client never
    # received, so registration is the last statement that can fail.
    size_bytes = os.path.getsize(apk_path)
    loaded_dex_count = dk.dex_count()

    sess = Session(sid, apk_path, tmpdir, dk)
    _sessions[sid] = sess
    _evict_if_needed()

    return {
        "session_id": sid,
        "apk_path": apk_path,
        "filename": apk.filename,
        "size_bytes": size_bytes,
        # What the uploaded container WAS, as the loader recorded it. Its
        # `source` is the STORED path (= `apk_path`), i.e. the file that was
        # actually probed — not the client's `filename`, which is display
        # metadata and is not a path component at all (dexllm#47).
        "identified": verdict,
        # ...and the session's own count, under a name that cannot be mistaken
        # for it: a concatenated packer dump probes as ONE dex and loads as N,
        # and a container whose sibling dex the verifier rejects loads FEWER
        # than it declares. dexllm#38 drew the same line for the MCP `identify`.
        "loaded_dex_count": loaded_dex_count,
    }


@app.delete("/session/{sid}")
def drop_session(sid: str) -> dict:
    """Close and remove the session ``sid``; report whether it existed."""
    s = _sessions.pop(sid, None)
    if s is None:
        raise HTTPException(status_code=404, detail=f"unknown session_id: {sid}")
    s.close()
    return {"ok": True, "session_id": sid}


# ─── Tool-use loop ────────────────────────────────────────────────────────

SYSTEM_PROMPT = (
    "You are an Android security analyst. The user has uploaded a dex "
    "container — an APK, or a bare/dumped dex with no manifest; "
    "use the provided dexkit tools to investigate it. Be methodical: "
    "1) start with `summarize_capabilities` or `list_classes` to orient, "
    "2) drill into suspicious areas with `find_*` tools, "
    "3) use `decompile_method` / `decompile_class` to confirm hypotheses. "
    "Reference specific class/method descriptors when you make claims. "
    "Prefer focused tool calls over wide enumerations."
)


def _sse(event: str, data: Any) -> dict:
    """sse-starlette event payload."""
    return {"event": event, "data": json.dumps(data, default=str)}


async def _run_agent(sess: Session, prompt: str) -> AsyncIterator[dict]:
    """Yield SSE events for one user prompt.

    Implements the manual tool-use loop:
      messages.create(tools=...) → check stop_reason → if 'tool_use' run
      tools.execute() for each tool_use block → append tool_result content
      → loop. Stops on stop_reason == 'end_turn' or MAX_TURNS.
    """
    client = _anthropic()
    tools = dxtools.tool_definitions()
    messages: list[dict] = [{"role": "user", "content": prompt}]

    yield _sse("session", {"session_id": sess.id, "apk_path": sess.apk_path})

    for turn in range(MAX_TURNS):
        try:
            resp = await asyncio.to_thread(
                client.messages.create,
                model=MODEL,
                max_tokens=MAX_TOKENS,
                system=SYSTEM_PROMPT,
                tools=tools,
                messages=messages,
                # display="summarized": Opus 4.8 omits thinking text by default,
                # which would make the SSE `thinking` events empty; opt in so the
                # reasoning is streamed to the browser.
                thinking={"type": "adaptive", "display": "summarized"},
            )
        except Exception as e:
            yield _sse(
                "error",
                {"where": "messages.create", "error": f"{type(e).__name__}: {e}"},
            )
            return

        # Surface every block to the UI.
        for block in resp.content:
            btype = getattr(block, "type", None)
            if btype == "text":
                yield _sse("text", {"turn": turn, "text": block.text})
            elif btype == "thinking":
                yield _sse(
                    "thinking", {"turn": turn, "text": getattr(block, "thinking", "")}
                )
            elif btype == "tool_use":
                yield _sse(
                    "tool_use",
                    {
                        "turn": turn,
                        "id": block.id,
                        "name": block.name,
                        "input": block.input,
                    },
                )

        # Append the assistant turn verbatim so tool_use ids match on the next call.
        messages.append({"role": "assistant", "content": resp.content})

        if resp.stop_reason == "end_turn" or resp.stop_reason == "stop_sequence":
            yield _sse("done", {"turn": turn, "stop_reason": resp.stop_reason})
            return

        if resp.stop_reason != "tool_use":
            yield _sse("done", {"turn": turn, "stop_reason": resp.stop_reason})
            return

        tool_results = []
        for block in resp.content:
            if getattr(block, "type", None) != "tool_use":
                continue
            result = await asyncio.to_thread(
                dxtools.execute, block.name, dict(block.input or {}), sess.dk
            )
            payload = json.dumps(result, default=str)
            is_error = isinstance(result, dict) and "error" in result
            yield _sse(
                "tool_result",
                {
                    "turn": turn,
                    "tool_use_id": block.id,
                    "name": block.name,
                    "is_error": is_error,
                    "result": result,
                },
            )
            tool_results.append(
                {
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": payload,
                    "is_error": is_error,
                }
            )

        messages.append({"role": "user", "content": tool_results})

    yield _sse("done", {"stop_reason": "max_turns", "max_turns": MAX_TURNS})


@app.post("/analyze")
async def analyze(
    session_id: str = Form(...), prompt: str = Form(...)
) -> EventSourceResponse:
    """Stream the agent's SSE response for ``prompt`` against the session's dex."""
    sess = _get_session(session_id)
    return EventSourceResponse(_run_agent(sess, prompt))


# ─── Static introspection ─────────────────────────────────────────────────


@app.get("/tools")
def list_tools() -> dict:
    """Return the tool catalog served to the model.

    Useful for the UI to render a 'what can Claude do here' panel.
    """
    return {"tools": dxtools.tool_definitions()}


def main() -> None:
    """Entry point for `python -m dexllm.server` (dev convenience)."""
    import uvicorn

    uvicorn.run(
        "dexllm.server:app",
        host=os.environ.get("DEXKIT_HOST", "127.0.0.1"),
        port=int(os.environ.get("DEXKIT_PORT", "8000")),
        log_level=os.environ.get("DEXKIT_LOG_LEVEL", "info"),
    )


if __name__ == "__main__":
    main()
