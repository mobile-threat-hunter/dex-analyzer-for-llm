"""dexllm(#55) — a cache-init failure must REPORT, never block forever.

`DexKit::InitDexCache` published a dex's "cache ready" flag only on the success
path, and `DexItem::WaitInitCache` was an unconditional `cv.wait` with no timeout
and no failure state. A cache-init task that threw was swallowed by the
`packaged_task` whose future `InitDexCache` discards, so the claim was never
retired and every caller of the warm / caller-xref family blocked forever.

THE VEHICLE IS GONE, AND THERE IS NO FOURTH ONE. This file has been re-based
twice and cannot be a third time, so the history is the point:

  #55  `class_def.annotations_off` repointed at the map_list — a well-formed
       offset holding the wrong structure, which worked only because that offset
       was checked by nothing.
  #56  closed it (the verifier walks the whole annotations subtree), and the
       guards went from green to nine hard errors, correctly naming the reason.
       Replaced by a ONE-BYTE craft: an annotation element retyped to
       `0x16 METHOD_HANDLE` on a **section-less** dex, where the index is out of
       range by construction and `ArrayView`'s `SLICER_CHECK_LT` throws.
  #72  closed THAT, by porting ART :1204/:1212. This file and CLAUDE.md both
       called the channel one "no future verifier improvement can take away,
       because closing it at the gate would be a false-reject" — dexllm#59
       measured ART and refuted it (`NumMethodHandles()` is 0 for a section-less
       dex, so ART rejects exactly this craft), and dexllm#72 acted on that.

WHY NO FOURTH, stated as a measurement rather than as a search that gave up.
Cache init dereferences three things: the instruction stream (DexKit's own
walk, bounded), the annotations subtree, and the id tables — and the verifier now
covers all three per-structure. Measured against the pre-#72 build:

  * every bare corpus dex x all 32 `encoded_value` type codes, retyped
    width-preservingly on a class annotation: **`0x16` was the ONLY one that
    verified and then threw** (2 of 64). After #72: **0 of 64**.
  * 500 random mutations inside the annotation sections and 1,200 across every
    map section: 317 verified, **0 threw**.
  * 120 `lenient=True` instruction-stream mutations: 11 verified, **0 threw**.
  * `RLIMIT_NPROC` reaches the pool CONSTRUCTOR, not a task — the throw comes
    out of `InitDexCache` directly ("Resource temporarily unavailable"), so it
    never reaches `AbortInitCache` / `WaitInitCache` at all. That is the one
    behavioural guard left, and it is the LAST test in this file.

WHAT THAT COSTS, said plainly: the publish-on-failure machinery — `AbortInitCache`
retiring the claim and recording a reason, `WaitInitCache` throwing on the failed
FLAG, `BeginInitCache` excluding an already-failed one, and the two wiring
`catch`es — has no behavioural guard any more. The three mutants the crafted dex
used to kill (the pre-fix module, the `EnterQueryExecution` try/catch, and the
task's own try/catch) are all SOURCE-visible, so they are pinned that way below:
the same device this repo uses wherever a load-bearing line is unreachable from
any input (dexllm#63's advancing `default:`, dexllm#71's four index bounds,
dexllm#70's shared-helper call). A source pin is weaker than a behavioural one —
it cannot see a line that is present and wrong — but it is what is left, and
"nothing" was not an option.

The surviving behavioural guard runs in a SUBPROCESS: a regression must FAIL the
suite, not hang it, and an in-process assertion cannot do that.
"""

from __future__ import annotations

import pathlib
import subprocess
import sys
import textwrap

import pytest
from conftest import REPO_ROOT

TIMEOUT_S = 90

_DEX_ITEM = REPO_ROOT / "vendor" / "dexkit_core" / "Core" / "dexkit" / "dex_item.cpp"
_DEXKIT = REPO_ROOT / "vendor" / "dexkit_core" / "Core" / "dexkit" / "dexkit.cpp"


def _strip_comments(text: str) -> str:
    """Remove // and /* */ comments, scanning left to right.

    One pass, in source order: a `//` line can contain `/*`, and this repo has
    paid for the two-regex version twice (dexllm#32, dexllm#57). Every pin below
    reads the stripped text, so a fix that survives only as a COMMENT is not a
    fix — which is exactly the mutant shape a reviewer used on dexllm#57.
    """
    out = []
    i, n = 0, len(text)
    while i < n:
        if text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


def test_the_comment_stripper_is_not_the_thing_that_is_broken():
    """Non-discriminating BY DESIGN — every pin below rests on this."""
    assert _strip_comments("a // /* b\nc") == "a \nc"
    assert _strip_comments("a /* // b */ c") == "a  c"
    assert _strip_comments("a /* unterminated") == "a "


def _body(path: pathlib.Path, signature: str) -> str:
    """The stripped body of the function whose definition starts with `signature`."""
    text = _strip_comments(path.read_text())
    start = text.index(signature)
    depth, i = 0, text.index("{", start)
    for j in range(i, len(text)):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                return text[i : j + 1]
    raise AssertionError(f"{signature} has no balanced body")  # pragma: no cover


# ── the publish/retire/throw state machine (dexllm#55's core) ────────────────
#
# Pinned at source because dexllm#72 removed the last input that can reach it.
# Each assertion names the ONE line the corresponding mutant deleted.


def test_a_failed_cache_init_is_published_not_merely_abandoned():
    """`AbortInitCache` must RECORD the failure and RETIRE the claim.

    Recording without retiring leaves the next `BeginInitCache` waiting on an
    in-flight claim that will never be published; retiring without recording
    leaves `WaitInitCache` with nothing to throw on, so it returns normally and
    the caller proceeds on a half-built cache.
    """
    body = _body(_DEX_ITEM, "void DexItem::AbortInitCache(")
    assert "init_cache_failed_flags |= failed_flags;" in body, body
    assert "init_cache_inflight_flags &= ~init_flags;" in body, body
    assert "init_cache_state_cv.notify_all();" in body, body
    # A reason is never empty, which is what lets WaitInitCache read it directly.
    assert "unknown error" in body, body


def test_the_waiter_wakes_on_failure_and_throws_on_the_FLAG():
    """`WaitInitCache` waits on `(ready | failed)` and throws keyed on the flag.

    Waiting on `ready` alone IS the original hang. Keying the throw on the
    message instead of the flag is a provably EQUIVALENT mutant today (a failed
    flag always carries a reason) and is rejected anyway: the flag is the state
    that means "failed", and a message-keyed throw would silently stop raising
    if that ever changed.
    """
    body = _body(_DEX_ITEM, "void DexItem::WaitInitCache(")
    assert "(ready_flags | init_cache_failed_flags) & init_flags) == init_flags" in body
    assert "failed = (init_cache_failed_flags & init_flags) != 0;" in body, body
    assert 'throw std::runtime_error("dex cache init failed: " + error);' in body, body


def test_a_failed_flag_is_not_claimed_again():
    """`BeginInitCache` excludes an already-failed flag.

    Without it the retry re-runs work known to throw on this dex; with it the
    caller reaches `WaitInitCache` and is told why. The two are coupled — this
    is what makes the failure STICKY rather than merely reported once.
    """
    body = _body(_DEX_ITEM, "uint32_t DexItem::BeginInitCache(")
    assert "& ~init_cache_failed_flags" in body, body


def test_the_task_publishes_its_own_diagnosis():
    """The enqueued lambda wraps `InitCache` in a catch that calls Abort*.

    Dropping it leaves the post-join net (`RetireInitClaims`) as the only
    publisher — the caller still gets an exception, which is why this mutant
    survived every other assertion in the file, but the message degrades from
    the real cause to "cache init task did not run".
    """
    body = _body(_DEXKIT, "void DexKit::InitDexCache(")
    assert "dex_item->InitCache(claimed_flags);" in body, body
    assert (
        "dex_item->AbortInitCache(claimed_flags, DescribeCurrentException());" in body
    )
    assert "dex_item->FinishInitCache(claimed_flags);" in body, body
    # The net, for a task that never ran at all, and the enqueue-throws path,
    # which must release rather than latch (a blip is not a verdict).
    assert "RetireInitClaims(init_jobs);" in body, body
    assert "ReleaseInitClaims(init_jobs);" in body, body
    # …and the WAIT. The state machine above publishes a verdict; this is the
    # line that makes anyone READ it, and it is the one the retired behavioural
    # guards covered that nothing else does: a correctness reviewer deleted it,
    # rebuilt, and the whole suite passed at the published 1040 — while the same
    # mutant against the pre-fix build and the pre-dexllm#72 test file gave 9
    # errors, all "warm_analysis_caches never returned". Without it a failed
    # cache init is published and then ignored, so the caller proceeds on caches
    # that were never built.
    assert "dex_item->WaitInitCache(init_flags);" in body, body


def test_the_warmup_flag_is_retired_on_the_throwing_path_too():
    """`EnterQueryExecution` clears `warmup_inflight` on BOTH paths.

    Making `InitDexCache` throw without this moves the hang one frame up: every
    later query blocks in `EnterQueryExecution`'s own wait instead. The queue
    ticket goes with it — the ticket is owned by a LOCAL, so leaving it in the
    wait queue strands it there permanently.
    """
    body = _body(_DEXKIT, "DexKit::QueryExecutionGuard DexKit::EnterQueryExecution(")
    after = body.split("InitDexCache(warmup_flags);", 1)[1]
    caught = after.split("catch (...)", 1)[1].split("throw;", 1)[0]
    assert "warmup_inflight = false;" in caught, caught
    assert "dequeue_shared_pool_admission_ticket();" in caught, caught
    assert "query_execution_cv.notify_all();" in caught, caught


# ── the one behavioural path left ────────────────────────────────────────────


def test_a_clean_dex_still_warms(dk):
    """No-regression on the corpus: the sticky-failure bookkeeping must not
    make a healthy dex look failed."""
    dk.warm_analysis_caches()
    dk.warm_analysis_caches()
    assert dk.list_classes()


def test_a_transient_resource_failure_is_not_latched_and_does_not_abort():
    """Out of threads must be REPORTED, and must not brick the DexKit.

    Two defects an adversarial review reproduced with a real `RLIMIT_NPROC`:

    * `ThreadPool`'s constructor was not exception-safe, so when `pthread_create`
      failed on any thread AFTER the first, unwinding destroyed a still-joinable
      `std::thread` and the process hit `std::terminate` — before any caller's
      catch could run, which silently voided the recovery path `InitDexCache`
      builds on that scope being catchable.
    * the sticky failure latched the blip, so a DexKit that hit its pids limit
      for one instant was permanently dead: every later call raised, with the
      generic "cache init task did not run" rather than the real cause.

    Runs in a subprocess because it lowers a process-wide rlimit, and drives the
    committed 2-dex container so the pool has 2 threads (the >1 case is the one
    that aborted; 1 thread was already survivable).
    """
    if not sys.platform.startswith("linux"):
        pytest.skip("RLIMIT_NPROC behaviour is Linux-specific")

    prog = textwrap.dedent("""
        import resource, subprocess, sys
        import dexllm
        dk = dexllm.DexKit(sys.argv[1])
        soft, hard = resource.getrlimit(resource.RLIMIT_NPROC)
        tasks = int(subprocess.run(
            ["bash", "-c", "ps -u $(id -u) -o pid= | wc -l"],
            capture_output=True, text=True).stdout.strip())
        resource.setrlimit(resource.RLIMIT_NPROC, (tasks + int(sys.argv[2]), hard))
        try:
            dk.warm_analysis_caches()
            print("BLIP_NOT_TRIGGERED")
        except Exception as e:
            print("BLIP", type(e).__name__, str(e).replace(chr(10), " "))
        resource.setrlimit(resource.RLIMIT_NPROC, (hard, hard))
        try:
            dk.warm_analysis_caches()
            print("RETRY_OK")
        except Exception as e:
            print("RETRY_RAISED", str(e).replace(chr(10), " "))
        """)
    apk = str(REPO_ROOT / "tests" / "data" / "multidex.apk")
    # Sweep the headroom: failing the FIRST pool thread was survivable even
    # before the fix (nothing was built yet), so a single k can miss the defect
    # entirely — the one that aborted is the one where a LATER thread fails.
    blips = 0
    for k in (0, 1, 2, 3, 4):
        proc = subprocess.run(
            [sys.executable, "-c", prog, apk, str(k)],
            capture_output=True,
            text=True,
            timeout=TIMEOUT_S,
        )
        out = proc.stdout
        assert proc.returncode == 0, (
            f"k={k}: the process died (rc={proc.returncode}) instead of reporting — "
            f"out={out!r} err={proc.stderr[-400:]!r}"
        )
        if "BLIP_NOT_TRIGGERED" in out:
            continue
        blips += 1
        assert "BLIP RuntimeError" in out, f"k={k}: {out!r}"
        # The reason must be the real one, not the post-join net's placeholder.
        assert "task did not run" not in out.split("RETRY")[0], f"k={k}: {out!r}"
        assert "RETRY_OK" in out, f"k={k}: a transient shortage was latched: {out!r}"

    if blips == 0:
        pytest.skip("could not make thread creation fail on this host")


def test_extract_iocs_does_not_hand_back_a_silently_locationless_report():
    """A systematic xref failure must PROPAGATE, not be swallowed per query.

    `extract_iocs` guards each cross-reference query with `except Exception`, so
    that one bad query cannot abort the report. dexllm#55 turned a hanging dex
    into a RAISING one, and that guard then converted the raise into every
    indicator coming back with `methods: []` and no error at all — which reads
    as "this indicator appears in no code", the exact ambiguity `declared_in`
    was added to remove. Distinguished by whether ANY query has ever worked.
    """

    class _Boom:
        """Enough of the DexKit surface for extract_iocs, with a dead xref."""

        def list_value_strings(self):
            return ["http://evil.example.com/a", "1.2.3.4"]

        def list_classes(self):
            return ["Lcom/example/App;"]

        def list_external_type_refs(self, *a, **k):
            return []

        def find_methods_using_strings(self, *a, **k):
            raise RuntimeError("dex cache init failed: crafted")

        def find_classes_declaring_strings(self, *a, **k):
            raise RuntimeError("dex cache init failed: crafted")

    import dexllm

    with pytest.raises(RuntimeError, match="cache init failed"):
        dexllm.extract_iocs(_Boom(), with_xref=True)

    # With the xref switched off the report is honest about carrying no
    # locations, so it must still be produced.
    off = dexllm.extract_iocs(_Boom(), with_xref=False)
    assert off["domains"] or off["urls"] or off["ips"]
