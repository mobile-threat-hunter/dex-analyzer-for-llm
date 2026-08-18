"""dexllm(#55) — a cache-init failure must REPORT, never block forever.

`DexKit::InitDexCache` published a dex's "cache ready" flag only on the success
path, and `DexItem::WaitInitCache` was an unconditional `cv.wait` with no timeout
and no failure state. A cache-init task that threw was swallowed by the
`packaged_task` whose future `InitDexCache` discards, so the claim was never
retired and every caller of the warm / caller-xref family blocked forever — on a
dex the structural verifier calls **valid**, because annotations are documented
as out of its scope.

The fixture crafts exactly that: it repoints one class_def's `annotations_off`
at the map_list, which is a well-formed offset holding the wrong structure. The
craft is IN PLACE and length-preserving, so every other section, offset and
checksum-independent field is untouched and the dex still verifies.

Every call that could hang runs in a SUBPROCESS with a deadline. A regression
must FAIL the suite, not hang it — an in-process assertion cannot do that.
"""

from __future__ import annotations

import glob
import pathlib
import struct
import subprocess
import sys
import textwrap

import pytest
from conftest import REPO_ROOT, require_corpus_shape

TIMEOUT_S = 90

# class_def_item is 32 bytes: class_idx, access_flags, superclass_idx,
# interfaces_off, source_file_idx, annotations_off, class_data_off,
# static_values_off — annotations_off is the 6th field, at +20.
_ANNOTATIONS_OFF = 20
_CLASS_DEF_SIZE = 32


def _craft(src: pathlib.Path, dst: pathlib.Path) -> bool:
    """Repoint the first nonzero `annotations_off` at the map_list.

    Returns False when `src` declares no annotated class, i.e. the shape this
    guard needs is absent from that file.
    """
    raw = bytearray(src.read_bytes())
    if raw[:4] != b"dex\n":
        return False
    map_off = struct.unpack_from("<I", raw, 0x34)[0]
    cds_size, cds_off = struct.unpack_from("<II", raw, 0x60)
    for i in range(cds_size):
        p = cds_off + i * _CLASS_DEF_SIZE + _ANNOTATIONS_OFF
        if struct.unpack_from("<I", raw, p)[0] == 0:
            continue
        struct.pack_into("<I", raw, p, map_off)
        dst.write_bytes(bytes(raw))
        return True
    return False


@pytest.fixture(scope="module")
def broken_cache_dex(tmp_path_factory):
    """A dex that VERIFIES but whose cache init throws.

    Three outcomes, and keeping them apart is the whole point — this fixture
    both BUILDS the input and runs the first probe against the product, so a
    naive "try the next candidate" loop reports a product regression as a
    missing corpus shape, and hides it entirely under a narrowing:

    * no bare `.dex` at all (the corpus-less CI leg)      -> SKIP, an environment fact
    * bare dexes exist but none is craftable              -> require_corpus_shape
    * a craftable dex HANGS the product                   -> FAIL, always
    """
    import dexllm

    candidates = sorted(glob.glob(str(REPO_ROOT / "test_apk" / "APK" / "*.dex")))
    if not candidates:
        pytest.skip("no bare .dex in the corpus to craft from")

    out = tmp_path_factory.mktemp("cacheinit") / "broken.dex"
    craftable = 0
    for src in candidates:
        if not _craft(pathlib.Path(src), out):
            continue
        report = dexllm.verify(str(out))
        if not report or not all(r["valid"] for r in report):
            continue
        craftable += 1
        # The craft must actually break cache init — otherwise the guards would
        # pass vacuously against any implementation. A HANG here is the defect
        # dexllm#55 removes, so it fails outright: it is a fact about the
        # product, and a narrowed corpus must not soften it.
        result = _run("dk.warm_analysis_caches()", out)
        if result.verdict == "HUNG":
            pytest.fail(
                f"dexllm#55 regression: warm_analysis_caches never returned on a "
                f"crafted {pathlib.Path(src).name} ({result.detail})"
            )
        if result.verdict != "RAISED":
            continue
        return out

    require_corpus_shape(
        craftable > 0,
        "bare .dex declaring an annotated class whose crafted annotations_off "
        "breaks cache init",
        "the #55 fixture can no longer be built, so the hang is unguarded",
    )
    pytest.fail(
        f"{craftable} crafted dex(es) verified but none broke cache init — the "
        "fixture no longer reaches the code path it guards"
    )


class _Result:
    def __init__(self, verdict: str, detail: str) -> None:
        self.verdict = verdict  # "RAISED" | "OK" | "HUNG" | "CRASHED"
        self.detail = detail

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"_Result({self.verdict!r}, {self.detail[:120]!r})"


def _run(body: str, dex: pathlib.Path) -> _Result:
    """Run `body` against a DexKit over `dex`, in a subprocess with a deadline.

    A hang is the DEFECT under test, so it must be observed as a timeout rather
    than blocking the test session.
    """
    prog = textwrap.dedent("""
        import sys
        import dexllm
        dk = dexllm.DexKit([sys.argv[1]])
        try:
            {body}
        except Exception as e:
            print("RAISED", type(e).__name__, str(e).replace(chr(10), " "))
        else:
            print("OK")
        """).format(body=body)
    try:
        proc = subprocess.run(
            [sys.executable, "-c", prog, str(dex)],
            capture_output=True,
            text=True,
            timeout=TIMEOUT_S,
        )
    except subprocess.TimeoutExpired:
        return _Result("HUNG", f"no result within {TIMEOUT_S}s")
    out = proc.stdout.strip()
    if proc.returncode != 0:
        return _Result("CRASHED", f"rc={proc.returncode} {proc.stderr[-300:]}")
    if out.startswith("RAISED"):
        return _Result("RAISED", out)
    if out.startswith("OK"):
        return _Result("OK", out)
    return _Result("CRASHED", f"unexpected output {out!r}")  # pragma: no cover


# ── the premise ──────────────────────────────────────────────────────────────


def test_the_crafted_dex_still_verifies(broken_cache_dex):
    """Non-discriminating BY DESIGN — it pins the premise.

    The whole point is that the verifier ACCEPTS this dex (annotations are
    documented out of its scope), so the failure has to be handled downstream
    rather than rejected at load. If this ever starts failing, the fixture is
    testing a different thing and the guards below prove nothing.
    """
    import dexllm

    report = dexllm.verify(str(broken_cache_dex))
    assert report and all(r["valid"] for r in report), report
    lenient = dexllm.verify(str(broken_cache_dex), lenient=True)
    assert lenient and all(r["valid"] for r in lenient), lenient


# ── the fix ──────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "call",
    [
        "dk.warm_analysis_caches()",
        "dk.find_call_sites_to('Ljava/lang/String;->length()I')",
        "dk.resolve_call_args('Ljava/lang/String;->length()I')",
        "dexllm.summarize_capabilities(dk)",
    ],
)
def test_a_failed_cache_init_reports_instead_of_blocking(broken_cache_dex, call):
    """Every API that warms the caller/cross-ref caches must raise, not hang."""
    result = _run(call, broken_cache_dex)
    assert result.verdict == "RAISED", f"{call}: {result.verdict} — {result.detail}"
    assert "cache init failed" in result.detail, result.detail


def test_the_reason_reaches_the_caller(broken_cache_dex):
    """The message must name the UNDERLYING failure, not a placeholder.

    Two things could publish the failure: the task's own `catch (...)`, which
    knows what was thrown, and the post-join net in `InitDexCache`, which only
    knows that nothing was published. Both retire the claim, so a caller still
    gets an exception either way — which is exactly why dropping the task's
    catch survived every other assertion in this file. What it costs is the
    diagnosis, so that is what this pins: neither the "unknown error" fallback
    nor the net's generic reason may be what the caller is told.
    """
    result = _run("dk.warm_analysis_caches()", broken_cache_dex)
    assert result.verdict == "RAISED", result.detail
    assert "unknown error" not in result.detail, result.detail
    assert "task did not run" not in result.detail, result.detail
    assert len(result.detail) > len(
        "RAISED RuntimeError cache init failed: "
    ), result.detail


def test_a_second_call_reports_too_and_does_not_block(broken_cache_dex):
    """The claim must be RETIRED, not merely abandoned.

    `BeginInitCache` sets `init_cache_inflight_flags` before the work starts and
    only the publish clears it — so a failure that left it set would make the
    NEXT caller block inside `BeginInitCache`'s own wait instead. Retrying is
    also how a consumer reacts to an error, which makes this the realistic path.
    """
    result = _run(
        "\n            try:\n"
        "                dk.warm_analysis_caches()\n"
        "            except Exception:\n"
        "                pass\n"
        "            dk.warm_analysis_caches()",
        broken_cache_dex,
    )
    assert result.verdict == "RAISED", f"{result.verdict} — {result.detail}"


def test_a_later_query_still_reports_rather_than_waiting_on_the_warmup(
    broken_cache_dex,
):
    """`EnterQueryExecution` sets `warmup_inflight` around `InitDexCache`.

    Making InitDexCache throw would leave that flag set forever, so every LATER
    query would block in `EnterQueryExecution`'s own wait — the old hang moved
    one frame up. This pins that a different API, entered after the failure,
    still reports.
    """
    result = _run(
        "\n            try:\n"
        "                dk.warm_analysis_caches()\n"
        "            except Exception:\n"
        "                pass\n"
        "            dk.find_call_sites_to('Ljava/lang/String;->length()I')",
        broken_cache_dex,
    )
    assert result.verdict == "RAISED", f"{result.verdict} — {result.detail}"


def test_the_apis_that_never_needed_the_cache_still_answer(broken_cache_dex):
    """No-regression: a broken cache must not take down the paths that do not
    use it. These worked before the fix (the hang was scoped to the caller /
    cross-ref flags) and must keep working."""
    result = _run(
        "\n            assert dk.list_classes()\n"
        "            assert dk.render_class_smali(dk.list_classes()[0])\n"
        "            dk.list_value_strings()\n"
        "            dk.decompile_class(dk.list_classes()[0])",
        broken_cache_dex,
    )
    assert result.verdict == "OK", f"{result.verdict} — {result.detail}"


def test_a_clean_dex_still_warms(dk):
    """No-regression on the corpus: the sticky-failure bookkeeping must not
    make a healthy dex look failed."""
    dk.warm_analysis_caches()
    dk.warm_analysis_caches()
    assert dk.list_classes()


# ── the paths the failure now travels, which the hang used to hide ───────────


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
