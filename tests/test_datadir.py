"""Guards for the bundled-data override channel (issue #33).

Two of the four files in ``data/`` carry hand judgement — the capability catalog
and ``content_uris.json``'s ``family`` labels — and before this channel an
installed user could not adjust either without editing ``site-packages``. The
unsupported workaround (assigning the module's private path global) worked only
before the first call, because the cache behind it had no invalidation:

    providers._DATA_PATH = custom   (before first use)  -> reflected
    providers._DATA_PATH = other    (cache warm)        -> ignored

So the guards below pin the two properties that made it unusable — resolution is
honoured per call, and two directories do not share one cache entry — plus the
failure modes, which #33 asked to be decided rather than left to a bare
``JSONDecodeError`` from inside a cached loader.

Deliberately NOT covered here: the permission table (``perm_api.json`` /
``perm_levels.json``). It is mechanical AOSP extraction with no hand content, and
``dataset_path=`` / ``$DEXLLM_AOSP_DATASET`` already serve its use case; adding it
to this channel would give one dataset two override mechanisms.

Corpus-free — every test uses a stub dk or the match helper directly.
"""

import json
import os

import pytest

from dexllm import capability, datadir, providers


@pytest.fixture(autouse=True)
def _isolate_caches(monkeypatch):
    """Each test starts with an empty data cache and no inherited env override."""
    monkeypatch.delenv(datadir.ENV_VAR, raising=False)
    datadir.clear_data_caches()
    yield
    datadir.clear_data_caches()


def _write_uris(directory, uri, family):
    (directory / "content_uris.json").write_text(
        json.dumps({uri: {"classes": ["Acme"], "family": family}})
    )


class _Site:
    """A call site as `summarize_capabilities` reads it (caller descriptor only)."""

    def __init__(self, caller):
        self.caller_descriptor = caller


class _StubDk:
    """Minimal dk: only the two calls detect_content_providers makes."""

    def __init__(self, strings):
        self._strings = strings

    def list_value_strings(self):
        return list(self._strings)

    def find_methods_using_strings(self, *_args, **_kwargs):
        return []


# --- resolution order -------------------------------------------------------


def test_arg_beats_env_beats_bundled(tmp_path, monkeypatch):
    """Resolution is arg -> $DEXLLM_DATA_DIR -> bundled, checked at each level."""
    bundled = providers.load_content_uris()
    assert "content://sms" in bundled, "premise: the bundled dataset carries sms"

    env_dir = tmp_path / "env"
    env_dir.mkdir()
    _write_uris(env_dir, "content://env-only", "envfam")
    arg_dir = tmp_path / "arg"
    arg_dir.mkdir()
    _write_uris(arg_dir, "content://arg-only", "argfam")

    monkeypatch.setenv(datadir.ENV_VAR, str(env_dir))
    assert set(providers.load_content_uris()) == {"content://env-only"}
    assert set(providers.load_content_uris(data_dir=str(arg_dir))) == {
        "content://arg-only"
    }

    monkeypatch.delenv(datadir.ENV_VAR)
    assert "content://sms" in providers.load_content_uris()


def test_two_data_dirs_do_not_share_a_cache_entry(tmp_path):
    """The pre-#33 order-dependence is gone: the cache is keyed by resolved path.

    This is the exact failure the issue reported — a second override was ignored
    once the cache was warm — so it FAILS against a single-slot module global.
    """
    first = tmp_path / "one"
    first.mkdir()
    _write_uris(first, "content://one", "famone")
    second = tmp_path / "two"
    second.mkdir()
    _write_uris(second, "content://two", "famtwo")

    assert set(providers.load_content_uris(data_dir=str(first))) == {"content://one"}
    assert set(providers.load_content_uris(data_dir=str(second))) == {"content://two"}
    # and back again — neither evicted the other
    assert set(providers.load_content_uris(data_dir=str(first))) == {"content://one"}


def test_per_file_replacement_falls_back_for_the_other_file(tmp_path):
    """Overriding one file must not oblige the user to copy the other.

    A directory holding only ``content_uris.json`` still serves the BUNDLED
    catalog — replacement is per file, which is what makes a one-file override
    practical.
    """
    _write_uris(tmp_path, "content://only", "onlyfam")

    assert set(providers.load_content_uris(data_dir=str(tmp_path))) == {
        "content://only"
    }
    catalog = capability._load_catalog(str(tmp_path))
    assert catalog["entries"], "the bundled catalog must still resolve"
    assert catalog.get("version"), "…and it is the real bundled file, not a stub"


# --- the value actually reaches the report ----------------------------------


def test_override_family_reaches_detect_content_providers(tmp_path):
    """The override changes REPORTED output, not merely the loader's return.

    Without this the channel could be wired into `load_content_uris` alone and
    `detect_content_providers` would keep serving bundled families.
    """
    _write_uris(tmp_path, "content://acme/things", "acme")
    dk = _StubDk(["content://acme/things/1"])

    hits = providers.detect_content_providers(
        dk, with_xref=False, data_dir=str(tmp_path)
    )
    assert [(h["uri"], h["family"]) for h in hits] == [
        ("content://acme/things", "acme")
    ]


def test_override_catalog_reaches_summarize_capabilities(tmp_path):
    """Same for the capability catalog: the report reflects the replacement."""
    sig = "Lcom/acme/X;->boom()V"
    (tmp_path / "android_api_map.json").write_text(
        json.dumps(
            {
                "version": "test-1",
                "category_vocabulary": ["ACME"],
                "flag_vocabulary": [],
                "entries": {
                    sig: {"permissions": ["acme.BOOM"], "categories": ["ACME"]}
                },
            }
        )
    )

    class _Dk:
        def find_call_sites_to(self, descriptor):
            return [_Site("La/B;->m()V")] if descriptor == sig else []

    report = capability.summarize_capabilities(_Dk(), data_dir=str(tmp_path))
    assert report.catalog_version == "test-1"
    assert report.catalog_size == 1
    assert report.categories == {"ACME": 1}


def test_a_custom_catalog_brings_its_own_vocabulary(tmp_path):
    """`only_categories` validates against the REPLACEMENT's declared vocabulary.

    A tag the custom catalog declares must be accepted even though the bundled
    catalog has never heard of it — otherwise the channel would let a user load a
    catalog they then cannot filter.
    """
    (tmp_path / "android_api_map.json").write_text(
        json.dumps(
            {
                "version": "test-1",
                "category_vocabulary": ["ACME"],
                "flag_vocabulary": [],
                "entries": {},
            }
        )
    )

    class _Dk:
        def find_call_sites_to(self, descriptor, **_kw):
            return []

    capability.summarize_capabilities(
        _Dk(), only_categories={"ACME"}, data_dir=str(tmp_path)
    )
    with pytest.raises(ValueError, match="TELEPHONY"):
        capability.summarize_capabilities(
            _Dk(), only_categories={"TELEPHONY"}, data_dir=str(tmp_path)
        )


def test_a_vocabulary_less_catalog_disables_the_only_categories_check(tmp_path):
    """A catalog declaring NEITHER vocabulary turns the loud failure off.

    Pinned because it is a documented EXEMPTION, not an oversight: the pre-existing
    rule keeps a catalog that predates the vocabulary keys usable instead of
    rejecting every filter. Before the override channel the catalog was always the
    bundled one (which declares both), so the exemption was unreachable — this
    change makes it reachable, which is why `summarize_capabilities` now states it.
    """
    (tmp_path / "android_api_map.json").write_text(
        json.dumps({"version": "novocab", "entries": {}})
    )

    class _Dk:
        def find_call_sites_to(self, descriptor):
            return []

    report = capability.summarize_capabilities(
        _Dk(), only_categories={"NOT_A_REAL_TAG"}, data_dir=str(tmp_path)
    )
    assert report.catalog_version == "novocab"
    assert report.matched_apis == 0


def test_env_override_reaches_the_sdk_and_mcp_layers(tmp_path, monkeypatch):
    """`$DEXLLM_DATA_DIR` is the form that reaches the argument-less layers.

    That is the whole reason the channel is an env var and not only a keyword —
    the SDK port and the MCP tool expose no data knobs at all (neither
    `dataset_path` nor `only_categories` nor this), so without the env var an
    embedded or MCP consumer could not override anything. Both hops are separate
    call sites and each would keep serving the bundled catalog if the resolution
    happened at import time rather than per call.
    """
    from dexllm import tools
    from dexllm.sdk.adapter import DexKitAdapter

    (tmp_path / "android_api_map.json").write_text(
        json.dumps(
            {
                "version": "env-1",
                "category_vocabulary": [],
                "flag_vocabulary": [],
                "entries": {},
            }
        )
    )
    monkeypatch.setenv(datadir.ENV_VAR, str(tmp_path))

    class _Dk:
        def find_call_sites_to(self, descriptor):
            return []

    adapter = DexKitAdapter.__new__(DexKitAdapter)
    adapter._dk = _Dk()  # type: ignore[attr-defined]
    assert DexKitAdapter.summarize_capabilities(adapter).catalog_version == "env-1"
    assert (
        tools.execute("summarize_capabilities", {}, _Dk())["catalog_version"] == "env-1"
    )


# --- failure modes ----------------------------------------------------------


def test_a_missing_data_dir_raises_naming_the_source(tmp_path, monkeypatch):
    """A typo'd directory fails loudly instead of silently serving bundled data.

    Both spellings are covered because they are separate code paths in the message
    and a user needs to know WHICH one pointed at the bad path.
    """
    missing = str(tmp_path / "nope")
    with pytest.raises(NotADirectoryError, match="data_dir="):
        providers.load_content_uris(data_dir=missing)

    monkeypatch.setenv(datadir.ENV_VAR, missing)
    with pytest.raises(NotADirectoryError, match=datadir.ENV_VAR):
        providers.load_content_uris()


def test_a_malformed_override_raises_naming_the_file(tmp_path):
    """Invalid JSON, non-UTF-8 bytes and a wrong shape all name the path.

    #33's complaint was a bare `JSONDecodeError` / `KeyError` surfacing from inside
    a cached loader with no indication of which file was at fault. The non-UTF-8
    case is separate because `json.loads` on bytes sniffs the encoding and raises
    `UnicodeDecodeError`, which is NOT a `JSONDecodeError` — catching only the
    latter lets a bare decoder error escape unnamed.

    No `clear_data_caches()` between the steps ON PURPOSE: each step re-reads the
    same path, so this also proves a FAILED load does not poison or half-populate
    the cache (a clear between them would mask exactly that).
    """
    (tmp_path / "content_uris.json").write_bytes(b"{not json")
    with pytest.raises(ValueError, match="content_uris.json"):
        providers.load_content_uris(data_dir=str(tmp_path))

    (tmp_path / "content_uris.json").write_bytes(b'\xff\xfe{"a":1}')
    with pytest.raises(ValueError, match="content_uris.json"):
        providers.load_content_uris(data_dir=str(tmp_path))

    (tmp_path / "content_uris.json").write_text(json.dumps({"content://x": {}}))
    with pytest.raises(ValueError, match="family"):
        providers.load_content_uris(data_dir=str(tmp_path))

    # …and the path is still loadable once repaired — nothing was cached.
    _write_uris(tmp_path, "content://ok", "okfam")
    assert set(providers.load_content_uris(data_dir=str(tmp_path))) == {"content://ok"}

    (tmp_path / "android_api_map.json").write_text(json.dumps({"no": "entries"}))
    with pytest.raises(ValueError, match="entries"):
        capability._load_catalog(str(tmp_path))


def test_validation_is_not_disabled_by_an_earlier_unvalidated_load(tmp_path):
    """A validator-less load must not permanently switch validation off.

    `load_data_json` is public and the validator is not part of the cache key, so
    if it ran only on first load, priming a path without one would let the
    malformed file straight through to `KeyError: 'entries'` inside a cached
    loader — the exact #33 symptom, reintroduced by the fix for it.
    """
    (tmp_path / "android_api_map.json").write_text(json.dumps({"no": "entries"}))

    datadir.load_data_json(
        "android_api_map.json", data_dir=str(tmp_path)
    )  # no validator
    with pytest.raises(ValueError, match="entries"):
        capability._load_catalog(str(tmp_path))


def test_an_empty_data_dir_means_unset_through_both_spellings(tmp_path, monkeypatch):
    """`""` is the canonical shape of an unset config value, not the process CWD.

    `Path("")` is `Path(".")`, so an `is not None` test would silently resolve
    against the CWD — the same silent-wrong-source failure the missing-directory
    raise exists to prevent — and the env branch already treated `""` as unset,
    so the two spellings must agree.
    """
    assert "content://sms" in providers.load_content_uris(data_dir="")
    monkeypatch.setenv(datadir.ENV_VAR, "")
    assert "content://sms" in providers.load_content_uris()


def test_a_relative_data_dir_is_not_aliased_across_a_chdir(tmp_path, monkeypatch):
    """The cache key is a resolved path, so a relative dir is a stable identity.

    Keyed by the path AS SPELLED, `data_dir="."` in two different directories is
    one key — the second call would serve the first directory's file.
    """
    one = tmp_path / "one"
    one.mkdir()
    _write_uris(one, "content://one", "famone")
    two = tmp_path / "two"
    two.mkdir()
    _write_uris(two, "content://two", "famtwo")

    monkeypatch.chdir(one)
    assert set(providers.load_content_uris(data_dir=".")) == {"content://one"}
    monkeypatch.chdir(two)
    assert set(providers.load_content_uris(data_dir=".")) == {"content://two"}


def test_match_content_uris_threads_the_override(tmp_path):
    """The public mid-chain helper takes `data_dir` too.

    Nothing else covers it — every other test enters through `load_content_uris`
    or `detect_content_providers` — so the kwarg could be dropped from the middle
    of the chain with a green suite.
    """
    _write_uris(tmp_path, "content://acme/x", "acme")
    assert providers.match_content_uris(
        ["prefix content://acme/x suffix"], data_dir=str(tmp_path)
    ) == [("content://acme/x", "acme")]


def test_a_tag_list_written_as_a_bare_string_is_rejected(tmp_path):
    """The commonest hand-edit slip must NAME the file, not corrupt the report.

    `summarize_capabilities` iterates each tag list, so `"categories": "REFLECTION"`
    is perfectly iterable and would count each CHARACTER as a category
    (`{'R':1,'E':1,'F':1,...}`) with no error at all; a non-iterable instead raises
    `TypeError` deep in the walk, which `tools.execute` reports to an LLM as "bad
    arguments" — pointing it at its own call instead of at this file.
    """
    for bad in ("REFLECTION", 5, [["ACME"]], [None]):
        (tmp_path / "android_api_map.json").write_text(
            json.dumps({"version": "v", "entries": {"Lx;->y()V": {"categories": bad}}})
        )
        with pytest.raises(ValueError, match="categories"):
            capability._load_catalog(str(tmp_path))


def test_an_empty_uri_key_is_rejected(tmp_path):
    """An empty key is a substring of every string, so it would match everything.

    One degenerate row would put every `content://` value the app holds into the
    report under that row's family — the one shape the substring match cannot
    defend itself against.
    """
    (tmp_path / "content_uris.json").write_text(
        json.dumps({"": {"classes": ["X"], "family": "everything"}})
    )
    with pytest.raises(ValueError, match="empty URI key"):
        providers.load_content_uris(data_dir=str(tmp_path))


def test_the_cache_is_bounded(tmp_path):
    """A per-request `data_dir` must not grow the cache without bound.

    The key is a caller-supplied path, not a file name, so a multi-tenant caller
    adds an entry per directory (measured pre-fix: 300 dirs -> 600 entries,
    +44 MB). This repo has shipped that failure once at 1.6 GB, and the sibling
    permission loader bounds itself the same way.
    """
    for i in range(datadir._MAX_CACHE_ENTRIES * 3):
        d = tmp_path / f"d{i}"
        d.mkdir()
        _write_uris(d, f"content://n{i}", "fam")
        assert set(providers.load_content_uris(data_dir=str(d))) == {f"content://n{i}"}

    assert len(datadir._CACHE) <= datadir._MAX_CACHE_ENTRIES


def test_a_vanished_dir_is_loud_while_a_vanished_file_stays_stable(tmp_path):
    """The two directions of "something disappeared", and why they differ.

    INVERTED at issue #43. This test used to assert the opposite for the file
    half — that unlinking the override mid-run silently switched the answer to
    bundled — pinning as documented behaviour the very surprise #43 reports: a
    redeploy doing ``rm`` + ``cp`` has a window in which a long-lived server
    answers with different `family` labels from one request to the next. The
    decision to USE that override is now frozen, so the answer is STABLE across
    that window and only :func:`clear_data_caches` moves it. (The freeze and the
    content cache are two bounded structures with independent lifetimes, not "one
    lifetime" as an earlier draft of this comment said — see
    ``test_a_frozen_override_that_is_deleted_self_heals_once_nothing_is_cached``
    for what happens when they diverge.)

    The DIRECTORY half is unchanged and deliberate: an unmounted config volume
    must not be masked by what the process happened to load an hour ago.
    """
    import shutil

    _write_uris(tmp_path, "content://vol", "volfam")
    assert set(providers.load_content_uris(data_dir=str(tmp_path))) == {"content://vol"}

    # the file alone disappears -> the answer does NOT change mid-run
    (tmp_path / "content_uris.json").unlink()
    assert set(providers.load_content_uris(data_dir=str(tmp_path))) == {"content://vol"}
    # …and the documented reset is what moves it, not a filesystem event
    datadir.clear_data_caches()
    assert "content://sms" in providers.load_content_uris(data_dir=str(tmp_path))

    # the whole directory disappears -> loud, even though a copy is still cached
    _write_uris(tmp_path, "content://vol", "volfam")
    assert set(providers.load_content_uris(data_dir=str(tmp_path))) == {"content://vol"}
    shutil.rmtree(tmp_path)
    with pytest.raises(NotADirectoryError):
        providers.load_content_uris(data_dir=str(tmp_path))


@pytest.mark.parametrize(
    "kind", ["directory", "fifo", "dangling", "loop", "link_to_fifo"]
)
@pytest.mark.parametrize("spelling", ["arg", "env"])
def test_an_override_entry_that_is_not_a_regular_file_is_loud(
    tmp_path, kind, spelling, monkeypatch
):
    """issue #43: "not a regular file" is a misconfiguration, not "absent".

    The old test was ``is_file()``, so all four of these read as absent and fell
    back — and the realistic one is the DANGLING SYMLINK: an override that is not
    really there, after which the analysis runs on bundled data while the operator
    believes theirs is live. The module docstring promised the opposite ("a typo'd
    path silently serving bundled data is the failure this prevents"), and that
    guarantee held only at the directory level.

    ``dangling``/``loop`` are why the check cannot be ``exists()``: it follows the
    link, so both read as absent.

    Parametrised over BOTH spellings because the message has a branch naming which
    one supplied the path — its ``NotADirectoryError`` sibling has
    ``test_a_missing_data_dir_raises_naming_the_source`` for exactly that reason,
    and an adversarial review showed a mutant hard-coding ``data_dir=`` survived
    the arg-only version.
    """
    entry = tmp_path / "content_uris.json"
    if kind == "directory":
        entry.mkdir()
    elif kind == "fifo":
        os.mkfifo(entry)
    elif kind == "dangling":
        entry.symlink_to(tmp_path / "never_mounted.json")
    elif kind == "link_to_fifo":
        # a link is only as good as what it points AT — a reviewer's mutant that
        # accepted any link with an existing target survived the other four kinds
        # and handed the loader a FIFO, i.e. an unbounded block one hop away.
        target = tmp_path / "pipe"
        os.mkfifo(target)
        entry.symlink_to(target)
    else:
        entry.symlink_to(entry)  # a self-referential link: ELOOP on any follow

    if spelling == "arg":
        call, expected_source = (
            lambda: providers.load_content_uris(data_dir=str(tmp_path)),
            "data_dir=",
        )
    else:
        monkeypatch.setenv(datadir.ENV_VAR, str(tmp_path))
        call, expected_source = providers.load_content_uris, "$" + datadir.ENV_VAR

    # bounded: a `fifo`/`link_to_fifo` that slipped through would be handed to
    # `read_bytes()`, which blocks forever — a hang, not a failure, without this
    got = _bounded(call)
    assert isinstance(got, OSError), f"expected a raise, got {got!r}"
    assert "is not a regular file" in str(got)
    assert str(entry) in str(got), "the message must name the offending path"
    assert expected_source in str(
        got
    ), "…and which spelling supplied it, like the NotADirectoryError sibling"
    # …and it is not a one-shot: the raise is not memoised into a frozen decision
    assert isinstance(_bounded(call), OSError)


def test_a_genuinely_absent_override_file_still_falls_back(tmp_path):
    """The other side of the same predicate — non-discriminating BY DESIGN.

    Partial override is the feature the fallback exists for, so the #43 raise must
    narrow "absent" to "nothing is there at all" without narrowing it further. A
    fix that raised on any non-``is_file()`` candidate would pass every assertion
    in the test above and break the channel's headline behaviour.
    """
    assert not (tmp_path / "content_uris.json").exists()
    assert "content://sms" in providers.load_content_uris(data_dir=str(tmp_path))


def test_a_symlink_to_a_real_file_is_a_valid_override(tmp_path):
    """A symlinked override is the NORMAL deployment shape, not the failure one.

    The #43 check accepts a link that RESOLVES to a regular file and rejects one
    that does not — that is what separates "the volume mounted" from "it did not".
    Without this the fix would reject the very configuration it protects.
    """
    real = tmp_path / "real"
    real.mkdir()
    _write_uris(real, "content://linked", "linkfam")
    link_dir = tmp_path / "cfg"
    link_dir.mkdir()
    (link_dir / "content_uris.json").symlink_to(real / "content_uris.json")

    assert set(providers.load_content_uris(data_dir=str(link_dir))) == {
        "content://linked"
    }


def test_a_frozen_decision_is_absolute_and_shared_by_every_spelling(
    tmp_path, monkeypatch
):
    """The frozen VALUE must be resolved, not the caller's spelling (issue #43).

    The first cut keyed the memo on the RESOLVED root but stored the SPELLED
    candidate, so a relative `data_dir` froze a CWD-relative path that a later call
    re-anchored elsewhere: two reviewers independently constructed
    ``cwd=/a data_dir="cfg"`` then ``cwd=/b data_dir="/a/cfg"`` -> served /b's
    dataset for an explicit, unambiguous /a request. That is a silent cross-
    directory WRONG ANSWER — worse than the bug being fixed — and it is exactly the
    aliasing the content cache resolves its own key to prevent.
    """
    cfg = tmp_path / "a" / "cfg"
    cfg.mkdir(parents=True)
    _write_uris(cfg, "content://FROM_A", "fam")
    other = tmp_path / "b"
    other.mkdir()

    monkeypatch.chdir(tmp_path / "a")  # restored by monkeypatch — a bare
    # os.chdir would leak the CWD into every later test in the session
    assert set(providers.load_content_uris(data_dir="cfg")) == {"content://FROM_A"}
    frozen = next(iter(datadir._RESOLVED.values()))
    assert frozen.is_absolute(), f"a relative decision was frozen: {frozen}"

    monkeypatch.chdir(other)
    assert set(providers.load_content_uris(data_dir=str(cfg))) == {"content://FROM_A"}
    # …and both spellings are ONE decision, which is what the resolved key buys
    assert len(datadir._RESOLVED) == 1


def test_a_bundled_fallback_is_not_frozen(tmp_path):
    """Only the OVERRIDE direction is frozen — the asymmetry is the point (#43).

    Freezing the bundled fallback too would convert a TRANSIENT wrong answer into a
    PERMANENT one: a single request landing inside a deploy's ``rm`` window pins
    bundled data for the life of the process, which is the very failure #43 reports
    made sticky. An adversarial review constructed exactly that against the first
    cut (five subsequent requests served bundled data while the override sat on
    disk, no error), and the first cut's own test asserted that behaviour as
    intended — so this REPLACES that assertion.
    """
    assert "content://sms" in providers.load_content_uris(data_dir=str(tmp_path))
    _write_uris(tmp_path, "content://appeared", "fam")
    assert set(providers.load_content_uris(data_dir=str(tmp_path))) == {
        "content://appeared"
    }, "a fallback must self-heal without clear_data_caches()"


@pytest.mark.parametrize("spelling", ["arg", "env"])
def test_the_freeze_works_through_both_spellings(tmp_path, monkeypatch, spelling):
    """`$DEXLLM_DATA_DIR` is the form that reaches the MCP and HTTP servers.

    So it is the long-running process #43 is FOR — yet every other freeze test uses
    `data_dir=`, and a reviewer's mutant that disabled the freeze for the env
    spelling alone passed the whole suite.
    """
    _write_uris(tmp_path, "content://frozen", "fam")
    if spelling == "arg":
        call = lambda: providers.load_content_uris(data_dir=str(tmp_path))  # noqa: E731
    else:
        monkeypatch.setenv(datadir.ENV_VAR, str(tmp_path))
        call = providers.load_content_uris

    assert set(call()) == {"content://frozen"}
    assert datadir._RESOLVED, f"nothing was frozen for the {spelling} spelling"
    (tmp_path / "content_uris.json").unlink()
    assert set(call()) == {"content://frozen"}, "the freeze must not depend on how"


def test_the_memo_hit_raise_names_the_configured_path_and_spelling(
    tmp_path, monkeypatch
):
    """A frozen decision holds the RESOLVED TARGET, which is not what to blame.

    For a symlinked override that target is inside the release directory, so a
    message built from it names neither the file nor the directory the operator
    configured — and #43's whole point is that a misconfiguration says WHERE. The
    cold path was parametrised over both spellings; the memo-hit path had no such
    coverage, and a reviewer's mutant hard-coding `data_dir=` there survived.
    """
    real = tmp_path / "rel"
    real.mkdir()
    _write_uris(real, "content://linked", "fam")
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    (cfg / "content_uris.json").symlink_to(real / "content_uris.json")

    monkeypatch.setenv(datadir.ENV_VAR, str(cfg))
    assert set(providers.load_content_uris()) == {"content://linked"}
    (real / "content_uris.json").unlink()
    os.mkfifo(real / "content_uris.json")  # the frozen target turns unreadable

    # bounded: if the kind re-check ever stops firing, this reads the FIFO
    got = _bounded(providers.load_content_uris)
    assert isinstance(got, OSError) and "is not a regular file" in str(got)
    assert str(cfg / "content_uris.json") in str(
        got
    ), "the message must name the CONFIGURED override, not the release target"
    assert "$" + datadir.ENV_VAR in str(got)


def test_an_empty_data_dir_is_unset_for_a_str_but_pathlib_eats_the_empty_path(
    tmp_path, monkeypatch
):
    """Pins a LIMITATION, not a fix — and where the boundary of it lies.

    A reviewer found that `data_dir=Path("")` means the process CWD, and proposed
    normalising with `os.fspath`. It does not help and cannot: pathlib collapses
    `Path("")` to `Path(".")` at CONSTRUCTION, so by the time `resolve_data_file`
    is called there is nothing left to distinguish it from a deliberate
    `Path(".")`, which is a legitimate request. The information is lost in the
    CALLER's own expression.

    So the rule is documented instead of enforced: pass `None` or `""` for an unset
    value. This test states the reality in both directions so the limitation is a
    decision on record rather than a surprise — and it would fail if the `str`
    spelling ever regressed to meaning the CWD.
    """
    from pathlib import Path

    _write_uris(tmp_path, "content://CWD_LEAK", "fam")
    monkeypatch.chdir(tmp_path)

    assert "content://sms" in providers.load_content_uris(data_dir="")
    assert Path("") == Path("."), "the premise: pathlib normalises before we see it"
    assert set(providers.load_content_uris(data_dir=Path(""))) == {
        "content://CWD_LEAK"
    }, "documented: a Path('') is a real request for the CWD, not an unset value"
    # …and an ordinary PathLike works, so nothing else was narrowed
    assert set(providers.load_content_uris(data_dir=Path(tmp_path))) == {
        "content://CWD_LEAK"
    }


def test_an_unreadable_override_directory_is_the_os_error_not_a_silent_fallback(
    tmp_path,
):
    """`except FileNotFoundError` must not widen to `except OSError` (issue #43).

    The pre-fix `is_file()` swallowed EACCES and fell back to bundled — a container
    that changes UID between deploys then runs the analysis on data the operator did
    not configure, with no error. Narrowing the catch fixed it; nothing guarded it,
    and a reviewer's `except OSError` mutant restored the silent fallback while the
    whole suite stayed green.
    """
    if os.geteuid() == 0:
        pytest.skip("running as root bypasses the permission bits this asserts")
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    _write_uris(cfg, "content://unreachable", "fam")
    cfg.chmod(0o600)  # readable, NOT traversable: stat inside it fails EACCES
    try:
        with pytest.raises(PermissionError):
            providers.load_content_uris(data_dir=str(cfg))
    finally:
        cfg.chmod(0o755)  # …or tmp_path cleanup fails


def test_a_frozen_override_survives_a_rm_and_a_relink(tmp_path):
    """The stability half, through a symlink — the blue/green deploy shape.

    The memo stores the RESOLVED target, so repointing the link does not re-decide;
    an earlier cut stored the link path, which decoupled it from the content cache
    key (that resolves the target) and served the NEW release immediately, silently
    contradicting the stability this fix promises.
    """
    releases = tmp_path / "rel"
    (releases / "v1").mkdir(parents=True)
    (releases / "v2").mkdir(parents=True)
    _write_uris(releases / "v1", "content://v1", "fam")
    _write_uris(releases / "v2", "content://v2", "fam")
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    link = cfg / "content_uris.json"
    link.symlink_to(releases / "v1" / "content_uris.json")

    assert set(providers.load_content_uris(data_dir=str(cfg))) == {"content://v1"}
    # …and what is frozen is the TARGET, not the link. Freezing the link is what a
    # non-strict `resolve()` produces if the entry vanishes mid-decision, and it
    # silently un-does the stability below — a delta review constructed exactly
    # that, so assert the mechanism and not only its effect.
    frozen = next(iter(datadir._RESOLVED.values()))
    assert frozen == (releases / "v1" / "content_uris.json").resolve()
    assert not frozen.is_symlink(), f"the LINK was frozen, not its target: {frozen}"

    link.unlink()
    link.symlink_to(releases / "v2" / "content_uris.json")
    assert set(providers.load_content_uris(data_dir=str(cfg))) == {
        "content://v1"
    }, "a relink must not switch datasets mid-run"
    datadir.clear_data_caches()
    assert set(providers.load_content_uris(data_dir=str(cfg))) == {"content://v2"}


def test_a_decision_is_not_frozen_from_an_unverified_resolve(tmp_path, monkeypatch):
    """`Path.resolve()` is NON-STRICT, so it can hand back the path it was given.

    If the entry vanishes between the usability check and the resolve, resolve()
    returns the SPELLED path — and freezing a LINK re-opens the relink flip this
    fix closes, permanently for the process. A delta review hit it naturally
    (8,751 of 20,000 resolutions under a relinking writer); this forces the same
    window deterministically by removing the link inside the check, so the guard
    does not depend on winning a race.
    """
    releases = tmp_path / "rel"
    releases.mkdir()
    _write_uris(releases, "content://target", "fam")
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    link = cfg / "content_uris.json"
    link.symlink_to(releases / "content_uris.json")

    real = datadir._override_is_usable

    def vanishing(candidate, source, shown):
        ok = real(candidate, source, shown)
        if ok and candidate.is_symlink():
            candidate.unlink()  # the window: gone before resolve() runs
        return ok

    monkeypatch.setattr(datadir, "_override_is_usable", vanishing)
    datadir.resolve_data_file("content_uris.json", data_dir=str(cfg))
    monkeypatch.undo()

    assert not datadir._RESOLVED, (
        "an unverified resolve() was frozen: "
        f"{ {str(k): str(v) for k, v in datadir._RESOLVED.items()} }"
    )
    # …and the next call simply re-decides, which is what makes a miss recoverable
    link.symlink_to(releases / "content_uris.json")
    assert set(providers.load_content_uris(data_dir=str(cfg))) == {"content://target"}
    frozen = next(iter(datadir._RESOLVED.values()))
    assert frozen == (releases / "content_uris.json").resolve()


def test_a_frozen_override_that_is_deleted_self_heals_once_nothing_is_cached(tmp_path):
    """The two bounded dicts have independent lifetimes — reconcile the states.

    A frozen decision serves stability only while its CONTENT is still cached. Once
    both are gone the decision has nothing left to serve, and handing the path back
    anyway turns a deliberate `rm` into a permanent FileNotFoundError for that
    directory — decided by invisible cache pressure, and the same stickiness the
    bundled direction is deliberately spared. So the frozen entry is dropped and the
    call re-decides.
    """
    _write_uris(tmp_path, "content://frozen", "fam")
    assert set(providers.load_content_uris(data_dir=str(tmp_path))) == {
        "content://frozen"
    }
    (tmp_path / "content_uris.json").unlink()
    # content still cached -> the freeze holds (the stability guarantee)
    assert set(providers.load_content_uris(data_dir=str(tmp_path))) == {
        "content://frozen"
    }
    # …now simulate the content entry being evicted under cache pressure while the
    # memo survives; the two are bounded independently, so this state is reachable.
    datadir._CACHE.clear()
    assert "content://sms" in providers.load_content_uris(
        data_dir=str(tmp_path)
    ), "with nothing left to serve it must fall back, not raise"
    assert not datadir._RESOLVED, "…and the stale decision is dropped, not retried"


def test_a_frozen_path_replaced_by_a_fifo_raises_instead_of_blocking(tmp_path):
    """A frozen decision is not re-decided, but its KIND is re-checked (#43).

    Reading a FIFO with no writer blocks forever — an unbounded hang in a server
    thread, the failure class this repo already treats as first-class (safe.py, the
    emit-walk cap). Freezing without the re-check hands the loader exactly that
    path. ABSENT is deliberately NOT re-decided: that is the stability above.

    Run through ``_bounded`` because the regression this names is a HANG.
    """
    _write_uris(tmp_path, "content://real", "fam")
    assert set(providers.load_content_uris(data_dir=str(tmp_path))) == {
        "content://real"
    }
    entry = tmp_path / "content_uris.json"
    entry.unlink()
    os.mkfifo(entry)

    got = _bounded(
        datadir.resolve_data_file, "content_uris.json", data_dir=str(tmp_path)
    )
    assert isinstance(got, OSError), f"expected a raise, got {got!r}"
    assert "is not a regular file" in str(got)


def _bounded(fn, *args, **kwargs):
    """Run ``fn`` on a worker and return its value, or the OSError it raised.

    Fails the test if it does not finish. Every path that can hand the loader a
    FIFO is exercised through this: reading one with no writer blocks forever, and
    an in-line call would hang the suite silently instead of turning it red (there
    is no per-test timeout configured). Verified necessary — a mutant that accepts
    any symlink with an existing target made an in-line version hang rather than
    fail.
    """
    import threading

    box: list = []

    def run():
        try:
            box.append(fn(*args, **kwargs))
        except BaseException as exc:  # noqa: BLE001 — reported to the caller
            box.append(exc)

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(timeout=10)
    assert not worker.is_alive(), f"{getattr(fn, '__name__', fn)} BLOCKED"
    return box[0]


def test_a_concurrent_rewrite_never_raises_about_a_good_file(tmp_path):
    """The deploy sequence itself must not produce a spurious raise (issue #43).

    The first cut tested ``is_file()`` and then ``os.path.lexists()`` — two
    syscalls with a gap — so a request landing between a deploy's ``rm`` and its
    ``cp`` saw "absent" then "present" and raised about a perfectly good file. An
    adversarial review measured 13,435 such raises in 12 s. ``stat`` decides the
    working shapes alone now, so the correct count is exactly zero.

    Scoped to a REGULAR-file override, which is what this closes. A symlinked one
    whose TARGET is rewritten non-atomically still raises transiently — documented
    in `_override_is_usable` as indistinguishable from a dangling link — so
    asserting zero there would be asserting something false.

    Carries its own non-vacuity floor: `spurious == 0` is also what a writer that
    never got scheduled produces, so count the iterations that actually landed in
    the window (the resolver saw no file and returned the bundled path).
    """
    import threading

    _write_uris(tmp_path, "content://churn", "fam")
    entry = tmp_path / "content_uris.json"
    payload = entry.read_text()
    stop = threading.Event()

    def churn():
        while not stop.is_set():
            try:
                entry.unlink()
                entry.write_text(payload)
            except OSError:  # noqa: PERF203 — the race is the point
                pass

    writer = threading.Thread(target=churn, daemon=True)
    writer.start()
    try:
        spurious = in_window = 0
        for _ in range(20000):
            try:
                got = datadir.resolve_data_file(
                    "content_uris.json", data_dir=str(tmp_path)
                )
                in_window += got.parent != tmp_path
            except OSError:
                spurious += 1
            datadir.clear_data_caches()  # re-decide every iteration, not memo-hit
    finally:
        stop.set()
        writer.join(timeout=5)
    assert spurious == 0, f"{spurious} raises about a file that was being rewritten"
    assert in_window, "the writer never won a race — this run proved nothing"


def test_the_resolution_memo_is_bounded_and_keeps_the_newest(tmp_path):
    """#43 added a second caller-path-keyed dict, so it takes the same bound.

    The content cache is bounded for a measured reason (300 dirs -> +44 MB, and
    this repo has shipped that failure once at 1.6 GB). A per-request `data_dir`
    grows the memo exactly as fast.

    A ceiling ALONE is not enough, and a reviewer proved it: a "refuse new entries
    when full" policy and a LIFO eviction both satisfy ``<= _MAX_CACHE_ENTRIES``
    while silently disabling the freeze for everything after the first 16. So this
    pins WHICH entries survive, in both directions — the newest is kept (kills
    refuse-when-full) and the oldest is gone (kills LIFO, which drops the entry it
    just used and would keep the first 16 forever).
    """
    dirs = []
    for i in range(datadir._MAX_CACHE_ENTRIES * 3):
        d = tmp_path / f"d{i}"
        d.mkdir()
        _write_uris(d, f"content://n{i}", "fam")
        assert set(providers.load_content_uris(data_dir=str(d))) == {f"content://n{i}"}
        dirs.append(d)

    def key(d):
        return (str(d.resolve()), "content_uris.json")

    assert len(datadir._RESOLVED) <= datadir._MAX_CACHE_ENTRIES
    assert datadir._RESOLVED, "…and it is not merely empty"
    assert key(dirs[-1]) in datadir._RESOLVED, "the newest decision must be kept"
    assert key(dirs[0]) not in datadir._RESOLVED, "eviction must drop the OLDEST"


def test_clear_data_caches_clears_the_frozen_decisions_too(tmp_path):
    """The reset covers both structures — otherwise a re-read goes through a
    decision the caller just asked to forget."""
    _write_uris(tmp_path, "content://first", "fam")
    assert set(providers.load_content_uris(data_dir=str(tmp_path))) == {
        "content://first"
    }
    assert datadir._RESOLVED, "the decision must actually be memoised"

    datadir.clear_data_caches()
    assert not datadir._RESOLVED and not datadir._CACHE

    # …and a replaced file is then re-read, which is what the reset is for
    _write_uris(tmp_path, "content://second", "fam")
    assert set(providers.load_content_uris(data_dir=str(tmp_path))) == {
        "content://second"
    }


def test_clear_data_caches_re_reads_an_edited_file(tmp_path):
    """The documented reset for in-place edits during a long-running process."""
    _write_uris(tmp_path, "content://v1", "one")
    assert set(providers.load_content_uris(data_dir=str(tmp_path))) == {"content://v1"}

    _write_uris(tmp_path, "content://v2", "two")
    assert set(providers.load_content_uris(data_dir=str(tmp_path))) == {
        "content://v1"
    }, "same path is cached — this is the documented behaviour, not a bug"

    datadir.clear_data_caches()
    assert set(providers.load_content_uris(data_dir=str(tmp_path))) == {"content://v2"}
