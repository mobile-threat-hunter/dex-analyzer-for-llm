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
    assert tools.execute("capability_report", {}, _Dk())["catalog_version"] == "env-1"


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

    datadir.load_data_json("android_api_map.json", data_dir=str(tmp_path))  # no validator
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
            json.dumps(
                {"version": "v", "entries": {"Lx;->y()V": {"categories": bad}}}
            )
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


def test_a_vanished_data_dir_fails_loudly_rather_than_serving_a_stale_cache(tmp_path):
    """Resolution runs BEFORE the cache lookup, deliberately.

    A config volume that unmounts must not be masked by what the process happened
    to load an hour ago — the two directions are stated here so the asymmetry with
    per-file fallback (a MISSING file inside a VALID directory falls back to
    bundled) is a documented decision rather than a surprise.
    """
    import shutil

    _write_uris(tmp_path, "content://vol", "volfam")
    assert set(providers.load_content_uris(data_dir=str(tmp_path))) == {"content://vol"}

    # the file alone disappears -> per-file fallback to bundled, no error
    (tmp_path / "content_uris.json").unlink()
    assert "content://sms" in providers.load_content_uris(data_dir=str(tmp_path))

    # the whole directory disappears -> loud, even though a copy is still cached
    shutil.rmtree(tmp_path)
    with pytest.raises(NotADirectoryError):
        providers.load_content_uris(data_dir=str(tmp_path))


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
