"""Schema and classification guards for the provider-URI dataset (issue #31).

``data/content_uris.json`` tags each ``content://`` URI with a ``family``, and
``detect_content_providers`` returns that string verbatim as the grouping key. The
``uri`` and ``classes`` fields are mechanical AOSP extraction (they match the
upstream CSVs exactly), but ``family`` is a HAND label with no generator — so
nothing but a test keeps it honest, and 26 of 209 entries had drifted into the
catch-all ``provider`` bucket.

Six of those 26 were not gaps but MISCLASSIFICATIONS: their own ``classes`` name a
contract an existing family already owns. That is the property
:func:`test_no_provider_entry_names_a_contract_another_family_owns` states, and it
is what the corpus a/b cannot see — none of the six URIs is referenced by any
bundled APK, so ``detect_content_providers`` is byte-identical over the whole
corpus and only the dataset moves.

The remaining 20 ``provider`` entries are genuine gaps needing NEW families
(blockednumber / bluetooth / simphonebook / timezone / voicemail / userdictionary /
hbpcd) and stay open on #31; the invariant below is true for them because nothing
else claims their contracts.

Note that ``family`` is NOT derivable from the outer contract alone —
``android.provider.Telephony.*`` splits three ways (``sms`` for Mms/Sms/MmsSms,
``telephony`` for Carriers/SimInfo, and the CellBroadcasts/ServiceStateTable/
SatelliteDatagrams set corrected here). So the invariant asserts only that such an
entry is not left UNCLASSIFIED, never which family it lands in.

These are dataset-only guards: they need no APK and run in CI without a corpus.
"""

import collections
import json
from pathlib import Path

DATASET = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "dexllm"
    / "data"
    / "content_uris.json"
)

# The closed `family` vocabulary, PINNED so that adding one is a conscious edit
# rather than a typo that silently splits a bucket in two. `provider` is the
# catch-all #31 is retiring — it is still listed because 20 entries legitimately
# await new families; when Tier B lands it should leave this set.
FAMILY_VOCABULARY = {
    "browser",
    "calendar",
    "calllog",
    "contacts",
    "media",
    "provider",
    "settings",
    "sms",
    "telephony",
}

# The six Tier A corrections, pinned individually. The invariant below states the
# PROPERTY; this states the RESOLUTION, which the property deliberately cannot
# (see the module docstring on Telephony's three-way split).
TIER_A_CORRECTIONS = {
    "content://call_composer_locations": "calllog",
    "content://cellbroadcast-legacy": "telephony",
    "content://cellbroadcasts": "telephony",
    "content://cellbroadcasts/history": "telephony",
    "content://satellite/incoming_datagrams": "telephony",
    "content://service-state/": "telephony",
}


def _dataset() -> dict:
    return json.loads(DATASET.read_bytes())


def _root_contract(cls: str) -> str:
    """The outer contract class: ``android.provider.CallLog.Locations`` -> ``CallLog``."""
    return cls.removeprefix("android.provider.").split(".")[0]


def _contract_owners(dataset: dict) -> dict[str, set[str]]:
    """Map each root contract to the set of families that claim it."""
    owners: dict[str, set[str]] = collections.defaultdict(set)
    for entry in dataset.values():
        for cls in entry["classes"]:
            owners[_root_contract(cls)].add(entry["family"])
    return owners


def test_dataset_shape():
    """Every entry carries a non-empty `classes` list and a vocabulary `family`.

    Non-discriminating by design — it must hold before and after the Tier A fix.
    It exists so a malformed refresh fails here rather than inside a cached loader.
    """
    dataset = _dataset()
    assert dataset, "dataset is empty"
    for uri, entry in dataset.items():
        assert uri.startswith("content://"), uri
        assert isinstance(entry["classes"], list) and entry["classes"], uri
        assert all(isinstance(c, str) and c for c in entry["classes"]), uri
        assert entry["family"] in FAMILY_VOCABULARY, (uri, entry["family"])


def test_no_provider_entry_names_a_contract_another_family_owns():
    """A `provider` entry whose own `classes` name a claimed contract is misfiled.

    This is the Tier A defect stated as a property: `provider` means "no family
    fits yet", so an entry naming a contract some family already owns is not an
    unclassified leftover but a wrong classification. FAILS against the pre-fix
    dataset with exactly the six entries in `TIER_A_CORRECTIONS`.

    Note for Tier B, which is INTENDED forcing rather than a trap: several of the
    20 remaining `provider` entries share a root contract (BlockedNumberContract,
    HbpcdLookup, TimeZoneRulesDataContract, VoicemailContract, UserDictionary), so
    classifying ONE member of such a group turns its siblings into violations and
    this test red. That is the point — a contract must not end up half-classified,
    which is how the current 26 accumulated.
    """
    dataset = _dataset()
    owners = _contract_owners(dataset)

    misfiled = {
        uri: cls
        for uri, entry in dataset.items()
        if entry["family"] == "provider"
        for cls in entry["classes"]
        if owners[_root_contract(cls)] - {"provider"}
    }
    assert not misfiled, (
        "these `provider` entries name a contract an existing family owns: "
        f"{misfiled}"
    )


def test_tier_a_corrections_are_pinned():
    """The six reclassified URIs keep their family across a dataset refresh.

    The upstream CSVs carry no `family` column, so a regenerated dataset drops
    every hand label — this is what makes the loss detectable.
    """
    dataset = _dataset()
    actual = {uri: dataset[uri]["family"] for uri in TIER_A_CORRECTIONS}
    assert actual == TIER_A_CORRECTIONS


def test_family_is_reachable_through_the_public_api():
    """`load_content_uris` serves the same families the file declares.

    Non-discriminating (must hold on both sides), but it is the only assertion
    here that goes through the module's cached loader rather than reading the file
    directly, so a loader that rewrote or filtered `family` could not hide.
    """
    from dexllm import providers

    served = providers.load_content_uris()
    on_disk = _dataset()
    assert {u: e["family"] for u, e in served.items()} == {
        u: e["family"] for u, e in on_disk.items()
    }
