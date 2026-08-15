"""Schema and classification guards for the provider-URI dataset (issue #31).

``data/content_uris.json`` tags each ``content://`` URI with a ``family``, and
``detect_content_providers`` returns that string verbatim as the grouping key. The
``uri`` and ``classes`` fields are mechanical AOSP extraction (they match the
upstream CSVs exactly), but ``family`` is a HAND label with no generator — so
nothing but a test keeps it honest, and 26 of 209 entries had drifted into the
catch-all ``provider`` bucket.

Tier A took six of those: not gaps but MISCLASSIFICATIONS, their own ``classes``
naming a contract an existing family already owned. Tier B took the remaining 20,
which were genuine gaps, into flat new families (``voicemail`` /
``blockednumber`` / ``simphonebook`` / ``bluetooth`` / ``timezone`` /
``userdictionary``, plus HBPCD's seven numbering tables into ``telephony``).
``provider`` is now BANNED: it was never a family, and an entry carrying it reads
to a consumer as though the classification had succeeded.

The corpus cannot check any of this — the bundled APKs reference exactly ONE
provider URI and none of the reclassified ones, so ``detect_content_providers`` is
byte-identical over the whole corpus and only the dataset moves. These guards are
therefore the only thing standing between a refresh and a silent regression, which
is why they assert PROPERTIES (no unclassified entry; no contract split across
families) and not just a list of expected values.

Two limits worth stating, both learned from a review that constructed them:

* the ownership invariant forces siblings only when a root contract appears more
  than once. Three entries name a SINGLETON root (``BluetoothShare``,
  ``MmsFileProvider``, ``AvrcpCoverArtProvider``), so they are pinned
  individually in ``TIER_B_CORRECTIONS`` instead;
* ``family`` is NOT derivable from the outer contract alone —
  ``android.provider.Telephony.*`` splits three ways (``sms`` for Mms/Sms/MmsSms,
  ``telephony`` for Carriers/SimInfo, and the CellBroadcasts/ServiceStateTable/
  SatelliteDatagrams set) — and it follows the DATA, not the owning package: a
  Bluetooth MAP provider serving Telephony MMS parts is ``sms``, because that is
  where an analyst will look for it.

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
# rather than a typo that silently splits a bucket in two. `provider` LEFT this
# set in Tier B (#31): it was never a family, it was "unclassified", and at 20 of
# 209 it made a tenth of the dataset group under a label that tells a consumer
# nothing while `{"family": "provider"}` reads as though classification succeeded.
FAMILY_VOCABULARY = {
    "blockednumber",
    "bluetooth",
    "browser",
    "calendar",
    "calllog",
    "contacts",
    "media",
    "settings",
    "simphonebook",
    "sms",
    "telephony",
    "timezone",
    "userdictionary",
    "voicemail",
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


# The Tier B reclassification (#31), pinned like Tier A and for the same reason:
# the upstream CSVs carry no `family` column, so a regenerated dataset drops every
# hand label. One representative per group — the contract-ownership invariant
# below then forces the siblings, which is what stops a contract ending up
# half-classified (how the bucket accumulated in the first place).
#
# Families verified against the AOSP checkout, by the package the contract lives
# in: HbpcdLookup is `com.android.internal.telephony` (numbering tables), the
# three bluetooth providers are `com.android.bluetooth.*`, and the rest are
# `android.provider.*` contracts that simply had no family of their own.
TIER_B_CORRECTIONS = {
    "content://hbpcd_lookup": "telephony",
    "content://com.android.voicemail/voicemail": "voicemail",
    "content://com.android.blockednumber/blocked": "blockednumber",
    "content://com.android.simphonebook/elementary_files": "simphonebook",
    "content://com.android.timezone/operation": "timezone",
    "content://user_dictionary/words": "userdictionary",
    # The three former `com.android.bluetooth.*` entries are pinned INDIVIDUALLY,
    # because the one-per-group rule does not hold for them: each names a root
    # contract that appears exactly ONCE (`BluetoothShare`, `MmsFileProvider`,
    # `AvrcpCoverArtProvider`), so the ownership invariant below forces nothing
    # and a reviewer changed two of them to any family at all with the suite
    # still green. They are also the three whose classification is least obvious,
    # which is why they are the ones spelled out — the family follows the DATA,
    # not the owning package: MmsFileProvider serves Telephony MMS parts over
    # Bluetooth MAP (AOSP builds its Uri on `Mms.CONTENT_URI`), so an analyst
    # filtering `sms` must see it; AvrcpCoverArtProvider serves album art.
    "content://com.android.bluetooth.opp/btopp": "bluetooth",
    "content://com.android.bluetooth.map.MmsFileProvider": "sms",
    "content://com.android.bluetooth.avrcpcontroller.AvrcpCoverArtProvider": "media",
    # …and the entry the first cut MISSED by adding `simphonebook` without
    # sweeping the 189 rows it did not touch: the legacy SIM phonebook URI.
    "content://icc/adn": "simphonebook",
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


def test_no_entry_is_left_unclassified():
    """`provider` is banned outright (#31 Tier B).

    INVERTED from `test_no_provider_entry_names_a_contract_another_family_owns`,
    which asked the weaker question "is this leftover MISfiled" because a leftover
    was still legitimate. It no longer is: `provider` was never a family, it was
    "unclassified", and an entry carrying it reads to a consumer as though the
    classification succeeded. The old test cannot state this — it was vacuous the
    moment the bucket emptied, since it only ever looked at `provider` entries.
    """
    stragglers = {
        u: e["classes"] for u, e in _dataset().items() if e["family"] == "provider"
    }
    assert not stragglers, (
        f"{len(stragglers)} entries are still unclassified: {stragglers}. "
        "`provider` is not a family — give them one, or add an honest name for "
        "'we do not know' to FAMILY_VOCABULARY as a conscious edit."
    )


# Root contracts that legitimately span families, with the exact set they span.
# A contract is normally owned by ONE family, and the test below uses that to
# force siblings — but two AOSP contracts really are multi-domain, so they are
# declared rather than allowed to weaken the rule for everything else. Declaring
# the SET (not just the name) means a THIRD family creeping into one of them is
# still caught.
MULTI_FAMILY_CONTRACTS = {
    "Telephony": {"sms", "telephony"},  # Telephony.{Sms,Mms} vs .Carriers/.CarrierId/…
    "BrowserContract": {"browser", "settings"},  # BrowserContract.Settings
}


def test_a_contract_is_owned_by_one_family_unless_declared():
    """No root contract may be split across families by accident.

    GENERALISED at Tier B. The Tier A version asked this only of `provider`
    entries — "does a REAL family already own this contract" — so it could not see
    two real families splitting one, and with `provider` gone that scope makes it
    vacuous. Half-classification is how the bucket accumulated: a group like
    `VoicemailContract{,.Status}` gets one member labelled and the rest left
    behind, which is exactly what this now forces.

    A first cut asserted single ownership outright and was WRONG: `Telephony`
    (`.Sms`/`.Mms` vs `.Carriers`) and `BrowserContract` (`.Settings`) genuinely
    span two domains. They are declared above with their exact family sets, so the
    rule keeps its force everywhere else and a third family joining one of them is
    still a failure.
    """
    bad = {}
    for contract, fams in _contract_owners(_dataset()).items():
        allowed = MULTI_FAMILY_CONTRACTS.get(contract)
        if allowed is None:
            if len(fams) > 1:
                bad[contract] = sorted(fams)
        elif fams - allowed:
            # SUBSET, not equality. Exact equality also rejected NARROWING a
            # declared exception — merging `BrowserContract.Settings` back into
            # `browser` failed with the message "contracts split across families",
            # i.e. the guard blocked the removal of a split and blamed it for
            # causing one. Only a family JOINING an exception is a defect; a
            # shrinking one is caught by the staleness check below instead.
            bad[contract] = (
                f"{sorted(fams - allowed)} joined declared {sorted(allowed)}"
            )
    assert not bad, f"contracts split across families: {bad}"

    # …and every declared exception is still real, so a stale entry cannot sit
    # here quietly widening the rule after the dataset stops needing it.
    owners = _contract_owners(_dataset())
    for contract in MULTI_FAMILY_CONTRACTS:
        assert len(owners.get(contract, set())) > 1, (
            f"{contract} no longer spans families — drop it from "
            f"MULTI_FAMILY_CONTRACTS instead of leaving the rule weakened"
        )


def test_tier_b_corrections_are_pinned():
    """The Tier B reclassification survives a dataset refresh.

    One representative per group; the ownership invariant above forces the rest,
    which is the division of labour Tier A already used.
    """
    dataset = _dataset()
    actual = {uri: dataset[uri]["family"] for uri in TIER_B_CORRECTIONS}
    assert actual == TIER_B_CORRECTIONS


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
