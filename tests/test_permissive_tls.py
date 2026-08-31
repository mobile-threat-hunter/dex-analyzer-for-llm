"""dexllm#53 — permissive-TLS detection, and the halves that can hide it.

Every behavioural case runs on ``tests/data/permissive-tls.dex``, which is
COMMITTED, so they hold in the corpus-less CI leg and under any
``$DEXLLM_TEST_APK`` narrowing. That fixture is the only carrier in reach of a
``HostnameVerifier`` implementor at all (the gitignored corpus has 0), and it is
AUTHORED, so its shapes are chosen rather than found: two permissive components,
two that genuinely check — without which "report every implementor" passes as a
working detector — a class implementing BOTH interfaces, and a verifier with a
non-constructor method and TWO constructors whose callers do not arrive sorted.
The last three exist because a correctness review found four load-bearing lines
whose mutants survived the whole file: the `<init>` filter, the caller dedupe, the
caller sort, and the row sort's second component.

The predicate is exercised on BOTH layers on purpose. ``classify_tls_method`` is
pure, so the shapes no dex in reach carries — a ``const/16``, a returned register
that is not the loaded one, an unreadable rendering — are testable without a dex;
and the end-to-end cases pin that the pure predicate is what the DexKit path
actually consults.
"""

from __future__ import annotations

import os

import pytest
from conftest import REPO_ROOT, corpus_is_narrowed, require_corpus_shape

import dexllm
from dexllm.tls_trust import (
    _COMPONENTS,
    NOT_PROVEN,
    PERMISSIVE,
    classify_tls_method,
    detect_permissive_tls,
)

FIXTURE = REPO_ROOT / "tests" / "data" / "permissive-tls.dex"

# The two platform interfaces, pinned as LITERALS. A guard parametrised over
# _COMPONENTS cannot catch an EDIT of _COMPONENTS — retargeting the detector at
# an interface nothing implements would leave every other case here green.
_EXPECTED_COMPONENTS = {
    "hostname_verifier": (
        "Ljavax/net/ssl/HostnameVerifier;",
        "verify",
        "(Ljava/lang/String;Ljavax/net/ssl/SSLSession;)Z",
    ),
    "trust_manager": (
        "Ljavax/net/ssl/X509TrustManager;",
        "checkServerTrusted",
        "([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V",
    ),
}

_VERIFY = "verify(Ljava/lang/String;Ljavax/net/ssl/SSLSession;)Z"
_CHECK = "checkServerTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V"


@pytest.fixture(scope="module")
def fdk():
    """The committed fixture, loaded."""
    if not FIXTURE.is_file():  # pragma: no cover - the file is committed
        pytest.skip("tests/data/permissive-tls.dex missing")
    return dexllm.DexKit(str(FIXTURE))


@pytest.fixture(scope="module")
def rows(fdk):
    """Row list, and a by-(class, kind) index — a class may yield TWO rows."""
    rs = detect_permissive_tls(fdk)
    return rs, {(r["class_descriptor"], r["kind"]): r for r in rs}


# ── the table itself ─────────────────────────────────────────────────────────


def test_the_component_table_is_the_two_platform_interfaces():
    """Both directions: a retargeted entry AND a dropped one fail."""
    assert _COMPONENTS == _EXPECTED_COMPONENTS


def test_check_client_trusted_is_deliberately_not_checked():
    """An empty checkClientTrusted is what a CLIENT is supposed to have.

    Checking it would report every well-behaved app, so its absence from the
    table is a decision — pinned here rather than left to the docstring. The
    fixture's `CheckingTrust` has an empty one, so a build that checked it would
    report a component the detector must decline.
    """
    assert not any(
        member == "checkClientTrusted" for _, member, _ in _COMPONENTS.values()
    )


# ── the end-to-end verdicts ──────────────────────────────────────────────────


def test_the_permissive_verifier_is_proven(rows):
    r = rows[1][("LPermissiveVerifier;", "hostname_verifier")]
    assert r["verdict"] == PERMISSIVE
    assert r["interface_descriptor"] == "Ljavax/net/ssl/HostnameVerifier;"
    assert r["method_descriptor"] == f"LPermissiveVerifier;->{_VERIFY}"
    assert r["reason"] == "verify returns the constant true"


def test_the_permissive_trust_manager_is_proven(rows):
    r = rows[1][("LPermissiveTrust;", "trust_manager")]
    assert r["verdict"] == PERMISSIVE
    assert r["interface_descriptor"] == "Ljavax/net/ssl/X509TrustManager;"
    assert r["method_descriptor"] == f"LPermissiveTrust;->{_CHECK}"
    assert r["reason"] == "checkServerTrusted body is empty, so it cannot throw"


@pytest.mark.parametrize(
    "key",
    [("LCheckingVerifier;", "hostname_verifier"), ("LCheckingTrust;", "trust_manager")],
    ids=["verifier", "trust_manager"],
)
def test_a_component_that_checks_is_not_proven(rows, key):
    """The negative controls — without these, "report every implementor" passes."""
    assert rows[1][key]["verdict"] == NOT_PROVEN


def test_every_implementor_is_reported_whatever_its_verdict(rows):
    """A not_proven component is still a reported fact: the app carries one."""
    assert {r["class_descriptor"] for r in rows[0]} == {
        "LBaseTrust;",
        "LCheckingTrust;",
        "LCheckingVerifier;",
        "LDuckTrust;",
        "LExtTrust;",
        "LInheritTrust;",
        "LPermissiveBoth;",
        "LPermissiveTrust;",
        "LPermissiveVerifier;",
    }


def test_a_class_implementing_both_interfaces_yields_a_row_per_kind(rows):
    """The ONLY shape that exercises the row sort's second component.

    With one row per class, `sorted` is stable and a key of `class_descriptor`
    alone is indistinguishable from the documented `(class, method)` — a mutant
    dropping the second component survived the whole file until this class
    existed.
    """
    both = [r for r in rows[0] if r["class_descriptor"] == "LPermissiveBoth;"]
    assert [(r["kind"], r["verdict"]) for r in both] == [
        ("trust_manager", PERMISSIVE),
        ("hostname_verifier", PERMISSIVE),
    ]
    assert [r["method_descriptor"] for r in both] == [
        f"LPermissiveBoth;->{_CHECK}",
        f"LPermissiveBoth;->{_VERIFY}",
    ]


def test_rows_are_sorted_by_class_then_method(fdk):
    got = detect_permissive_tls(fdk)
    assert got == sorted(
        got, key=lambda r: (r["class_descriptor"], r["method_descriptor"])
    )


def test_a_class_declared_in_two_dexes_is_reported_once(fdk):
    """A descriptor can be DECLARED more than once, and the report is per class.

    `find_classes_implementing` answers per DECLARATION, so a multidex app — or
    any packer session, where the dump and the original both carry the class —
    would otherwise report N identical rows for one component and the MCP `count`
    would say N.
    """
    twice = dexllm.DexKit([str(FIXTURE), str(FIXTURE)])
    assert twice.dex_count() == 2
    # the premise: the raw search answers per DECLARATION — 3 implementors x 2 dexes
    assert (
        len(twice.find_classes_implementing("Ljavax/net/ssl/X509TrustManager;")) == 14
    )
    assert [
        r["class_descriptor"] for r in detect_permissive_tls(twice, with_xref=False)
    ] == [r["class_descriptor"] for r in detect_permissive_tls(fdk, with_xref=False)]


def test_the_body_judged_is_the_first_wins_one(tmp_path):
    """Which declaration is judged, pinned — it is the library-wide resolution.

    `render_method_smali` resolves a descriptor first-wins, so in a session where
    two dexes declare the class the FIRST source decides the verdict. That is what
    `add_dumped_dexes(prefer=True)` is for: it puts the dump first, so the
    unpacked body is the one judged. Pinned in both directions, because a reader
    otherwise cannot tell a deliberate resolution from an accident.
    """
    blunted = tmp_path / "blunted.dex"
    raw = bytearray(FIXTURE.read_bytes())
    # `const/4 v1,#1 ; return v1` -> `const/4 v1,#0 ; return v1`, in place: one
    # nibble, so every offset and section size is untouched and nothing but the
    # intended operand can be what changed. EVERY such body is patched — which
    # class each occurrence belongs to is a layout fact, not the subject.
    body, blunt = b"\x12\x11\x0f\x01", b"\x12\x01\x0f\x01"
    assert raw.count(body) >= 2, "the fixture no longer carries such a body"
    raw = bytearray(bytes(raw).replace(body, blunt))
    blunted.write_bytes(bytes(raw))
    assert dexllm.verify(str(blunted))[0]["valid"], "the craft must still load"
    assert (
        detect_permissive_tls(dexllm.DexKit(str(blunted)), with_xref=False)[-1][
            "verdict"
        ]
        == NOT_PROVEN
    ), "the craft did not blunt the verifier"

    def verdict(sources):
        rs = detect_permissive_tls(dexllm.DexKit(sources), with_xref=False)
        return next(
            r["verdict"] for r in rs if r["class_descriptor"] == "LPermissiveVerifier;"
        )

    assert verdict([str(FIXTURE), str(blunted)]) == PERMISSIVE
    assert verdict([str(blunted), str(FIXTURE)]) == NOT_PROVEN


# ── the construction xref ────────────────────────────────────────────────────


def test_constructed_in_names_only_the_constructing_methods(rows):
    """Three load-bearing lines at once, each of which had NO guard.

    The value must be the CONSTRUCTORS' callers, DEDUPLICATED and SORTED:

    * `LAInstaller;->poke(...)` calls the verifier's non-constructor `helper()`
      and constructs nothing, so dropping the `<init>` filter adds it;
    * `LInstaller;->touch()V` constructs it TWICE, so dropping the dedupe
      repeats it;
    * the per-constructor concatenation arrives as
      `[Installer.install, Installer.touch, Installer.touch, AInstaller.install]`,
      so dropping the sort leaves `AInstaller` last.
    """
    got = rows[1][("LPermissiveVerifier;", "hostname_verifier")]["constructed_in"]
    assert got == [
        "LAInstaller;->install()V",
        "LInstaller;->install()V",
        "LInstaller;->touch()V",
    ]


def test_the_premise_of_the_constructed_in_guard_holds(fdk):
    """Non-vacuity: the fixture must still offer all three distinctions.

    Each assertion here is a property of the FIXTURE, not of the code under test,
    so a rebuilt fixture that lost a shape fails loudly instead of turning the
    guard above into a tautology.
    """
    concat = [
        c.caller_descriptor
        for m in fdk.list_class_methods("LPermissiveVerifier;")
        if "-><init>(" in m
        for c in fdk.find_call_sites_to(m)
    ]
    assert len(concat) > len(set(concat)), "no duplicate caller to deduplicate"
    assert concat != sorted(set(concat)), "the concatenation is already sorted"
    non_ctor = {
        c.caller_descriptor
        for c in fdk.find_call_sites_to("LPermissiveVerifier;->helper()V")
    }
    assert non_ctor - set(concat), "no caller reaches a non-constructor ONLY"


def test_with_xref_false_leaves_constructed_in_empty(fdk):
    assert all(
        r["constructed_in"] == [] for r in detect_permissive_tls(fdk, with_xref=False)
    )


# ── the class-level rules ────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "cls,reason_fragment",
    [
        ("LDuckTrust;", "another overload"),
        ("LExtTrust;", "another overload"),
        ("LInheritTrust;", "extends LBaseTrust;"),
    ],
)
def test_a_duck_typed_overload_declines_the_verdict(fdk, rows, cls, reason_fragment):
    """The FALSE POSITIVE an adversarial review built from ordinary Java.

    Conscrypt's `Platform.checkServerTrusted` casts to `X509ExtendedTrustManager`
    when it can and otherwise DUCK-TYPES a 3-argument overload, reaching the
    2-argument method only when neither exists. So all three of these classes are
    CORRECT — one pins a hostname, two throw — and reporting them permissive is an
    accusation, not a finding.

    Each asserts that the 2-argument BODY is the permissive shape, so it is the
    class-level rule doing the work and not an accident of the body predicate.
    `LInheritTrust;` is the case only the superclass test can catch: it declares
    no sibling, and the overload Conscrypt would find lives on its base.
    """
    md = f"{cls}->{_CHECK}"
    assert classify_tls_method("trust_manager", fdk.render_method_smali(md)) == (
        PERMISSIVE,
        "checkServerTrusted body is empty, so it cannot throw",
    ), "the body is no longer the shape this case exists to override"
    row = rows[1][(cls, "trust_manager")]
    assert row["verdict"] == NOT_PROVEN
    assert reason_fragment in row["reason"]


def test_a_class_level_block_does_not_overwrite_a_body_reason(rows):
    """The block explains why a PERMISSIVE body was not enough — nothing else.

    `LBaseTrust;` is blocked (it declares a 3-argument sibling) AND its 2-argument
    method has no body at all, so both reasons apply. The body's is the specific
    one, and `reason` is the field that makes a row actionable; applying the block
    unconditionally would replace it and survived the file until this case.
    """
    row = rows[1][("LBaseTrust;", "trust_manager")]
    assert row["verdict"] == NOT_PROVEN
    assert row["reason"] == "the method has no instructions"


def test_a_sub_interface_is_not_reported_as_a_component(rows):
    """An interface is a TYPE, not a component.

    `SubVerifier` extends the platform interface (the shape the legacy Apache
    `X509HostnameVerifier` has), so it DECLARES it and would otherwise be
    reported carrying `not_proven` / "the method has no instructions" — a row
    that reads as "we looked and found nothing" while standing in for the
    implementor that was never examined.
    """
    assert "LSubVerifier;" not in {r["class_descriptor"] for r in rows[0]}


def test_a_sub_interface_implementor_is_the_documented_bound(fdk, rows):
    """Pinned so the bound is a decision, not an unnoticed hole.

    `SubAllowAll`'s body is EXACTLY the shape the detector proves, and it is
    invisible because it declares the sub-interface rather than the platform one.
    """
    assert classify_tls_method(
        "hostname_verifier", fdk.render_method_smali(f"LSubAllowAll;->{_VERIFY}")
    ) == (PERMISSIVE, "verify returns the constant true")
    assert "LSubAllowAll;" not in {r["class_descriptor"] for r in rows[0]}


# ── the issue, stated as a test ──────────────────────────────────────────────


def test_the_detector_answers_what_the_capability_report_cannot(fdk, rows):
    """dexllm#52 says the app supplies its own trust; #53 says it accepts everything.

    Both facts on ONE dex: `CUSTOM_TLS_TRUST` counts the four platform install
    calls, and every one of them names a FRAMEWORK member — none of them can say
    what the installed objects decide.
    """
    cap = dexllm.summarize_capabilities(fdk)
    assert cap.categories.get("CUSTOM_TLS_TRUST") == 4
    assert {u.api_descriptor for u in cap.api_usages} == {
        "Ljavax/net/ssl/HttpsURLConnection;->setDefaultHostnameVerifier"
        "(Ljavax/net/ssl/HostnameVerifier;)V",
        "Ljavax/net/ssl/SSLContext;->init([Ljavax/net/ssl/KeyManager;"
        "[Ljavax/net/ssl/TrustManager;Ljava/security/SecureRandom;)V",
    }
    assert sorted(
        {r["class_descriptor"] for r in rows[0] if r["verdict"] == PERMISSIVE}
    ) == ["LPermissiveBoth;", "LPermissiveTrust;", "LPermissiveVerifier;"]


# ── the rendering this module parses ─────────────────────────────────────────


def test_the_smali_rendering_is_the_one_the_parser_expects(fdk):
    """Pinned as a LITERAL, because a format change is otherwise SILENT.

    `_body_instructions` returns None on a line it cannot read, and the caller
    turns that into `not_proven` — so a renderer change would empty every verdict
    while every other assertion about "not proven" still passed.
    """
    assert fdk.render_method_smali(f"LPermissiveVerifier;->{_VERIFY}") == (
        f"LPermissiveVerifier;->{_VERIFY}\n"
        "    .registers 3\n"
        "    0x0: const/4 v1, #1\n"
        "    0x2: return v1\n"
    )
    assert fdk.render_method_smali(f"LPermissiveTrust;->{_CHECK}") == (
        f"LPermissiveTrust;->{_CHECK}\n" "    .registers 3\n" "    0x0: return-void\n"
    )


# ── the pure predicate ───────────────────────────────────────────────────────


def _verify_body(*insns: str) -> str:
    lines = [f"    0x{i * 2:x}: {t}" for i, t in enumerate(insns)]
    return "M;->verify()Z\n    .registers 3\n" + "".join(f"{ln}\n" for ln in lines)


@pytest.mark.parametrize("const", ["const/4 v1, #1", "const/16 v1, #1", "const v1, #1"])
def test_every_const_form_that_can_load_one_is_accepted(const):
    """d8 emits const/4; an obfuscator or another compiler may not."""
    assert classify_tls_method(
        "hostname_verifier", _verify_body(const, "return v1")
    ) == (PERMISSIVE, "verify returns the constant true")


@pytest.mark.parametrize(
    "const", ["const/4 v1, #0", "const/4 v1, #2", "const/4 v1, #-1"]
)
def test_a_constant_other_than_one_is_not_permissive(const):
    verdict, _ = classify_tls_method(
        "hostname_verifier", _verify_body(const, "return v1")
    )
    assert verdict == NOT_PROVEN


def test_the_returned_register_must_be_the_loaded_one():
    """`const v1, #1; return v0` returns whatever v0 held — not a constant true."""
    verdict, _ = classify_tls_method(
        "hostname_verifier", _verify_body("const/4 v1, #1", "return v0")
    )
    assert verdict == NOT_PROVEN


@pytest.mark.parametrize(
    "insns",
    [
        ("const/4 v1, #1", "nop", "return v1"),
        ("const/4 v1, #1", "return v1", "nop"),
    ],
    ids=["interposed", "trailing"],
)
def test_a_longer_verify_body_is_not_proven(insns):
    """The predicate is whole-body EQUALITY, and `trailing` pins that CHOICE.

    A PREFIX match ("the first two instructions are const-1 then return") is
    OUTPUT-EQUIVALENT on any body a compiler emits — execution starts at offset 0,
    so what follows a `return` is dead — and it survived this file until this
    case existed. Equality is kept because it accounts for every instruction
    rather than resting on a reachability argument, and because a 2-instruction
    body is exactly 2 code units, so nothing can precede or follow it. The
    `trailing` case is therefore a deliberate conservatism, not a soundness
    property, and says so.
    """
    verdict, _ = classify_tls_method("hostname_verifier", _verify_body(*insns))
    assert verdict == NOT_PROVEN


def test_a_trust_manager_needs_exactly_return_void():
    assert classify_tls_method("trust_manager", _verify_body("return-void")) == (
        PERMISSIVE,
        "checkServerTrusted body is empty, so it cannot throw",
    )
    for extra in (("nop", "return-void"), ("return-void", "nop")):
        verdict, _ = classify_tls_method("trust_manager", _verify_body(*extra))
        assert verdict == NOT_PROVEN, extra


def test_a_one_instruction_verify_body_is_not_proven():
    """`while (true) {}` compiles to a single `goto` — ordinary, legal Java.

    A plausible relaxation (`len(body) <= 2`) then indexes `body[1]` and raises
    IndexError; nothing fed the predicate a 1-instruction body until this case.
    """
    assert classify_tls_method("hostname_verifier", _verify_body("goto +0")) == (
        NOT_PROVEN,
        "verify body is 1 instructions",
    )


@pytest.mark.parametrize(
    "line", ["    .catch Ljava/lang/Exception; {...}", "    # try start"]
)
def test_a_header_the_parser_does_not_KNOW_is_unreadable(line):
    """The fail-closed property is enforced by `_HEADER` being NARROW.

    Widening it to `\\..*` or `#.*` — a plausible edit the day the renderer grows
    baksmali-style try markers — makes the parser SKIP those lines, and a longer
    body then looks two instructions long. The unreadable-body case above starts
    with a letter, so it cannot see either widening.
    """
    body = "M;->verify()Z\n    .registers 3\n" + line + "\n    0x0: return-void\n"
    assert classify_tls_method("trust_manager", body) == (
        NOT_PROVEN,
        "body could not be read as instructions",
    )


def test_a_body_that_cannot_be_read_is_not_proven():
    """An unreadable rendering may only LOSE a finding, never invent one."""
    verdict, reason = classify_tls_method(
        "hostname_verifier",
        "M;->verify()Z\n    .registers 3\n    something entirely else\n",
    )
    assert (verdict, reason) == (NOT_PROVEN, "body could not be read as instructions")


@pytest.mark.parametrize(
    "smali",
    ["", "M;->verify()Z\n    # (no code item)\n"],
    ids=["absent", "abstract"],
)
def test_a_method_with_no_instructions_is_not_proven(smali):
    assert classify_tls_method("hostname_verifier", smali) == (
        NOT_PROVEN,
        "the method has no instructions",
    )


def test_an_unknown_kind_raises_instead_of_answering_not_proven():
    """A silent not_proven would read as "this app does not do this"."""
    with pytest.raises(ValueError, match="unknown TLS component kind"):
        classify_tls_method("nope", _verify_body("return-void"))


# ── the other layers ─────────────────────────────────────────────────────────


def test_the_sdk_model_carries_every_field():
    from dexllm.sdk import TlsTrustComponent, open_apk

    sdk = open_apk(str(FIXTURE))
    got = {(c.class_descriptor, c.kind): c for c in sdk.detect_permissive_tls()}
    assert all(isinstance(c, TlsTrustComponent) for c in got.values())
    p = got[("LPermissiveVerifier;", "hostname_verifier")]
    assert p.verdict == PERMISSIVE
    assert p.interface_descriptor == "Ljavax/net/ssl/HostnameVerifier;"
    assert p.method_descriptor == f"LPermissiveVerifier;->{_VERIFY}"
    assert p.reason == "verify returns the constant true"
    assert p.constructed_in == (
        "LAInstaller;->install()V",
        "LInstaller;->install()V",
        "LInstaller;->touch()V",
    )
    assert got[("LCheckingVerifier;", "hostname_verifier")].verdict == NOT_PROVEN


def test_the_adapter_forwards_with_xref():
    """An adapter that ACCEPTS the flag and drops it type-checks and lies."""
    from dexllm.sdk import open_apk

    sdk = open_apk(str(FIXTURE))
    assert all(
        c.constructed_in == () for c in sdk.detect_permissive_tls(with_xref=False)
    )
    assert any(c.constructed_in for c in sdk.detect_permissive_tls(with_xref=True))


def test_the_mcp_tool_reports_both_counts(fdk):
    """A zero headline beside a nonzero count is the legible "none proven"."""
    from dexllm import tools

    out = tools.execute("detect_permissive_tls", {}, fdk)
    assert out["count"] == 10
    assert out["permissive_count"] == 4
    assert sorted(
        {c["class_descriptor"] for c in out["components"] if c["verdict"] == PERMISSIVE}
    ) == ["LPermissiveBoth;", "LPermissiveTrust;", "LPermissiveVerifier;"]


def test_the_mcp_payload_carries_every_field(fdk):
    """Four of the seven were droppable with the suite green.

    `reason` is what makes a `permissive` verdict actionable, on the primary
    LLM-facing surface; the SDK layer had a full-field guard and this one had
    none. `tools.py` projects and renames in many other tools, so the pass-through
    that makes this true today is a fact about one line.
    """
    from dexllm import tools

    out = tools.execute("detect_permissive_tls", {}, fdk)
    for c in out["components"]:
        assert set(c) == {
            "class_descriptor",
            "interface_descriptor",
            "kind",
            "method_descriptor",
            "verdict",
            "reason",
            "constructed_in",
        }
    row = next(c for c in out["components"] if c["class_descriptor"] == "LDuckTrust;")
    assert "another overload" in row["reason"]


def test_the_mcp_schema_default_is_the_impl_default():
    """The schema default is what an LLM reads to decide whether to pass it.

    dexllm#49 pinned exactly this for `app_only` and it was not generalised.
    """
    import inspect

    from dexllm import tools

    schema = next(
        d for d in tools.TOOL_DEFINITIONS if d["name"] == "detect_permissive_tls"
    )
    assert schema["input_schema"]["properties"]["with_xref"]["default"] is True
    sig = inspect.signature(tools.TOOL_IMPLS["detect_permissive_tls"])
    assert sig.parameters["with_xref"].default is True


def test_the_mcp_tool_honours_with_xref(fdk):
    from dexllm import tools

    out = tools.execute("detect_permissive_tls", {"with_xref": False}, fdk)
    assert all(c["constructed_in"] == [] for c in out["components"])


# ── the corpus ───────────────────────────────────────────────────────────────


def test_a_real_corpus_trust_all_manager_is_found():
    """Evidence from a dex nobody wrote for this feature.

    ``InterfaceCls.dex`` (androguard's own test data) declares the textbook
    trust-all ``X509TrustManager``, and before this detector existed
    ``summarize_capabilities`` reported ``{}`` for it.

    HONOURS the narrowing explicitly: taking `loadable_apks` and then re-globbing
    the corpus would ignore `$DEXLLM_TEST_APK` and make `require_corpus_shape`'s
    skip branch dead, which is how a guard passes for the wrong reason.
    """
    import glob

    if corpus_is_narrowed():
        sources = [os.environ["DEXLLM_TEST_APK"]]
    else:
        sources = sorted(glob.glob(str(REPO_ROOT / "test_apk" / "APK" / "*")))
        if not sources:
            pytest.skip("no corpus")
    found = []
    for p in sources:
        if not os.path.isfile(p):
            continue
        try:
            d = dexllm.DexKit(p)
        except Exception:  # noqa: BLE001 - not a container
            continue
        found += [
            (os.path.basename(p), r["class_descriptor"])
            for r in detect_permissive_tls(d, with_xref=False)
            if r["verdict"] == PERMISSIVE
        ]
    require_corpus_shape(
        bool(found),
        "class implementing javax.net.ssl HostnameVerifier / X509TrustManager "
        "with a provably permissive body",
        "the detector stopped firing on real dex",
    )
