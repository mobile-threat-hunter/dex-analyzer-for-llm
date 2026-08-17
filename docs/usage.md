# dexllm

Python static analysis library for Android APK / DEX files, built on top of [LuckyPray/DexKit](https://github.com/LuckyPray/DexKit) with pybind11.

Adds capabilities that upstream DexKit doesn't expose, oriented for **security analysis / malware triage** rather than Xposed module development:

- **External API reference enumeration** — every Android framework API the app touches
- **Call site mapping with bytecode offsets** — including external (framework) callees
- **Capability / permission summary** — API → category aggregation (LOCATION, CRYPTO, REFLECTION, …)
- **Intra-method dataflow** — track ConstString / NewInstance / argument origin per call site
- **Smali rendering** — baksmali-style, no JVM needed
- **Java decompiler** — full DAD-aligned C++ port in `dad_cpp/`: `decompile_method`, `decompile_class`, and `decompile_method_ast` (the complete androguard `dast.py` nested AST). ~92% byte / ~98% line parity vs androguard DAD, 0-crash on a 22-APK / 443k-method corpus, and ~4.5× faster per method than androguard (see [comparison](#performance)).
- **LLM backends** — a shared tool catalog (`dexllm.tools`) exposed via an MCP stdio server and a FastAPI/SSE web backend.

> **Looking for the flat reference?** [docs/api.md](api.md) lists every method
> with its exact return type and a real example output. This page is the
> task-oriented walkthrough.

**`L` = capability level** — a numbered grouping of analysis capabilities, not a strict abstraction hierarchy: `L7` (the find/match engine) is the bottom-layer search primitive that `L1`–`L4` build on, and `L5`/`L6` are the smali/Java decompile paths. All of L1–L7 below are operational. The decompiler is a strict function-by-function port of androguard's DAD (`decompiler/*.py`: graph → dataflow → control_flow → writer/dast); see [CLAUDE.md](../CLAUDE.md#dad-aligned-development-policy) for the port roadmap.

## Install

Requires:
- Python 3.9+
- CMake 3.20+, Ninja
- pybind11 3.0+, scikit-build-core 0.10+
- C++20 compiler

```bash
# from the repo root
pip install -e .                           # editable build
# or:
pip install -e . --no-build-isolation --force-reinstall   # force a clean native rebuild
```

## TL;DR — load an APK

```python
import dexllm

dk = dexllm.DexKit("/path/to/app.apk")
print(dk.dex_count(), "dex files,", dk.apk_path())
# Optional: warm all analysis caches upfront (one-time ~200ms on a 50-dex APK).
# Otherwise caches warm lazily on first access of each analyser.
dk.warm_analysis_caches()
```

`DexKit(path)` identifies the file **by content, not by extension** — a `dex\n` magic loads as a bare `.dex`, anything else must prove out as a real zip/apk container (PK signature + a valid central directory) carrying at least one `classes*.dex`. So a **disguised or extension-less APK** (a renamed `.png`, no extension, …) still loads, while a non-dex/non-zip file or a zip with no `classes*.dex` raises a clear error instead of silently loading nothing.

```python
dk = dexllm.DexKit("classes2.dex")            # raw secondary dex (dex\n magic), loaded directly
dk = dexllm.DexKit("/tmp/evil.png")           # disguised APK — loaded by its PK content
print(dk.decompile_class("Lcom/blafoo/bar/Blafoo;"))
```

Probe a file **without loading it** with `dexllm.identify(path)` — handy for triaging a directory of unknown blobs:

```python
dexllm.identify("/path/to/suspect")
# → {'format': 'zip', 'is_apk': True, 'has_manifest': True, 'dex_count': 2,
#    'source': '/path/to/suspect'}
#   format: "dex" | "zip" | "unknown";  is_apk = a zip carrying an AndroidManifest.xml
```

Every loaded dex is **structurally verified at load** (a port of ART's
`DexFileVerifier`) before the core parses it — malformed or crafted input is
rejected with a byte-level reason instead of crashing the analyzer. Inspect the
per-dex verdicts of a **loaded** container with `dk.verify_report()`:

```python
for r in dk.verify_report():
    print(r)   # → {'dex_id': 0, 'name': 'classes.dex', 'valid': True, 'reason': '', 'source': 'app.apk'}
```

To verify **without loading** — the `verify()` sibling of `identify()` — use
`dexllm.verify(path)`. It runs the same gate over a path's dex(es) and returns
one verdict per dex, but **never raises**: a malformed / unopenable / non-dex
path is reported as a `valid=False` verdict (where construction would throw).
For a loadable source the result is byte-identical to `dk.verify_report()`.

```python
dexllm.verify("/path/to/suspect")     # per-dex, no load, no raise
# → [{'dex_id': 0, 'name': 'classes.dex', 'valid': True, 'reason': '', 'source': 'app.apk'}]
dexllm.verify("broken.dex", lenient=True)   # lenient = ART-structural mode (skip VerifyInsns)
```

A container whose every dex fails verification raises at construction (but
`dexllm.verify` reports it instead). See the
[DEX-handling comparison](dexkit-vs-art-dex-handling.md) §1 for exactly what's checked.

In a multidex APK, a class declared in more than one `classes*.dex` resolves **first-wins by lowest dex_id** (classes.dex before classes2.dex), deterministically — matching ART/AOSP, so packer collisions decompile to the body that actually runs (see [DEX-handling comparison](dexkit-vs-art-dex-handling.md)).

### Multiple sources — priority by order (packer / runtime-unpack)

Pass a **list** of sources to load them in order; earlier sources get lower
dex_ids, and resolution is first-wins, so the **first source wins a class
collision**:

```python
# Analysing a packed app: a runtime-decrypted/dumped dex should win over the
# original (stub) classes. List it FIRST so first-wins prefers it — the same
# order the packer arranges at runtime (ART consults the decrypted dex first).
dk = dexllm.DexKit(["/tmp/dumped_real.dex", "app.apk"])   # dumped wins collisions
dk.decompile_class("Lcom/evil/RealC2;")              # the unpacked body

dk = dexllm.DexKit(["dump1.dex", "dump2.dex", "app.apk"]) # several dumps + apk
```

Each source is a bare `.dex` or a zip/apk, every dex still passes the load-time
verifier, and classes from **all** sources are cross-indexed (search/decompile see
the merged set). This is the static side of the unpack workflow — dump the
decrypted dex with an external dynamic tool, then load it first. (`apk_path()`
reports the first source; `sources()` returns the whole list.)

`dexllm.add_dumped_dexes` is the ergonomic verb for the "re-analyze after dumping"
step — it rebuilds from the dump(s) **plus** the current sources:

```python
dk = dexllm.DexKit("app.apk")
# ... detect packing, dump the decrypted dex to /tmp/dump.dex with a dynamic tool ...
dk = dexllm.add_dumped_dexes(dk, "/tmp/dump.dex")   # dump prepended → unpacked wins
dk.decompile_class("Lcom/evil/RealC2;")        # the real body
```

Defaults: `prefer=True` (dumps loaded first → win collisions) and `lenient=True`
(verify in **ART-structural-equivalent** mode — skip instruction-operand checks — so
a *partially*-decrypted dump, with valid structure but garbage method bodies, still
loads, exactly as ART loads it; header/structure/bounds are still verified). It
returns a fresh `DexKit` (a clean rebuild, consistent caches) — keep the new handle.

The single-source constructor argument is still named `apk_path` for backward
compatibility. A zip APK loads in ~150ms for a 50-dex app using zero-copy slicer-based dex parsing. Subsequent operations cache aggressively — the second call is always ≤1µs marshalling overhead plus the algorithm cost.

---

## L1 — what external (Android framework) APIs does this APK touch?

```python
# Methods
for ref in dk.list_external_method_refs(framework_only=True):
    print(ref.java_signature)
    # → android.util.Log.d(java.lang.String, java.lang.String) -> int
    # → android.content.Intent.<init>(java.lang.String) -> void
    # ...

# Types
for ref in dk.list_external_type_refs(framework_only=True):
    print(ref.java_name)
    # → android.app.Activity
    # → android.util.Log

# Fields
for ref in dk.list_external_field_refs(framework_only=True):
    print(ref.java_signature)
```

Pass `framework_only=False` to also include non-framework external refs (SDKs you embed, …).

### Filter with helpers

```python
from dexllm import filter_method_refs

# Only methods on android.content.* / android.net.*
hits = filter_method_refs(
    dk.list_external_method_refs(),
    class_prefix=("android.content.", "android.net."),
)
```

---

## L1.5 — class summary (works on internal AND external classes)

```python
summary = dk.get_class_summary("Lcom/ss/android/agilelogger/ALog;")
print(summary.is_internal, summary.dex_id, summary.superclass_descriptor)
print("methods:", len(summary.methods))
print("fields:", len(summary.fields))
```

For external classes (e.g. `Landroid/util/Log;`), the summary lists only the members the APK *actually references* — useful for understanding the subset of an SDK that's in use.

---

## L2 — find every call site to a specific API (internal or external)

```python
for site in dk.find_call_sites_to(
    "Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I"
):
    print(f"[opcode {site.invoke_opcode:02x} @ off 0x{site.bytecode_offset:x}] "
          f"{site.caller_descriptor}  dex={site.caller_dex_id}")
```

Each site is a distinct invoke instruction — if the same caller invokes the API twice, you get two entries. `bytecode_offset` is the byte offset into the caller's **instruction stream** — the same base `render_method_smali` prints (`0xNN:`), i.e. relative to `insns`, not to the start of the `code_item` struct.

The **forward** direction — what a given method calls (its callees) — is
`dk.find_call_sites_from(method)`: the same `CallSite` list, but the caller is
fixed to the method and `callee_descriptor` varies. `find_call_sites_from(M)`
and `find_call_sites_to(C)` are the forward and reverse of one invoke edge (if
`M` invokes `C`, `M` is among `C`'s callers). `[]` for an external / bodyless method.

### L2.5 — field read/write xref

Which methods **read** (`iget*`/`sget*`) or **write** (`iput*`/`sput*`) a field —
from dexkit's exact `field_get_method_ids` / `field_put_method_ids` reverse index:

```python
fd = "La2dp/Vol/StoreLoc;->MAX_ACC:F"          # Lcls;->name:Type
dk.find_methods_reading_field(fd)                  # -> [method descriptors that read it]
dk.find_methods_writing_field(fd)                 # -> [method descriptors that write it]
```

Both return **one entry per access instruction, not per method** (like `CallSite`),
so a method touching the field twice appears twice — `set()` the result when you
want distinct methods.

Type xref (signature positions) — where a `Lpkg/Cls;` type appears as a field type,
a method return type, or a method parameter:

```python
tr = dk.find_type_references("Landroid/location/Location;")
tr.fields              # fields OF this type
tr.methods_returning   # methods returning it
tr.methods_with_param  # methods taking it as a param
```

Per-dex enumeration follows a uniform scope axis — the bare form is all loaded
dexes, the `…_in_dex(dex_id)` form is one dex (empty if out of range), and the
all-dexes form is exactly the per-dex concatenation: `dk.list_classes` /
`dk.list_classes_in_dex(dex_id)` (declared classes), `dk.list_fields` /
`dk.list_fields_in_dex(dex_id)`, `dk.list_methods` /
`dk.list_methods_in_dex(dex_id)` (id-table references), and
`dk.extract_dex(dex_id)` (raw dex image bytes **plus** where they came from — `source` / `entry` / `offset`), or `dk.extract_dexes()` for the whole container at once.

---

## L3 — what permissions / categories does this APK exercise?

```python
report = dexllm.summarize_capabilities(dk)

# Top permissions touched (via API usage) — the APP's own call sites by default
for perm, count in report.top_permissions(10):
    print(f"{count:>5}× {perm}")
# →     2 × android.permission.INTERNET

# Top categories
for cat, count in report.top_categories(10):
    print(f"{count:>5}× {cat}")
# →     2 × STORAGE
# →     2 × REFLECTION
# →     2 × NETWORK_IO

# Everything the dex does, including bundled libraries (the pre-dexllm#49 numbers)
dexllm.summarize_capabilities(dk, app_only=False).top_categories(3)
# → [('REFLECTION', 120), ('SCHEDULING', 8), ('CRYPTO', 8)]

# Cross-domain concerns (today only IDENTIFIER)
report.flags            # Counter() on this APK; Counter({'IDENTIFIER': 2}) on one
                        # calling both getDeviceId overloads. IDENTIFIER also covers
                        # getSubscriberId / getSimSerialNumber / getLine1Number /
                        # BluetoothAdapter.getAddress

# Filter to a subset (only crypto-related APIs)
crypto = dexllm.summarize_capabilities(dk, only_categories={"CRYPTO"})
for hit in crypto.api_hits:
    print(hit.api_signature, "→", hit.permissions, hit.categories, hit.flags)
```

The catalog carries **two axes**, kept apart so the counters stay meaningful:

- `categories` — one axis (domain / behaviour), no tag implied by another, so one
  call site is never counted twice under two names for the same concern. A second
  tag is only correct when the API genuinely spans two domains
  (`WifiManager.getScanResults` → `WIFI` + `LOCATION`) — and then it does count
  once in each, so `sum(report.categories.values()) >= total_call_sites +
  total_field_accesses`, with equality exactly when every matched entry carries a
  single tag. Both totals appear because the Counters count TOUCHES — an invoke
  instruction for a method entry, a reading method for a field one (dexllm#36) —
  while the two totals keep those units apart.
- `flags` — the orthogonal, cross-domain concerns a domain tag cannot express.
  Today only `IDENTIFIER`, which rolls up across TELEPHONY / BLUETOOTH / … and is
  not recoverable from the domain axis.

`only_categories=` matches **either** axis, so a tag keeps working as a filter
whichever axis it lives on — `only_categories={"IDENTIFIER"}` selects the
identifier-returning APIs. A tag the catalog does not declare (one the 0.2
normalisation removed, or a typo) raises `ValueError`: a silently empty report
would be indistinguishable from "this APK does none of that".

Facts the key already states (`IMSI` for `getSubscriberId`), severity judgements
(`RISKY`) and argument-dependent guesses (`POTENTIAL_ANDROID_ID` — [L4
`resolve_call_args`](#l4--intra-method-dataflow-whats-actually-passed-at-each-call-site)
answers that properly) are deliberately **not** tags.

### Reading an `<init>` key on a framework service

Four entries are the CONSTRUCTOR of a class an app **subclasses** —
`AccessibilityService` (`ACCESSIBILITY`), `InputMethodService` (`INPUT_CAPTURE`),
`NotificationListenerService` (`NOTIFICATIONS`) and `DeviceAdminReceiver`
(`DEVICE_ADMIN`). A hit means **the APK declares such a service**:

```python
report = dexllm.summarize_capabilities(dexllm.DexKit("a2dp.Vol_137.apk"))
listeners = [h for h in report.api_hits
             if "NotificationListenerService" in h.api_signature]
for hit in listeners:
    print(hit.api_signature, hit.call_site_count, sorted(hit.callers))
# → Landroid/service/notification/NotificationListenerService;-><init>()V 1
#   ['La2dp/Vol/NotificationCatcher;-><init>()V']
```

The capability of such a service is reached two ways, and a member key can name
neither reliably. A member the app **calls** (`getRootInActiveWindow`,
`performGlobalAction`, `getActiveNotifications`) is invoked on `this`, and a dex
`method_id` records the **static receiver type**, so it is spelled under the app's
own subclass — unreachable, and `getActiveNotifications` accordingly has 0
`method_id`s in the APK above. A callback the app **overrides**
(`onNotificationPosted`) is invoked by the system, so there is no call site for it
at all — unless the override happens to call `super.onNotificationPosted()`, which
*is* spelled under the framework class but is entirely **optional**: a payload that
wants the notifications and not the default behaviour simply omits it.

A **constructor is never inherited**, and `super()` is emitted by the compiler
whether or not the source writes it, so it is the one part of the capability that
is spelled under the framework class **unconditionally**. That is what makes it a
usable key where the members are not.

How tightly a hit implies *declares* depends on the class. `AccessibilityService`
and `NotificationListenerService` are `abstract` in AOSP, so naming their
constructor is **provably** a subclass — nothing else can. `InputMethodService`
and `DeviceAdminReceiver` are concrete, so `new X()` would emit the identical
descriptor and a hit there reads as *declares or constructs*; no corpus APK does
the latter (nobody instantiates a service by hand) and both readings point at the
same capability, but the distinction is real.

Nothing else about these entries is special. They count invoke instructions into
`call_site_count` like any other method key (normally one per subclass; a class
declaring two constructors of its own chains `super()` twice), the caller is the
subclass's own `<init>`, so `app_only` separates an app's service from a bundled
one with no special case.

Three limits, stated rather than left to be discovered:

- **A dex fact only.** The service must also be declared in the manifest with its
  `BIND_*` permission to be usable, and dexllm reads no manifest — so a hit is a
  strong triage signal, not proof the capability is reachable at runtime.
- **A subclass declaring no constructor is invisible**, since it emits no
  `super()`. Real but out of reach of these four: 17 of the corpus's 7,539
  non-`Object` subclasses are in that shape (R8-minified library internals), while
  **0** of its 178 `Service` / `BroadcastReceiver` / `Activity` / `Application` /
  `ContentProvider` subclasses are — the framework instantiates a service through
  its no-arg constructor, so one that lost it would not start.
- **One key per constructor OVERLOAD.** Each of these four classes declares
  exactly one constructor, no-arg, so the single `()V` key is complete for them.
  A class with several would need each curated: `Thread` has 4, and of 30 corpus
  subclasses only 27 chain `()V` — the rest call `super(Runnable, String)` or
  `super(String)`.

**An interface is not a fourth limit — it needs no key form at all.** It has no
constructor, so the trick above does not apply, but nothing has to: an
implementation is inert until the app **hands it to the framework**, and for a
capability-shaped interface that handover is an ordinary call on a framework
receiver (`requestLocationUpdates`, `SSLContext.init`) — already an ordinary call
site. The subclass case needed a new key for the opposite reason: the system
instantiates a manifest-declared service *itself*, so there is no app-side call to
find.

That is an **empirical** claim about the capability surface, not a structural
universal — a handover is not always a call. An AIDL `Stub` returns its binder
from `onBind`, `Parcelable$Creator` is a static field the framework reads
reflectively, and `ServiceLoader` registers through a `META-INF/services`
resource; all three occur in the corpus. None is a capability the catalog misses:
an AIDL `Stub` is an abstract **class**, so the constructor form covers it;
`Creator` is serialization boilerplate; the corpus's `ServiceLoader` entries are
coroutine internals. A capability-shaped interface whose handover is *not* a call
would be invisible, and none is known.

On the corpus, exactly two implemented framework interfaces are capability-shaped
rather than UI, lifecycle or serialization boilerplate:

- **`android.location.LocationListener`**, implemented by an app class in two real
  APKs — and reported, because `LocationManager.requestLocationUpdates` is curated
  and fires there (3 sites, `LOCATION` 5). This is the decision working end to end.
- **`javax.net.ssl.X509TrustManager`**, in a bare test dex only. Its registration
  calls were the gap: `SSLContext.init` and
  `SSLCertificateSocketFactory.setTrustManagers` are curated now, alongside the
  per-connection `HttpsURLConnection.setHostnameVerifier` that was missing beside
  its already-curated `setDefault*` and instance-factory siblings.

### `CUSTOM_TLS_TRUST` — the app supplies its own TLS trust decision

Those six, plus six more, are tagged **`CUSTOM_TLS_TRUST`** rather than
`NETWORK_IO` (dexllm#52). Under `NETWORK_IO` "the app supplies its own trust
decision" was counted exactly like "the app uses the network", which every app
does.

The name is deliberate in both directions. `TLS_BYPASS` would over-claim: the same
APIs implement certificate **pinning**, the security-positive use, and what a
`TrustManager` decides lives in its body, not at the registration, so no call site
proves a bypass. `TLS_VALIDATION` — the first name tried — under-claimed: *every*
app validates TLS, so it did not discriminate, and the docs had to explain that
the tag was not what it sounded like. **CUSTOM** is the discriminating word.

| curated member | what it is |
|---|---|
| `SSLContext.init` / `.setDefault` | install a `TrustManager`; `setDefault` needs no `init` first (AOSP: *"The default context must be immediately usable and not require initialization"*) |
| `HttpsURLConnection.set{,Default}HostnameVerifier` / `set{,Default}SSLSocketFactory` | per-connection and process-wide |
| `SSLCertificateSocketFactory.setTrustManagers` / `.getInsecure` / `.createSocket` | `getInsecure` needs no `TrustManager` at all — AOSP: *"all SSL security checks disabled … **Warning:** … vulnerable to person-in-the-middle attacks!"*; the hostname-less `createSocket` overloads skip verification |
| `org.apache.http.conn.ssl.SSLSocketFactory.setHostnameVerifier` / `ALLOW_ALL_HOSTNAME_VERIFIER` | the legacy Apache stack (shipped through API 28) — the twin of the `HttpsURLConnection` setter, and the field is what proves permissiveness rather than customisation |
| `SslErrorHandler.proceed` | the `onReceivedSslError` bypass |

`SslErrorHandler.proceed` carries **`WEBVIEW` as well**, so a WebView sweep still
finds it. That is not a contradiction: `categories` forbids a tag *implied by*
another, not two tags — `WebView.loadUrl` is already `['WEBVIEW', 'NETWORK_IO']`.
Its sibling `cancel()` is the correct behaviour and is deliberately **not**
curated; curating both would only detect that a WebView exists.

The callback itself cannot be a key — the system invokes `onReceivedSslError` on
the app's own `WebViewClient` subclass, so it is spelled there — but `proceed()`
is called *by* the app *on* a framework object.

**`javax.net.ssl.SSLSocketFactory.createSocket` stays `NETWORK_IO`**: that
factory's trust comes from the `SSLContext` that built it, and every way of
customising that context is already a key. (Its `android.net` namesake is
different, and is curated — AOSP marks its hostname-less overloads as skipping
verification.)

> **This moved values that were already released.** Six entries left `NETWORK_IO`,
> so `report.categories['NETWORK_IO']` shrinks and `only_categories={'NETWORK_IO'}`
> no longer returns them, with no type or name change to warn you. Query
> `{'CUSTOM_TLS_TRUST'}` for the family.

One path has no framework spelling at all — an OkHttp `HostnameVerifier` is set on
a builder that is not a framework class, and unlike the TrustManager case there is
no `SSLContext`-shaped choke point behind it, so nothing in the dex names it.

The catalog is JSON (`android_api_map.json`). To use your own, copy the bundled
file, edit it, and point dexllm at the containing **directory** — do not edit the
copy inside `site-packages`, which `pip install -U` discards:

```python
dexllm.summarize_capabilities(dk, data_dir="/etc/dexllm")   # or $DEXLLM_DATA_DIR
```

See [Overriding the bundled data](#overriding-the-bundled-data). Keep the two axes
and declare your own `category_vocabulary` / `flag_vocabulary` — `only_categories`
validates against **your** catalog's, so a custom taxonomy stays filterable.
A key is either a **method** descriptor (`Lcls;->name(proto)ret`, resolved through
`find_call_sites_to`) or a **field** descriptor (`Lcls;->NAME:Ltype;`, resolved
through `find_methods_reading_field` — how an app reaches contacts/SMS/calendar,
by reading a framework `CONTENT_URI` constant). The two are told apart by shape,
so no schema key says which; any other shape resolves nothing, silently.

Two things the numbers do **not** say. A `permissions` entry is what the API
*requires* at any protection level — `getDeviceId` carries both `READ_PHONE_STATE`
and the `signature`-level `READ_PRIVILEGED_PHONE_STATE` — so it is not what the app
*requests*; the manifest is. And a count is of **call sites in the dex, not
executions**.

That second one used to mean a bundled library's call sites counted like the app's
own, which made several categories measure how much androidx an APK ships: over the
corpus 98% of `REFLECTION` touches, 94% of `SCHEDULING` and **all** of `BIOMETRIC` /
`SETTINGS` / `DYNAMIC_LOAD` come from library callers, and 90% of the 515 distinct
callers are library code — which is why a Google TV *sample app* used to report
`3 × SCHEDULE_EXACT_ALARM` (100% `AlarmManagerCompat`) and `3 × USE_FINGERPRINT`
(100% `FingerprintManagerCompat`). Since dexllm#49 **`app_only=True` is the
default**, the same verb, default and predicate as
[`dangerous_permission_api_callers`](#dangerous-permission-api-usage), so the
counters describe the app; an API left with no kept caller drops out of `api_hits`
entirely, so a category can disappear — and `report.dropped_touches` /
`report.dropped_apis` say what went, so a zero report is readable as "only the
bundled libraries do this" rather than as "this APK does none of it" (11 of the
17 corpus sources that report anything report nothing under the default).
`app_only=False` restores every caller and leaves both at 0.

The filter is a package-prefix heuristic, so a filtered report is a triage aid, not
proof of absence. A library the list does not name reads as app code and is kept
(the tvleanback hits above are mostly `com.bumptech.glide`); code that merely sits
under `com.google.android.*` — what a repackaged sample does — reads as a library
and is dropped. `report.by_caller` names who, and `app_only=False` shows everyone.

The bundled catalog is **generated** by `scripts/gen_capability_catalog.py` from a
curated `(class, member)` selection — the script resolves each name against the
AOSP member catalog, expands it to every overload, and fills permissions from
`perm_api.json`, so a descriptor is never hand-typed. Only the *selection* is
hand-made: projecting every `@RequiresPermission` member instead was measured and
its top additions are `Context.startActivity` / `sendBroadcast` / `bindService`,
present in essentially every app. For the exhaustive permission surface use
[`dangerous_permission_apis`](#dangerous-permission-api-usage) instead.

---

## L4 — intra-method dataflow (what's actually passed at each call site?)

```python
# Every (Intent, String action) constructor site
sites = dk.resolve_call_args(
    "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
)

# arg[0] is the receiver (NewInstance), arg[1] is the action string
actions = sorted({
    s.args[1].string_value
    for s in sites
    if s.args[1].kind == "ConstString"
})
print(f"{len(actions)} unique Intent actions:")
for a in actions:
    print(" ", a)

# Same trick for Cipher.getInstance — find every transformation used
ciphers = sorted({
    s.args[0].string_value
    for s in dk.resolve_call_args(
        "Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;")
    if s.args[0].kind == "ConstString"
})
# → ['AES/CBC/PKCS5Padding', 'AES/ECB/NoPadding', ...]
```

`ArgOrigin.kind` values: `ConstString`, `ConstInt`, `ConstWide`, `ConstClass`, `ConstNull`, `FieldRead`, `MethodReturn`, `Parameter`, `NewInstance`, `NewArray`, `Unknown`. Available fields depend on kind (`string_value`, `int_value`, `class_descriptor`, …).

**How much this proves (dexllm#16).** The simulation MEETS the register file at every
control-flow join, so a reported value is one that reaches the call on **every** path —
a value that is only valid on one branch is never presented as unconditional. It is not
a fixed point (two passes, no iteration): a value defined *before* a loop and not
re-established inside it does not survive the loop header, and a *catch handler*
starts from an unknown register file. Both give `Unknown` with
**`crossed_branch = True`**, which means "a tracked definition was discarded here" —
the paths may disagree, or the analyzer gave up at a loop/catch. Treat it as
*not proven*, not as a proven pair of values. `Unknown` with `crossed_branch = False`
means no definition was tracked at all (arithmetic, array load, …). A rule that requires an exact argument value should treat a
`crossed_branch` argument as *unproven*, not as *absent*:

```python
for s in dk.resolve_call_args(
        "Landroid/content/pm/PackageManager;->setComponentEnabledSetting"
        "(Landroid/content/ComponentName;II)V"):
    state, flags = s.args[2], s.args[3]
    if state.kind == "ConstInt" and state.int_value == 2 \
            and flags.kind == "ConstInt" and flags.int_value == 1:
        print("hides its launcher icon:", s.caller_descriptor)   # proven on all paths
    elif state.crossed_branch:
        print("conditional — decompile to see which branch:", s.caller_descriptor)
```

When the value genuinely depends on a branch, decompile the caller
(`decompile_method` / `decompile_method_ast`) — that path carries the real CFG.

---

## L5 — smali rendering (baksmali-style, no JVM)

```python
# Whole class
print(dk.render_class_smali("Lcom/ss/android/agilelogger/ALog;"))

# Single method
print(dk.render_method_smali(
    "Lcom/ss/android/agilelogger/ALog;->d(Ljava/lang/String;Ljava/lang/String;)V"
))
```

Returns `""` for external / missing classes.

---

## L6 — Java decompilation (DAD port — complete)

```python
# Single method → DAD-quality Java (GIL released → parallel-safe)
print(dk.decompile_method("Lcom/example/Utils;->getDisplaySize(Landroid/content/Context;)Landroid/graphics/Point;"))

# Whole class → package + header + fields + methods
print(dk.decompile_class("Lcom/example/Utils;"))

# Structured AST — the full androguard dast.py nested form
ast = dk.decompile_method_ast("Lcom/example/Utils;->getDisplaySize(Landroid/content/Context;)Landroid/graphics/Point;")
print(ast["ast"]["body"])      # {triple, flags, ret, params, comments, body}
# Skip the redundant text emit when only the AST is needed (~1.7x faster):
ast_only = dk.decompile_method_ast(desc, include_source=False)

# Java text + source-line ↔ bytecode-offset map (smali ↔ Java cursor sync):
pc = dk.decompile_method_with_pc_map("Lcom/example/Utils;->getDisplaySize(Landroid/content/Context;)Landroid/graphics/Point;")
print(pc["source"], pc["pc_map"])   # pc_map: [(line_1based, byte_off), …], headers included
```

API surface: `decompile_method` / `decompile_method_with_pc_map` / `decompile_class` / `decompile_method_ast` / `render_method_smali`, plus cache control
(`clear_decompiler_cache`, `decompiler_cache_size`, `set_decompiler_cache_capacity`). External / native / abstract methods return `""` (graceful — androguard crashes on these).

The decompiler is a strict, function-by-function port of androguard's `decompiler/*.py` (graph → dataflow → control_flow → writer/dast) under `dad_cpp/`, validated by 25 DAD parity suites (`ninja parity_tests && ctest`) and an end-to-end diff vs androguard. A few spec-correctness divergences are intentional (valid `null`/`true`/`false` where androguard leaks `None`/`True`/`False`; IEEE754 floats) — see [CLAUDE.md](../CLAUDE.md) "Upstream DAD bug fixes".

---

## L7 — find / match operations (Aho-Corasick + matcher engine from upstream)

**Two input concepts (DexKit's own split).** The name-SEARCH family below takes a fuzzy
name query and is lenient — all operations here auto-normalise their inputs, so you may
pass a descriptor (`Landroid/app/Activity;`), a smali path (`android/app/Activity`), or a
Java dotted name (`android.app.Activity`). By contrast the IDENTITY APIs (decompile,
`find_call_sites_to` / `resolve_call_args`, `find_type_references`,
`find_methods_reading_field` / `find_methods_writing_field`,
`render_*_smali`, `get_class_summary`, `list_class_methods`, `list_class_strings` /
`list_method_strings`, `locate_class_dex`) address one
EXACT entity and require the canonical Dalvik descriptor (the L-form emitted by `list_*` /
`find_*` output). Passing a dotted/smali name to an identity API is a clear error, not a
silent empty result — copy the descriptor straight from a search or list result.

```python
# Name patterns
dk.find_classes_by_name("Activity", "ends_with")       # match mode: equals / starts_with / ends_with / contains / regex
dk.find_methods_by_name("onCreate", "equals",
                        declaring_class="Landroid/app/Activity;")
dk.find_fields_by_name("mTitle", "equals")             # the field arm (dexllm#37)

# String literal usage — which code LOADS the string
dk.find_classes_using_strings(["android.permission.READ_CONTACTS"])

# …and which class DECLARES it as a constant. `using` searches the const-string
# bytecode index, so a `static final String` the app never loads is invisible to it —
# this is the only way to locate an indicator kept solely in a constant.
dk.find_classes_declaring_strings(["https://c2.example/gate.php"], "equals")
dk.find_methods_using_strings(["AES/CBC/PKCS5Padding"])

# The FORWARD direction — which strings does THIS code load? (identity APIs:
# exact descriptors). Answers "what literals does this method carry" without
# rendering smali or decompiling; class scope adds static `VALUE_STRING` inits.
dk.list_method_strings("Lcom/x/Net;->beacon()V")   # its const-string operands
dk.list_class_strings("Lcom/x/Net;")               # declared methods ∪ static init

# Batch (Aho-Corasick) — multiple keys at once, much faster than N separate scans
dk.batch_find_classes_using_strings({
    "ROOT_CHECK": ["/system/bin/su", "/system/xbin/su"],
    "REFLECTION": ["java.lang.reflect.Method"],
    "DEBUG": ["isDebuggerConnected"],
})
dk.batch_find_methods_using_strings({"NET": ["http://", "https://"]})  # same, at method granularity

# Numeric literals (useful for magic constants, ports, opcodes)
dk.find_methods_using_int_literals([0xDEADBEEF, 0xCAFEBABE])
dk.find_methods_using_double_literals([3.14159])

# Type hierarchy
dk.find_classes_by_super("Landroid/app/Activity;")
dk.find_classes_implementing("Landroid/os/Parcelable;")

# Annotations
dk.find_classes_by_annotation("Lkotlin/Metadata;")
dk.find_methods_by_annotation("Landroidx/annotation/RequiresApi;")
```

**`match_type`** (the name/string finders) is one of `equals` / `contains`
(default) / `starts_with` / `ends_with` / `regex`, with `ignore_case=False` by
default. **`regex` is DexKit's *SimilarRegex* — it supports only the `^` (prefix)
and `$` (suffix) anchors, not full regex** (e.g. `"^com/foo"`, `"Activity$"`); an
unrecognised `match_type` string silently falls back to `contains`.

---

## Static C2 / IOC extraction

VirusTotal shows the URLs, domains, and IPs an app *contacts*; `extract_iocs`
recovers the same indicators **statically** — with no execution — and ties each one
back to the class/method that references it.

> **Requires** `pip install "dexllm[ioc]"` (pulls `tldextract` for public-suffix
> domain validation). The defang + indicator regexes are in-tree.

```python
import dexllm

dk = dexllm.DexKit("app.apk")

iocs = dexllm.extract_iocs(dk)           # with_xref=True, denoise=True by default
for category in dexllm.IOC_CATEGORIES:   # urls / ips / domains / emails / onion
    for row in iocs[category]:
        # `methods` = call sites that LOAD it; `declared_in` = classes that DECLARE it
        # as a constant (an indicator kept only as a constant has no call site at all)
        print(category, row["value"], "<-", row["methods"][:1] or row["declared_in"][:1])
# urls https://c2.example.top/gate.php <- ['Lcom/x/Net;->beacon()V']

# The value-string feed it scans, for custom queries:
value_strings = dk.list_value_strings()  # strings loaded as DATA (no identifiers)
```

**Input** is `dk.list_value_strings()` — only strings the app loads *as data*
(`const-string`/`jumbo` operands + static `VALUE_STRING` initializers), so
type/method/field-name identifiers never enter the scan. **Defanged** indicators are
recovered (`hxxps://evil[.]top`, `1[.]2[.]3[.]4`, `admin[at]phish[.]kr`) by a
literal, linear un-defang pass. **Domains** are validated against the public suffix
list (`tldextract`), so `com.google.util` (not a real suffix) is rejected while
`maps.google.co.uk` resolves correctly. **Denoising** then drops the residual
identifier hosts: the app's own dex package paths (self-calibrating, from its type
descriptors), reverse-DNS / platform roots (`com.*`, `org.*`, `android.*`, …),
XML-namespace URIs (`http://schemas.android.com/...`), and word-gTLD identifier
collisions where a Java path's tail is a dictionary-word gTLD (`os.name`,
`Matcher.group`, `*.support` — `.name`/`.group`/`.support` are real TLDs). A
scheme-qualified URL keeps its host regardless. The classifier regexes are
hand-bounded (ReDoS-safe) and each string is length-capped — important because dex
value-strings include multi-MB blobs. Set `with_xref=False` to skip the per-indicator
L7 cross-reference, or lower `xref_limit` on string-heavy apps. Also the `extract_iocs`
MCP tool (returns `{indicators, counts}`).

> Note: the indicator extraction is in-tree and ReDoS-bounded by design —
> `iocextract` was evaluated but its regexes backtrack catastrophically on the dotted
> blobs dex strings contain, so only the safe `tldextract` PSL lookup is used.

### `content://` provider query URIs

The `content://` URIs a `ContentResolver` reads are the real handles for
SMS / contacts / call-log / calendar — the surface `READ_SMS` / `READ_CONTACTS`
gate, and invisible to the `@RequiresPermission` map (the `Uri` is assembled at
runtime). `detect_content_providers` matches the app's value-strings against a
bundled AOSP provider-URI dataset (`content_uris.json`):

```python
for hit in dexllm.detect_content_providers(dk):
    print(hit["uri"], hit["family"], "<-", hit["methods"][:1])
# content://sms sms <- ['Lb/g/a/m/f;->run()V']
```

### Overriding the bundled data

Two of the four data files carry **hand judgement** rather than mechanical AOSP
extraction — the capability catalog (`android_api_map.json`) and the `family`
labels in `content_uris.json` — so they take a per-call `data_dir=` argument, or
`$DEXLLM_DATA_DIR` for process-wide use (the form that also reaches the MCP and
HTTP servers, which take no such argument):

```python
dexllm.summarize_capabilities(dk, data_dir="/etc/dexllm")
dexllm.detect_content_providers(dk, data_dir="/etc/dexllm")
```

(Both paths above are real directories on your machine — a named directory that
does not exist raises, so substitute your own.)

Resolution is **arg → `$DEXLLM_DATA_DIR` → bundled**, and replacement is **per
file**: a directory holding only `content_uris.json` still serves the bundled
catalog, so overriding one file does not oblige you to copy the other. A file is
replaced whole rather than merged — both are small enough to copy and edit, and a
merge would need a per-key precedence rule neither schema expresses.

A `data_dir` that is named but does not exist raises `NotADirectoryError` (a typo
must not silently serve bundled data); an entry that **is** there but is not a
regular file — a directory, a FIFO, or a **dangling symlink** — raises `OSError`
naming the path, rather than reading as "absent" and falling back; and a file that
is present but malformed raises `ValueError` naming the path. An **empty** value
means "not configured" through both spellings, not the current directory. Note
what is *not* an error: an override directory that exists but is **empty** is
indistinguishable from a deliberate partial override, so it falls back — worth
knowing, because that is what a failed bind-mount usually leaves behind.

Parsed data is cached per resolved path, and so is **the decision to use an
override**: once a file has been taken from `data_dir`, a `rm` + `cp` redeploy
cannot demote a long-running server to bundled data mid-request. A bundled
**fallback** is re-decided every call, deliberately — an override that appears
later is picked up on its own, and one request landing inside a deploy window
cannot pin bundled data for the life of the process. Call
`dexllm.clear_data_caches()` to pick up a file whose bytes changed, or one
replaced at a path an override decision has already frozen on. The guarantee is
bounded by the cache size (16 entries), so a caller rotating more override
directories than that re-decides the evicted ones; one process-wide
`$DEXLLM_DATA_DIR`, or a handful of explicit directories, never reaches it.
Whether the override *directory* still exists is checked on every call, so a
volume that unmounts fails loudly rather than serving a stale copy — that
asymmetry is deliberate.

An unset config value must be threaded in as `None` or `""`, not `Path("")`:
pathlib turns that into `Path(".")` before the call, which is a real request for
the process directory and cannot be told apart from a deliberate one.

The permission tables (`perm_api.json` / `perm_levels.json`) are **not** in this
channel: they are mechanical extraction with no hand content, and `dataset_path=`
/ `$DEXLLM_AOSP_DATASET` already serve their real use case — a fresher AOSP
snapshot. See [Dangerous-permission API usage](#dangerous-permission-api-usage).

### Engine C++ port — permission callers (shared with the WASM binding)

`permission_api_callers` has a byte-identical **C++ engine port**,
`dk.permission_callers()` (all protection levels), so the WASM (embind) binding and
pybind run **one implementation over the engine-bundled AOSP dataset** (issue #14).
The pybind/SDK permission surface uses this C++ join directly.

> **The byte-identity holds for the bundled data.** The C++ dataset is a
> build-time blob compiled into the extension, so it cannot be overridden at
> runtime. Under `dataset_path=` / `$DEXLLM_AOSP_DATASET` the **Python**
> `permission_api_callers` follows your dataset while `dk.permission_callers()`
> keeps the bundled one. Measured over the test corpus with the bundled tables:
> identical on all 32 loadable sources (5 of which produce a non-empty result);
> divergent as soon as an override is set. Use one or the other under an
> override, not both.

The Python path still costs several times the C++ one, but it no longer rebuilds
its derived overload index on every call: that index is memoised per loaded table
(alongside the two `lru_cache`d loaders), so repeated calls — and the three
functions sharing it — pay for it once per dataset (dexllm#39).

The IoC / content-provider / capability analyses are **pure Python**
(`dexllm.extract_iocs` / `detect_content_providers` / `summarize_capabilities`) —
the canonical, ReDoS-safe, PSL-validated implementations dexllm's own API uses. The
earlier C++ mirrors of these three (which existed only to back the WASM binding)
were removed: dexllm does not carry web-only engine code, and a WASM consumer must
vendor its own in-browser engine.

The bundled AOSP data — the full `@RequiresPermission` permission→API map + level
buckets (`perm_api.json` / `perm_levels.json`, all protection levels) and the provider
URIs (`content_uris.json`) — is a committed snapshot of
[aosp_data_set](https://github.com/mobile-threat-hunter/aosp_data_set) (metalava
permission table + content-URI CSVs), verified in sync with upstream as of the
2026-07-04 dataset revision. (`android_api_map.json` is a separate catalog for
`summarize_capabilities`: a hand-curated SELECTION of APIs, with the descriptors,
overloads and permissions derived from that same dataset by
`scripts/gen_capability_catalog.py` — so regenerating it needs an `aosp_data_set`
checkout, while building and running dexllm do not. See
[L3](#l3--what-permissions--categories-does-this-apk-exercise) for its two-axis
schema before extending it.)

---

## Dangerous-permission API usage

Which **dangerous** permissions does the APK exercise *through real API calls* —
not just `<uses-permission>` claims? This joins AOSP's `@RequiresPermission`
permission→API map ([aosp_data_set](https://github.com/mobile-threat-hunter/aosp_data_set))
against the APK's referenced framework APIs.

```python
import dexllm

dk = dexllm.DexKit("app.apk")

# {permission: [pkg.Class#method(signature), ...]} for the gated APIs actually used
apis = dexllm.dangerous_permission_apis(dk)
# {'android.permission.ACCESS_FINE_LOCATION':
#     ['android.location.LocationManager#getLastKnownLocation(String)', ...], ...}

# same, plus WHO calls each gated API (jump straight to the code)
callers = dexllm.dangerous_permission_api_callers(dk)   # app_only=True by default
for perm, rows in callers.items():
    for row in rows:
        print(perm, row["api"], "<-", row["callers"][:1])
# ACCESS_FINE_LOCATION  android.location.LocationManager#getLastKnownLocation(String)
#   <- ['La2dp/Vol/StoreLoc;->grabGPS()V']
```

By default `app_only=True` drops callers that are bundled framework / official-library
code (`androidx.*`, `android.support.*`, `kotlin.*`, `com.google.android.*`, …) — a
dangerous-API call from there (e.g. AppCompat's `TwilightManager` reading location for
day/night theming) is library plumbing, not the app's own behaviour. Pass
`app_only=False` to keep every caller:

```python
dexllm.dangerous_permission_api_callers(dk, app_only=False)   # include framework callers
```

### All protection levels

`permission_api_callers` generalises this to the **full** permission surface — not just
the ~25 dangerous permissions, but all levels (`dangerous` / `signature` / `internal` /
`normal`, per `dexllm.PERM_LEVELS`), each group carrying its real `protectionLevel`:

```python
for g in dexllm.permission_api_callers(dk):           # app_only=True by default
    print(g["protectionLevel"], g["perm"], "→", len(g["rows"]), "APIs")
# signature  android.permission.WRITE_SECURE_SETTINGS → 1 APIs
# dangerous  android.permission.READ_SMS → 2 APIs

# filter to a subset of levels
sig = dexllm.permission_api_callers(dk, levels={"signature", "internal"})
```

It returns `[{"perm", "protectionLevel", "rows": [{"api", "descriptors", "callers"}]}]`
sorted by permission — the same shape the C++/WASM `permission_callers()` binding
returns (the dangerous slice is just this filtered to `protectionLevel == "dangerous"`).

The table carries the full method signature for each gated API, so **overloads are
matched precisely** — `getLastKnownLocation(String)` and its `LastLocationRequest`
overload are distinguished, and only the one the app actually references is reported
(arity is the primary, parse-robust discriminator; a `(class, method)` with a single
overload of an arity still matches on that alone, so a signature edge case can't drop
a real hit).

The full permission→API table (`perm_api.json`, 571 perms across all levels) + the
protection-level buckets (`perm_levels.json`) ship bundled — AOSP's metalava-extracted
`@RequiresPermission` inventory (clean, fully-qualified types) plus the AOSP
runtime-enforcement bridge (runtime-enforced public APIs that carry no annotation, e.g.
`SmsManager#copyMessageToIcc` → SEND_SMS; recorded arity-only, matched on arity); the
dangerous slice is DERIVED from them (single source of truth). Regenerate from a fresher checkout with
`python scripts/gen_perm_data.py /path/to/aosp_data_set`, or pass
`dataset_path="…/aosp_data_set"` (or set `$DEXLLM_AOSP_DATASET`) at call time to
compute live. `dangerous_permission_apis` / `dangerous_permission_api_callers` are also
MCP tools (the latter takes `app_only`).

---

## Descriptor helpers

```python
from dexllm import descriptor_to_java, java_to_descriptor, parse_proto, pretty_proto

descriptor_to_java("Landroid/util/Log;")     # → 'android.util.Log'
descriptor_to_java("[[I")                    # → 'int[][]'
java_to_descriptor("java.util.List")         # → 'Ljava/util/List;'
parse_proto("(II)Ljava/lang/String;")        # → (['I', 'I'], 'Ljava/lang/String;')
pretty_proto("(II)Ljava/lang/String;")       # → '(int, int) -> java.lang.String'
```

---

## End-to-end example: malware triage

```python
import dexllm

dk = dexllm.DexKit("/path/to/suspicious.apk")
dk.warm_analysis_caches()

# 1. What permissions does it actually exercise?
report = dexllm.summarize_capabilities(dk)
for perm, count in report.top_permissions(15):
    print(f"  {count:>4}× {perm}")

# 2. What Intent actions does it construct?
actions = sorted({
    s.args[1].string_value
    for s in dk.resolve_call_args("Landroid/content/Intent;-><init>(Ljava/lang/String;)V")
    if s.args[1].kind == "ConstString"
})
print(f"\n{len(actions)} Intent actions:")
for a in actions:
    print(" ", a)

# 3. Any weak crypto?
ciphers = sorted({
    s.args[0].string_value
    for s in dk.resolve_call_args("Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;")
    if s.args[0].kind == "ConstString"
})
for c in ciphers:
    flag = " ⚠️" if "ECB" in c or "NoPadding" in c else ""
    print(f"  cipher: {c}{flag}")

# 4. Reflection hotspots (Class.forName)
sites = dk.resolve_call_args(
    "Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;"
)
for s in sites[:20]:
    if s.args[0].kind == "ConstString":
        print(f"  Class.forName(\"{s.args[0].string_value}\") @ {s.caller_descriptor}")

# 5. Drill into one suspicious method
print("\n--- decompiled ---")
print(dk.decompile_method(
    "Lcom/example/SuspiciousReceiver;->onReceive(Landroid/content/Context;Landroid/content/Intent;)V"
))
```

---

## Typed SDK — ports & adapters (`dexllm.sdk`)

The calls above return a mix of `str`, `list`, `dict`, and pybind objects. For
embedding dexllm in a larger system, `dexllm.sdk` wraps the same engine in a
**ports-and-adapters** layer: `@runtime_checkable` Protocol *ports* (the use-case
interfaces) and frozen-dataclass *domain models* with an accurate type on every
argument and return value — so callers program against types, not dict keys.

```python
from dexllm.sdk import open_apk, identify, DexAnalysisUseCase

# identify is load-free; open_apk returns a session satisfying DexAnalysisUseCase
info = identify("app.apk")                      # -> ContainerInfo(format, is_apk, has_manifest, dex_count, source)
session: DexAnalysisUseCase = open_apk("app.apk")
# packer/unpack: open_apk([dumped_dex, "app.apk"], lenient=True)  (earlier source wins)

m = session.decompile_method("Lcom/x/Y;->m(I)V")          # -> DecompiledMethod(descriptor, source, found, pc_map)
d = session.decompile_method_with_pc_map("Lcom/x/Y;->m(I)V")  # + pc_map: tuple[SourceLocation(line, byte_offset)]
c = session.decompile_class("Lcom/x/Y;")                  # -> DecompiledClass(descriptor, source)
a = session.decompile_method_ast("Lcom/x/Y;->m(I)V")      # -> MethodAst(name, proto, ast, pc_map, ...)

for cls in session.list_classes():                        # -> tuple[str, ...]
    for meth in session.list_class_methods(cls): ...       # -> tuple[str, ...]
refs = session.list_external_method_refs(framework_only=True)  # -> tuple[ExternalMethodRef, ...]

sites = session.find_call_sites_to("Landroid/util/Log;->d(...)I")     # -> tuple[CallSite, ...] (callee fixed)
callees = session.find_call_sites_from("Lcom/x/Y;->m(I)V")              # -> tuple[CallSite, ...] (caller fixed)
for rc in session.resolve_call_args("...->getInstance(Ljava/lang/String;)..."):
    for arg in rc.args: arg.kind, arg.string_value          # -> ArgOrigin (only the kind's field set)
session.find_methods_reading_field("Lcom/x/Y;->token:Ljava/lang/String;")  # -> methods that iget/sget it
session.find_methods_writing_field("Lcom/x/Y;->token:Ljava/lang/String;")  # -> methods that iput/sput it
session.find_type_references("Lcom/x/Y;")                 # -> TypeReferences(fields, methods_returning, methods_with_param)

info = session.class_info("Lcom/x/Y;")                    # -> ClassInfo(superclass, interfaces, access_flags, ...)
fields = session.class_fields("Lcom/x/Y;")                # -> tuple[FieldInfo(name, type, access_flags)]
methods = session.class_methods("Lcom/x/Y;")              # -> tuple[MethodInfo(name, proto, access_flags)]
# access_flags is None (UNKNOWN) on an external class — see sdk.md / api.md
descs = session.list_class_methods("Lcom/x/Y;")           # -> the descriptor-only view of the same members

for g in session.permission_callers(app_only=True):       # -> tuple[PermissionCallerGroup, ...]
    g.permission, g.protection_level                        # dangerous|signature|internal|normal|other
    for row in g.rows: row.api, row.callers                 # PermissionCallerRow

ioc = session.extract_iocs()                              # -> IocReport; ioc.domains: tuple[Indicator(value, methods, declared_in)]
cap = session.summarize_capabilities()                   # -> CapabilityReport(...); app_only=True by default
prov = session.detect_content_providers()                # -> tuple[ContentProviderUse(uri, family, methods)]

session.raw       # the underlying dexllm.DexKit (escape hatch for L7 search etc.)
```

The models are immutable (frozen; `Mapping` fields are read-only views) — the
value-object models are also hashable, while the two carrying a `Mapping`
(`CapabilityReport`, `MethodAst`) are not. The ports are structural, so
`isinstance(session, DecompilationPort)` works and any object with the same methods
satisfies the contract (test doubles need no base class). Split ports —
`DecompilationPort`, `EnumerationPort`, `DexExtractionPort`, `ClassInspectionPort`,
`CrossReferencePort`, `SearchPort`, `PermissionAnalysisPort`,
`IndicatorExtractionPort`, `CapabilityPort`, `ContentProviderPort`,
`CacheControlPort`, `ContainerProbePort` — let a consumer depend on just the concern it needs. See the [component reference](sdk.md) and the source
[`src/dexllm/sdk/`](../src/dexllm/sdk/) (`model.py` / `ports.py` / `adapter.py`).

---

## Architecture

```
.
├── native/core_ext/   — C++ extension over upstream DexKit (find/match wrappers, ref enumeration)
├── native/dad_cpp/    — DAD-aligned Java decompiler (complete: graph/dataflow/control_flow/writer/dast)
├── native/binding/    — pybind11 module (boundary between C++ and Python)
├── src/dexllm/        — Python facade + descriptor helpers + capability catalog + tools/MCP/FastAPI
└── tests/             — C++ parity suites (tests/parity, ctest) + Python pytest suite
```

Vendored DexKit Core fork lives at `vendor/dexkit_core/`. Public accessors added to upstream's `DexItem` class live in `vendor/dexkit_core/Core/dexkit/{include/dex_item.h,dex_item.cpp}`. The fork stays small and re-rebases easily on upstream updates.

For the ports & adapters boundary see [architecture.md](architecture.md); for the end-to-end runtime flows (load → verify → decompile → agent) as diagrams see [workflow.md](workflow.md).

---

## Performance (representative 50-dex APK)

| Stage | First call | Cached |
|---|---|---|
| Constructor + slicer | 115–145 ms | — |
| `warm_analysis_caches()` | 260–290 ms | < 1 µs (no-op) |
| L1 external refs | 20–60 ms | same |
| L2 call sites (153 k hits) | 80–110 ms | same |
| L3 capability summary | 90–120 ms | same |
| L4 resolve_call_args (2.4 k sites) | 23 ms¹ | same |
| L5 render_class_smali (77 methods) | 0.5 ms | same |
| L6 decompile_method | ~0.06 ms / method (warm) | cached |
| L7 find_classes_by_name | 1–3 ms | same |

¹ Measured before `resolve_call_args` became join-aware (dexllm#16). That change runs
the register simulation twice and copies the register file at each forward branch, and
costs **2.6–3.3×** the previous scan — measured on the bundled corpus at 2,407 sites
2.1 ms → 6.3 ms and 3,534 sites 3.1 ms → 10.2 ms. Absolute cost stays in the
single-digit-milliseconds range; the row above has not been re-measured on the
original 50-dex APK.

Python ↔ C++ marshalling overhead stays under 1 ms per call.

<a name="performance"></a>
### vs androguard (decompile, Telegram 12.7.3 — 39,146 classes)

| | dexllm (C++) | androguard (Python) |
|---|---|---|
| APK load (incl. structural verification) | **~120 ms** | 28.8 s |
| Full decompile (1 thread) | **54 s** | impractical |
| Full decompile (parallel) | **18.5 s** (GIL released) | — (GIL-bound) |
| Peak RSS | **523 MB** | — |
| Crashes | 0 | — |

Per-method decompile is ~4.5× faster than androguard; APK load is ~100× faster (lazy slicer parse + load-time structural verification), and the gap grows with APK size — this 39k-class app loads ~240× faster than androguard's 28.8 s. On this heavy app the parallel decompile speedup is ~3× — returning hundreds of MB of decompiled text is GIL-bound, so small/medium APKs scale higher (~10× on tvleanback). Search (L1–L7) is 3–6× faster than androguard's scan.

Reproduce the androguard comparison on any APK: [`bench/bench_vs_androguard.py`](../bench/bench_vs_androguard.py) (`pip install -e ".[dev]"`, then `python bench/bench_vs_androguard.py app.apk`). It prints a paste-ready table of load / decompile / search timings plus byte-parity.

---

## Licence

- This wrapper (everything in this repo): **Apache 2.0**
- Upstream LuckyPray DexKit (linked statically): **LGPLv3**
- DAD algorithm references (androguard): **Apache 2.0**

When distributing, ensure LGPL compliance for the linked `dexkit_static` library.
