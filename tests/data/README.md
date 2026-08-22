# tests/data — the one committed sample

The regression corpus lives in `test_apk/`, which is **gitignored** (binary APKs,
fetched separately). CI therefore has no APK and every corpus-dependent test
skips there. That leaves one thing unguarded: the rule that a
**`$DEXLLM_TEST_APK` narrowing must SKIP, never fail** (dexllm#46). The
corpus-less run cannot catch a regression of it — it skips at the fixtures,
before a single non-vacuity floor is reached — so CI runs the suite once more,
narrowed to the sample here.

| file | size | what it is |
|---|---|---|
| `multidex.apk` | 1,233 B | 2 dexes, 2 classes, no `AndroidManifest.xml` |
| `invoke-custom.dex` | 31,732 B | 29 `method_handle_item`s, `invoke-custom`, annotations |
| `method_handles.dex` | 28,228 B | 16 `invoke-polymorphic` sites, all in ONE of its 24 classes |
| `invoke-polymorphic.dex` | 1,160 B | 1 `invoke-polymorphic/range` (7 registers) + 2 `invoke-polymorphic` |
| `const-method-handle.dex` | 2,524 B | the only `const-method-type` anywhere in reach |
| `multidex-container.dex` | 1,468 B | the only **v41 CONTAINER** in reach — 2 slices sharing one data section |

`multidex.apk` is deliberately the WORST case, not a convenient one: it is the
sample that produced 17 of the failures in dexllm#46 (no `switch` header, no
boolean-literal assignment, no constant-only indicator, no interface method, no
control-bearing literal, and — being manifest-less — `identify().is_apk == False`).
A suite that stays green on it is a suite whose floors skip instead of failing.

The narrowed leg reaches **254** tests in CI where the corpus-less run reaches
111 (260 / 114 locally, where the optional `mcp` / `fastapi` / dev extras are
installed), so it also adds real coverage where CI had none.

`multidex-container.dex` is here because the v41 CONTAINER format is where the
verifier's span rule stops being per-dex: `ComputeDataRange` gives every slice the
whole container, since siblings SHARE a data section (this file's slice 0 has
`file_size` 564 and `string_ids_off` 684 — outside its own file_size, and legally
so). dexllm#59 walks the method_handle section's contents, and a first cut bounded
that walk by the slice's own `file_size / 8`; a reviewer took THIS file, appended a
shared section and nothing else, and found the crossover was exactly that bound —
70 entries accepted, 71 rejected, and the sibling rule then took the whole
container down. The fix that replaced it rejects nothing, and the guard that pins
it needs a genuine v41 container: a faked one (a v038 dex with `header_size`
patched to 120) overwrites the bytes after the header, so it can pin the REJECT
direction but never the ACCEPT one.

`invoke-custom.dex` is here for a different reason: it carries a **method_handle
section**, and *nothing* in the gitignored corpus does (0 of its 36 dexes). Two
properties can only be tested with one:

* the SUCCESS path of dexllm#57 — a `0x16 METHOD_HANDLE` `encoded_value` whose
  index actually resolves, i.e. what makes a real API-26+ dex load rather than
  throw. Every craft on a section-less dex exercises only the out-of-range throw.
* the dexllm#57-review CRITICAL — an inflated `method_handle` map count made
  `ArrayView`'s bound useless and read ~134 MB past the file (SIGSEGV on a
  `verify()`-valid dex). Crafting that needs a section to inflate.

Both guards craft it IN PLACE and length-preservingly, so the committed bytes are
never the thing under test — the file is the only available *carrier* of a
method_handle section.

`method_handles.dex` is here for the third variant of the same reason, and it is
used UNMODIFIED rather than crafted. dexllm#61 taught four separate gates that
`invoke-polymorphic` (0xFA/0xFB) carries a method reference; the committed
`invoke-custom.dex` does have two such sites, but in blocks that also contain an
ordinary invoke — so reverting the CFG "this block needs the extractor" mark is
**masked** there (measured: `resolve_call_args` stays at 2). On this file the same
revert takes it from 10 to **0**, which is the only behavioural evidence that gate
is load-bearing. The gitignored corpus has 0 `invoke-polymorphic` sites, so nothing
in it can substitute.

Its 16 sites are **all in `Lcom/code_intelligence/jazzer/api/Jazzer;`** (10
`autofuzz` overloads, one site each at offset 0x4), so it is a weaker fixture for
anything block- or class-structural than a raw site count suggests — and every one
of them is arity 3. That is why the third file is here.

`invoke-polymorphic.dex` carries the half nothing else does. Both reviews of
dexllm#61 found independently that **0xFB (`invoke-polymorphic/range`) had zero
behavioural coverage anywhere in the repo** — not in the other two fixtures, not in
the corpus, and not in dexllm#58's verifier guard, which is 0xFA-only. Two mutants
survived the whole suite because of it: moving `case 0xFB` into the 45cc arm (the
source guard sees the arms' union), and excluding 0xFB with a negated clause while
leaving its `op == 0xfb` literal in place. This file kills both — its single range
site has a **7-register window** that the arm swap collapses to empty. It also
carries the only 45cc with **A=5**, i.e. the only one where the G nibble is a real
argument rather than padding.

`const-method-handle.dex` is here for dexllm#66, which taught `emit_index` five
index kinds that used to render a bare `@N`. Three of them had a carrier already
(`invoke-custom.dex` has 46 `invoke-custom`, `method_handles.dex` has 2
`const-method-handle`); **`const-method-type` (0xFF, `kIndexProtoRef`) had none** —
0 sites across the gitignored corpus, the other three fixtures and `multidex.apk`.
It is also the one kind that is fully RESOLVED rather than labelled, so without a
carrier the difference between resolving the proto and printing another label was
unobservable. Used UNMODIFIED.

Note what it does NOT close, checked rather than assumed: dexllm#60 records a
mutant it could not kill — taking a polymorphic call's return type from the
signature-polymorphic DECLARATION instead of the call site — and says it needs "a
fixture with a live, non-`Object`, non-void polymorphic result". This file has
exactly that shape (`(Ljava/lang/Object;)Ljava/lang/Class;` followed by
`move-result-object`), and it still does not kill the mutant: `RegisterPropagation`
inlines the result straight into a `StringBuilder.append(Object)` argument, so the
type never reaches a declaration and both return types render identically. The gap
stands.

## Provenance

`multidex.apk` is byte-identical (md5 `627622df6a7557fd0b85fdde6fccb7ad`) to
[androguard](https://github.com/androguard/androguard)'s own test data,
`tests/data/APK/multidex.apk`, which is also where `test_apk/`'s corpus comes
from. androguard is licensed **Apache-2.0**, the same licence as this project.

`invoke-custom.dex` is byte-identical (md5 `3cbe61c0d2eb9ae9df5e05013b3ba119`) to
AOSP's `art/test/dexdump/invoke-custom.dex` — dexdump's own regression input,
also **Apache-2.0**. This repo already used that directory as a
spec reference (`multidex-container.dex` for the v41 container work) before
copying anything out of it; this was the first.

`method_handles.dex` is byte-identical (md5 `b7b3414ac12878c016e0e2fa9c921c47`) to
AOSP's `tools/dexter/testdata/method_handles.dex` — dexter's own test input, also
**Apache-2.0**.

`multidex-container.dex` is byte-identical (md5 `c6621661ee9ef06c9af6aab68d5d9230`) to AOSP's
`art/test/dexdump/multidex-container.dex`, from the same directory and also
**Apache-2.0** — the file this repo had already been using as its v41 spec
reference from outside the tree, now committed so the guard that needs it runs in
CI.

`invoke-polymorphic.dex` is byte-identical (md5 `fd1f7a6de8a8b3ddd498264c411fedac`)
to AOSP's `art/test/dexdump/invoke-polymorphic.dex`. `const-method-handle.dex` is
byte-identical (md5 `8d5213617dd2b2a0f746be290312bc99`) to AOSP's
`art/test/dexdump/const-method-handle.dex`, from the same directory and also
**Apache-2.0**. Note that dexter ships a file
of the same name which is NOT usable here — it fails this repo's verifier with
`code: outs_size > registers_size`. See [LICENSE](../../LICENSE).
