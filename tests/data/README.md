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

`multidex.apk` is deliberately the WORST case, not a convenient one: it is the
sample that produced 17 of the failures in dexllm#46 (no `switch` header, no
boolean-literal assignment, no constant-only indicator, no interface method, no
control-bearing literal, and — being manifest-less — `identify().is_apk == False`).
A suite that stays green on it is a suite whose floors skip instead of failing.

The narrowed leg reaches **254** tests in CI where the corpus-less run reaches
111 (260 / 114 locally, where the optional `mcp` / `fastapi` / dev extras are
installed), so it also adds real coverage where CI had none.

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

## Provenance

`multidex.apk` is byte-identical (md5 `627622df6a7557fd0b85fdde6fccb7ad`) to
[androguard](https://github.com/androguard/androguard)'s own test data,
`tests/data/APK/multidex.apk`, which is also where `test_apk/`'s corpus comes
from. androguard is licensed **Apache-2.0**, the same licence as this project.

`invoke-custom.dex` is byte-identical (md5 `3cbe61c0d2eb9ae9df5e05013b3ba119`) to
AOSP's `art/test/dexdump/invoke-custom.dex` — dexdump's own regression input,
also **Apache-2.0**. This repo already uses that directory as a spec reference
(`multidex-container.dex` for the v41 container work); this is the first file
copied from it. See [LICENSE](../../LICENSE).
