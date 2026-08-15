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

`multidex.apk` is deliberately the WORST case, not a convenient one: it is the
sample that produced 17 of the failures in dexllm#46 (no `switch` header, no
boolean-literal assignment, no constant-only indicator, no interface method, no
control-bearing literal, and — being manifest-less — `identify().is_apk == False`).
A suite that stays green on it is a suite whose floors skip instead of failing.

The narrowed leg reaches **254** tests in CI where the corpus-less run reaches
111 (260 / 114 locally, where the optional `mcp` / `fastapi` / dev extras are
installed), so it also adds real coverage where CI had none.

## Provenance

Taken byte-identical (md5 `627622df6a7557fd0b85fdde6fccb7ad`) from
[androguard](https://github.com/androguard/androguard)'s own test data,
`tests/data/APK/multidex.apk`, which is also where `test_apk/`'s corpus comes
from. androguard is licensed **Apache-2.0**, the same licence as this project;
see [LICENSE](../../LICENSE).
