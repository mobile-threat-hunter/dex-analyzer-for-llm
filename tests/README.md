# Tests

Three layers, from self-contained to integration.

## 1. C++ parity suites — primary regression gate (no APK needed)

28 standalone executables under [`parity/`](parity/), each a function-by-function
check against androguard DAD on synthetic bytecode. This is the gate that must stay
green for any decompiler change.

```bash
cd ../build/cp*-cp*-*        # scikit-build-core's platform build dir (linux/macos)
ninja parity_tests
ctest --output-on-failure        # expect: 100% tests passed, 0 failed out of 28
```

## 2. Python suite (pytest)

[`test_dexkit.py`](test_dexkit.py) — import / tools-catalog tests always run;
decompile / AST / search / external-ref / "no Python-literal leak" tests use a
test APK and **skip** if none is found.

```bash
pip install -e "..[dev]"          # pytest + androguard
# APK resolution: $DEXLLM_TEST_APK, else any test_apk/APK/*.apk
DEXLLM_TEST_APK=/path/to/app.apk pytest . -v
```

### Narrowing the corpus to one sample

`$DEXLLM_TEST_APK` points the whole suite at a single APK — what an analyst wants
while triaging one sample. A dozen guards assert that a production pass ACTUALLY
FIRED (a `switch` header carrying a pc-map entry, a `boolean v = false;`, a
constant-only IOC), and a small sample carries none of those shapes. The rule,
implemented once in `conftest.require_corpus_shape` and pinned by
[`test_corpus_shape_helper.py`](test_corpus_shape_helper.py): a missing shape on
the **bundled** corpus is a regression and FAILS; the same absence under a
narrowing is a property of the chosen sample and SKIPS. An environment fact must
never turn the suite red (dexllm#46).

[`test_llm_backends.py`](test_llm_backends.py) — the end-to-end check of
`tools.py`, `mcp_server.py`, and the FastAPI `server.py`; the only automated
coverage of the latter two. Every dependency is a **skip**: no corpus, no `mcp`
extra, no `fastapi` extra, and the live `/analyze` agent step without
`ANTHROPIC_API_KEY`. It ran as a standalone script named
`llm_backend_integration.py` until dexllm#40 — outside pytest's `test_*.py`
pattern, so it was never collected and rotted unnoticed;
[`test_harness_hygiene.py`](test_harness_hygiene.py) now fails if any module
here defines tests pytest cannot collect.

## 3. Standalone parity scripts

- [`dvclass_parity.py`](dvclass_parity.py) — class-level decompile parity vs
  androguard across the APK corpus (heavy; needs `[dev]` + `test_apk/`).

## What each layer guards

| Layer | Needs APK | Needs androguard | Guards |
|---|---|---|---|
| C++ parity (ctest) | no | no (golden baked in) | IR / decompiler correctness, 0-crash |
| pytest | optional (skips) | no | Python API surface, AST shape, regressions |
| parity scripts | yes | yes | corpus-wide decompile parity |
