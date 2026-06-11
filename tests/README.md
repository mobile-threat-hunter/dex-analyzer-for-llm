# Tests

Three layers, from self-contained to integration.

## 1. C++ parity suites — primary regression gate (no APK needed)

25 standalone executables under [`parity/`](parity/), each a function-by-function
check against androguard DAD on synthetic bytecode. This is the gate that must stay
green for any decompiler change.

```bash
cd ../build/cp*-cp*-*        # scikit-build-core's platform build dir (linux/macos)
ninja parity_tests
ctest --output-on-failure        # expect: 100% tests passed, 0 failed out of 25
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

## 3. Standalone integration / parity scripts

- [`llm_backend_integration.py`](llm_backend_integration.py) — end-to-end check of
  `tools.py`, `mcp_server.py`, and the FastAPI `server.py` (the live `/analyze`
  agent step runs only if `ANTHROPIC_API_KEY` is set). Needs the `[all]` extra.
  ```bash
  python llm_backend_integration.py
  ```
- [`dvclass_parity.py`](dvclass_parity.py) — class-level decompile parity vs
  androguard across the APK corpus (heavy; needs `[dev]` + `test_apk/`).

## What each layer guards

| Layer | Needs APK | Needs androguard | Guards |
|---|---|---|---|
| C++ parity (ctest) | no | no (golden baked in) | IR / decompiler correctness, 0-crash |
| pytest | optional (skips) | no | Python API surface, AST shape, regressions |
| integration scripts | yes | yes | LLM backends, corpus-wide parity |
