# Examples

Runnable usage examples for `dexllm`. Each takes a path as an argument — a zip
container (`.apk`/`.jar`/`.zip`) or a bare `.dex` file — or falls back to
`$DEXLLM_TEST_APK`, or the first APK under `../test_apk/APK/`.

```bash
pip install -e ..            # if not already installed

python examples/01_overview.py     /path/to/app.apk   # scale + external APIs + capabilities
python examples/02_decompile.py    /path/to/app.apk   # method/class → Java, smali, AST
python examples/03_search.py       /path/to/app.apk   # find by name / string / API call-site
python examples/04_decompile_dex.py classes.dex       # decompile straight from a bare .dex
```

| Script | Shows |
|---|---|
| `01_overview.py` | load, class/method counts, `list_external_method_refs`, `summarize_capabilities` |
| `02_decompile.py` | `decompile_method_java` / `decompile_class_java` / `decompile_method_ast` / `render_method_smali` |
| `03_search.py` | `find_classes_by_name` / `find_methods_using_strings` / `find_call_sites_to_api` / `resolve_call_args` |
| `04_decompile_dex.py` | loading a **bare `.dex`** (no zip) and decompiling a class from it |

For the LLM backends, see the top-level [README](../README.md):
`python -m dexllm.mcp_server` (MCP) and `uvicorn dexllm.server:app` (FastAPI/SSE).
