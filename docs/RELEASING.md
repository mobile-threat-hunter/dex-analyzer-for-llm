# Releasing — pre-built wheels on this repo's Releases

dexllm ships **pre-built platform wheels** so users `pip install` without a C++
toolchain. A version tag triggers CI to build the wheels and attach them to this
repo's GitHub **Releases**.

```
push tag vX.Y.Z → .github/workflows/release.yml
   guard (tag == pyproject version)
   → wheels  (Linux manylinux_2_28 x86_64, macOS x86_64+arm64, cp39–cp313)  +  sdist
   → publish (gh release create on THIS repo, auth: built-in GITHUB_TOKEN)
```

No tokens or extra setup: the publish job uses the workflow's built-in
`GITHUB_TOKEN` with `contents: write`, since releases now live in the same repo.

## Cutting a release

1. **Bump the version** in [pyproject.toml](../pyproject.toml) `[project] version`
   **and** [src/dexllm/__init__.py](../src/dexllm/__init__.py) `__version__` (the
   `guard` job fails if the tag and pyproject version don't match).
2. Commit, then tag and push:
   ```bash
   git commit -am "release: vX.Y.Z"
   git tag vX.Y.Z
   git push origin master vX.Y.Z      # DOCS_CHECKED=1 if the docs gate blocks
   ```
3. The `release` workflow runs: `guard` → `wheels` (Linux + macOS) + `sdist` →
   `publish` (uploads every wheel + the sdist to the `vX.Y.Z` Release).
   Re-running re-uploads with `--clobber`.

`workflow_dispatch` (Actions tab → release → Run workflow) rebuilds an existing
tag without re-pushing.

## Installing (what users do)

```bash
pip install dexllm --find-links https://github.com/mobile-threat-hunter/dex-analyzer-for-llm/releases/expanded_assets/vX.Y.Z
```

`pip` picks the wheel matching the platform/Python. LLM backends:
`pip install "dexllm[all]" --find-links <same-url>`. Or grab a specific `.whl`
from the [Releases page](https://github.com/mobile-threat-hunter/dex-analyzer-for-llm/releases)
and `pip install ./that-file.whl`.

## Build matrix & scope

Defined in [pyproject.toml](../pyproject.toml) `[tool.cibuildwheel]`:

- **Linux**: `manylinux_2_28` x86_64 (GCC 12 — the C++20 core needs a modern
  compiler; the default manylinux2014/GCC 10 is too old). `zlib-devel` installed
  in `before-all`; `auditwheel` bundles `libz` (the only non-baseline dep).
- **macOS**: x86_64 + arm64, `MACOSX_DEPLOYMENT_TARGET=13.3` (dad_cpp/dast.cpp uses
  `std::to_chars` for float/double, whose libc++ symbol needs macOS 13.3+).
- **CPython** 3.9–3.13. musllinux + PyPy skipped.
- **Windows** is intentionally absent — the build is only validated on Linux/macOS
  (CI). Adding it needs MSVC/C++20 portability work on the vendored slicer first.

Each wheel is smoke-tested in CI (`test-command`: import + `identify()`); the full
parity/sweep gates stay in [ci.yml](../.github/workflows/ci.yml) (they need the
gitignored APK corpus).
