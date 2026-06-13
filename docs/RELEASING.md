# Releasing — private source, public pre-built wheels

dexllm ships **pre-built platform wheels** so users `pip install` without a C++
toolchain. This repo (the source) stays **private**; wheels are published to a
**separate public repo's Releases**. CI builds them; a cross-repo token uploads.

```
mobile-threat-hunter/dex-analyzer-for-llm   (PRIVATE)  ── source + CI
        │  push tag vX.Y.Z → .github/workflows/release.yml
        │  cibuildwheel (Linux manylinux_2_28 x86_64, macOS x86_64+arm64, cp39–cp313)
        ▼  gh release create  (auth: RELEASE_REPO_TOKEN)
mobile-threat-hunter/dexllm-releases        (PUBLIC)   ── Releases only (wheels + sdist)
```

## One-time setup

1. **Create the public release repo** — e.g. `mobile-threat-hunter/dexllm-releases`,
   visibility **Public**. It holds only Releases (no source). A short README that
   points at the latest release is enough.

2. **Create a scoped token** — GitHub → Settings → Developer settings →
   **Fine-grained personal access token**:
   - *Repository access*: **Only select repositories** → the public release repo.
   - *Permissions*: **Contents → Read and write** (nothing else).
   - Copy the token.

3. **Add the token to THIS (private) repo** — Settings → Secrets and variables →
   Actions → New repository secret → name `RELEASE_REPO_TOKEN`, value = the token.

4. **Point the workflow at the public repo** — edit `PUBLIC_RELEASE_REPO` at the
   top of [.github/workflows/release.yml](../.github/workflows/release.yml) if the
   name differs from the default.

> Why a separate token (not the built-in `GITHUB_TOKEN`)? `GITHUB_TOKEN` only has
> rights to *this* repo. Publishing into a *different* repo needs a token that
> carries write access there — hence the scoped PAT.

## Cutting a release

1. **Bump the version** in [pyproject.toml](../pyproject.toml) `[project] version`
   (the workflow's `guard` job fails if the tag and this don't match).
2. Commit it, then tag and push:
   ```bash
   git commit -am "release: vX.Y.Z"
   git tag vX.Y.Z
   git push origin master vX.Y.Z      # DOCS_CHECKED=1 if the docs gate blocks
   ```
3. The `release` workflow runs: `guard` → `wheels` (Linux + macOS) + `sdist` →
   `publish` (uploads every wheel + the sdist to the public repo's `vX.Y.Z`
   Release). Re-running the workflow re-uploads with `--clobber`.

`workflow_dispatch` (Actions tab → release → Run workflow) rebuilds an existing
tag without re-pushing.

## Installing (what users do)

```bash
# from the public Releases page, or directly:
pip install https://github.com/mobile-threat-hunter/dexllm-releases/releases/download/vX.Y.Z/dexllm-X.Y.Z-cp313-cp313-manylinux_2_28_x86_64.whl
```

LLM backends still need the extras: `pip install "dexllm[all] @ <wheel-url>"`.

## Build matrix & scope

Defined in [pyproject.toml](../pyproject.toml) `[tool.cibuildwheel]`:

- **Linux**: `manylinux_2_28` x86_64 (GCC 12 — the C++20 core needs a modern
  compiler; the default manylinux2014/GCC 10 is too old). `zlib-devel` installed
  in `before-all`; `auditwheel` bundles `libz` (the only non-baseline dep).
- **macOS**: x86_64 + arm64 (`MACOSX_DEPLOYMENT_TARGET=11.0`).
- **CPython** 3.9–3.13. musllinux + PyPy skipped.
- **Windows** is intentionally absent — the build has only been validated on
  Linux/macOS (CI). Adding it needs MSVC/C++20 portability work on the vendored
  slicer first.

Each wheel is smoke-tested in CI (`test-command`: import + `identify()`); the
full parity/sweep gates stay in [ci.yml](../.github/workflows/ci.yml) (they need
the gitignored APK corpus).
