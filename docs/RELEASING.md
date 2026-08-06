# Releasing — pre-built wheels on PyPI and this repo's Releases

dexllm ships **pre-built platform wheels** so users `pip install` without a C++
toolchain. A version tag triggers CI to build the wheels and ship them to two
places: **PyPI** (the normal install path) and this repo's GitHub **Releases**
(mirror / direct `.whl` download).

```
push tag vX.Y.Z → .github/workflows/release.yml
   guard (tag == pyproject version)
   → wheels  (Linux manylinux_2_28 x86_64, macOS x86_64+arm64, cp39–cp313)  +  sdist
   → publish (gh release create on THIS repo, auth: built-in GITHUB_TOKEN)
     pypi    (pypa/gh-action-pypi-publish,  auth: PYPI_API_TOKEN secret)
```

`publish` needs no setup — it uses the workflow's built-in `GITHUB_TOKEN` with
`contents: write`, since releases live in the same repo. `pypi` needs the
one-time token setup below.

## One-time PyPI setup

1. **Create the API token** at <https://pypi.org/manage/account/token/>. Until
   `dexllm` exists on PyPI there is no project to scope to, so the first token
   must be **account-scoped** ("Entire account"). The value starts with `pypi-`
   and is shown exactly once.
2. **Store it as a repo secret** named `PYPI_API_TOKEN`:
   ```bash
   gh secret set PYPI_API_TOKEN --repo mobile-threat-hunter/dex-analyzer-for-llm
   # paste the pypi-... value at the prompt, then Ctrl-D
   ```
   (Or Settings → Secrets and variables → Actions → New repository secret.)
3. **After the first successful release**, replace it with a token scoped to the
   `dexllm` project only, and delete the account-scoped one — same
   `gh secret set` command overwrites in place.

Optional hardening: Settings → Environments → `pypi` → **Required reviewers**
makes every PyPI upload wait for a manual approval. PyPI uploads are
irreversible (a version can be yanked but never re-uploaded), so this is worth
turning on if releases are ever cut by automation.

> Alternative: PyPI **Trusted Publishing** (OIDC) removes the long-lived token
> entirely. It needs a "pending publisher" registered on PyPI for
> owner `mobile-threat-hunter` / repo `dex-analyzer-for-llm` / workflow
> `release.yml` / environment `pypi`, plus `permissions: id-token: write` on the
> `pypi` job and dropping the `password:` line. Worth switching to once the
> token flow is proven.

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
   `publish` (uploads every wheel + the sdist to the `vX.Y.Z` Release) **and**
   `pypi` (uploads the same set to PyPI). Re-running re-uploads to the Release
   with `--clobber`; PyPI is `skip-existing`, so an already-published version is
   left alone rather than failing the run.

`workflow_dispatch` (Actions tab → release → Run workflow) rebuilds an existing
tag without re-pushing.

## Installing (what users do)

```bash
pip install dexllm
pip install "dexllm[all]"    # + MCP server + FastAPI backend
pip install -U dexllm        # upgrade — plain `install` no-ops if dexllm is present
```

`pip` picks the wheel matching the platform/Python from PyPI. The GitHub Release
remains a mirror — grab a specific `.whl` from the
[Releases page](https://github.com/mobile-threat-hunter/dex-analyzer-for-llm/releases)
and `pip install ./that-file.whl`.

Pinning takes a version specifier, **not** `--find-links`: that flag adds a source
alongside PyPI instead of replacing it, so `pip install dexllm --find-links <v0.8.1
assets>` resolves to the newest version on PyPI, not to 0.8.1. Use
`pip install "dexllm==0.8.1" --find-links <v0.8.1 assets>` (the `--find-links` is
needed only for ≤0.8.1, which predate PyPI), or add `--no-index` to cut PyPI out
entirely.

### Platforms with no wheel

The sdist is on PyPI too, so an unmatched platform (Windows, musllinux, PyPy,
Linux aarch64, CPython 3.14+) falls back to **building from source** — which
needs a C++20 toolchain and, on Windows, is not yet supported at all. Those users
see a compiler error rather than a clean "no distribution" message. If that
becomes a support burden, either narrow `requires-python` in `pyproject.toml` or
drop the sdist from the `pypi` job's upload set.

## Build matrix & scope

Defined in [pyproject.toml](../pyproject.toml) `[tool.cibuildwheel]`:

- **Linux**: `manylinux_2_28` x86_64 (GCC 12 — the C++20 core needs a modern
  compiler; the default manylinux2014/GCC 10 is too old). `zlib-devel` installed
  in `before-all`; `auditwheel` bundles `libz` (the only non-baseline dep).
- **macOS**: x86_64 + arm64, `MACOSX_DEPLOYMENT_TARGET=13.3` (dad_cpp/dast.cpp uses
  `std::to_chars` for float/double, whose libc++ symbol needs macOS 13.3+).
- **CPython** 3.9–3.13. musllinux + PyPy skipped.
- **Windows** is not yet shipped — the build is currently validated on Linux/macOS
  (CI). The stack is mostly portable already (the slicer has no POSIX deps, a
  `mmap_windows.h` shim exists); the scoped change set, zlib decision, CI design, and
  MSVC C++20 risks are in [windows-port-plan.md](windows-port-plan.md).

Each wheel is smoke-tested in CI (`test-command`: import + `identify()`); the full
parity/sweep gates stay in [ci.yml](../.github/workflows/ci.yml) (they need the
gitignored APK corpus).
