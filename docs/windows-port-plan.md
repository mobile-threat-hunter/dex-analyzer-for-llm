# Windows port plan (analysis only — not yet implemented)

**Status: PLAN. No code changed yet.** dexllm currently ships Linux + macOS
wheels; Windows is unsupported. This document scopes the exact changes, the zlib
decision, the CI design, and the MSVC C++20 risks that can only surface on a
Windows runner.

> **Validation reality:** the dev workstation is Linux with no MSVC, so none of
> these changes can be built/tested locally. Every change is a hypothesis until a
> GitHub Actions `windows-latest` job validates it — implementation will be a
> push → CI → fix loop over several rounds. Recommended vehicle: a
> `windows-support` branch + PR, master untouched until CI is green.

---

## 1. Portability assessment — most of the stack is already portable

| Component | Windows status |
|---|---|
| Slicer (AOSP ART–derived, `Core/third_party/slicer/`) | ✅ **zero POSIX deps** (verified: no `unistd.h`/`mmap`/`sys/*`/endian) |
| third_party flatbuffers, parallel_hashmap | ✅ already cross-platform (carry their own `_WIN32` paths) |
| `mmap_windows.h` | ✅ full `mmap`/`munmap` shim (CreateFileMapping/MapViewOfFile) already vendored |
| `zip_archive.h` | ✅ already has a `_WIN32` branch (line 261) |
| Our `native/` code (core_ext + dad_cpp + binding) | ✅ no MSVC-hostile constructs (`__attribute__` / `__builtin_` / `<codecvt>` / `<unistd.h>` — none) |
| pybind11, scikit-build-core | ✅ first-class Windows support |

So the work is **build configuration + a handful of guards**, not a rewrite.

---

## 2. Block-by-block change proposals

### B1 — `mmap.h` unconditional `<unistd.h>` (the one hard source blocker)

[vendor/dexkit_core/Core/dexkit/include/mmap.h](../vendor/dexkit_core/Core/dexkit/include/mmap.h)
includes `<unistd.h>` **unconditionally** (top of file), then separately includes
`<mmap_windows.h>` inside a `_WIN32` branch. MSVC has no `<unistd.h>`, so this is a
hard compile break. The Windows branch already uses `_wopen`/`O_BINARY` from
`<io.h>` (pulled by `mmap_windows.h`), so `<unistd.h>` is only needed on POSIX.

**Change (vendored fork — stays small, per CLAUDE.md fork policy):**
```cpp
#if defined(_WIN32) || defined(WIN32)
#include <mmap_windows.h>
#include <codecvt>
#include <locale>
#else
#include <unistd.h>          // move here — POSIX-only
#include <sys/mman.h>
#endif
```
Also confirm the Windows branch's `<codecvt>` + `std::wstring_convert` (lines
30/70–72) compiles under MSVC C++20 — it is *deprecated*, needs the silence macro
(see B2). `_wopen`/`fstat`/`O_BINARY` are MSVC-available via `<io.h>`/`<sys/stat.h>`.

> **Open question — MSVC vs MinGW.** The Windows path here (`_wopen`, `<codecvt>`)
> reads as written/tested for **MinGW** (which *has* `<unistd.h>`, hiding the bug
> above). cibuildwheel's Windows image defaults to **MSVC**. The plan targets MSVC
> (the standard wheel toolchain); if MSVC C++20 conformance fights us in the core,
> the fallback is MinGW via a cibuildwheel toolchain override — noted in §5.

### B2 — top `CMakeLists.txt`: compiler-flag portability

[CMakeLists.txt:70](../CMakeLists.txt) applies `-Werror=narrowing` to our targets —
a GCC/Clang flag MSVC's `cl.exe` rejects. And MSVC needs several flags our code
implicitly relies on.

```cmake
foreach(t dexkit_ext dexkit_dad _dexkit_core)
    if(MSVC)
        target_compile_options(${t} PRIVATE /utf-8 /bigobj /EHsc)
        target_compile_definitions(${t} PRIVATE
            NOMINMAX _CRT_SECURE_NO_WARNINGS
            _SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING)
    else()
        target_compile_options(${t} PRIVATE -Werror=narrowing)
    endif()
endforeach()
```
Rationale, each grounded in this codebase:
- **`NOMINMAX`** — `mmap.h` pulls `<windows.h>`, whose `min`/`max` macros break the
  `std::min`/`std::max` used in `dexitem_code_source.cpp` (×4), `control_flow.cpp`
  (×3), `dataflow.cpp`, `basic_blocks.cpp`. **Required.**
- **`/bigobj`** — `instruction.cpp` (1656 lines), `opcode_ins.cpp` (1183) and the
  visitor-table TUs exceed MSVC's default object section limit. **Required.**
- **`/utf-8`** — source/test files contain UTF-8 string literals; MSVC otherwise
  assumes the system codepage. **Required.**
- **`/EHsc`** — standard C++ exception model (the pipeline throws `std::runtime_error`).
- **`_SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING`** — `mmap.h` uses
  `<codecvt>`; MSVC C++20 errors on it without this.
- **`_CRT_SECURE_NO_WARNINGS`** — quiets MSVC CRT deprecations (`fopen` etc.).

These must also reach the **vendored Core** target (`dexkit_static`) — likely add
the same MSVC block in `vendor/dexkit_core/Core/CMakeLists.txt`, since flatbuffers
codegen and the slicer compile there. (Confirm in CI; the vendored CMake currently
sets no platform flags.)

### B3 — zlib on Windows (the main provisioning task)

`mmap.h` / `zip_archive` `#include <zlib.h>` and link `libz`. Linux/macOS have it
system-wide (cibuildwheel installs `zlib-devel` in `before-all`); Windows has none,
and neither our top CMake nor the vendored Core does an explicit
`find_package(ZLIB)`.

| Option | How | Pros | Cons | Pick |
|---|---|---|---|---|
| **vcpkg** | `vcpkg install zlib:x64-windows`, `-DCMAKE_TOOLCHAIN_FILE=...vcpkg.cmake` in `CIBW_ENVIRONMENT_WINDOWS` | clean `find_package(ZLIB)`, prebuilt, cached on the runner | adds a build dep, DLL must be bundled by delvewheel | **recommended** |
| CMake `FetchContent(zlib)` | build zlib from source in-tree, static | self-contained, no external dep, static link (no DLL to bundle) | longer builds, must wire `ZLIB::ZLIB` for the vendored Core | strong alt |
| Prebuilt zlib zip | download a release, set `ZLIB_ROOT` | simple | unpinned/opaque source, supply-chain smell | no |

**Recommendation: vcpkg** for the first pass (least CMake surgery — drop in
`find_package(ZLIB REQUIRED)` + `target_link_libraries(... ZLIB::ZLIB)` where the
core links `z`), with **static FetchContent as the fallback** if DLL bundling via
delvewheel proves fiddly. Either way add an explicit `find_package(ZLIB)` so the
dependency is declared, not implicit.

### B4 — `pyproject.toml` cibuildwheel: add Windows

```toml
[tool.cibuildwheel]
build = "cp39-* cp310-* cp311-* cp312-* cp313-*"
skip = "*-musllinux* pp*"
# portable smoke test — /etc/hostname does not exist on Windows (see B6)
test-command = 'python -c "import dexllm, sys; print(dexllm.__version__); dexllm.identify(sys.executable)"'

[tool.cibuildwheel.windows]
archs = ["AMD64"]
before-all = "vcpkg install zlib:x64-windows"     # or FetchContent (B3)
environment = { CMAKE_TOOLCHAIN_FILE = "C:/vcpkg/scripts/buildsystems/vcpkg.cmake" }
# bundle the zlib DLL into the wheel
repair-wheel-command = "delvewheel repair -w {dest_dir} {wheel}"
```
(`delvewheel` added to the build env. ARM64-Windows deferred — x64 first.)

### B5 — `.github/workflows/ci.yml`: add a Windows test job

Matrix currently `os: [ubuntu-latest, macos-latest]`. Add `windows-latest`
(py 3.11 + 3.13). This is the **primary validation loop** — it builds + imports +
runs the smoke/identify path on every push to the branch. The C++ ctest parity
suites should also build/run on Windows (they're pure C++ + `MockCodeSource`, no APK
needed) — a strong Windows correctness signal.

### B6 — portable smoke test

`test-command` uses `/etc/hostname` (Linux-only). Replace with `sys.executable`
(exists on every platform) so the post-build `identify()` probe runs everywhere.
Same edit in `pyproject.toml` and any CI inline smoke.

---

## 3. Expected MSVC C++20 risks (will only surface in CI)

Ordered by likelihood. These are why this needs iteration, not a one-shot push:

1. **`<codecvt>` under MSVC C++20** — B2's silence macro should fix; if MSVC made it
   a hard removal, rewrite `mmap.h`'s path conversion to `MultiByteToWideChar`.
2. **`/bigobj` insufficient / template blowup** — large IR TUs; may also need
   `/Zc:__cplusplus` so `__cplusplus` reports C++20 correctly to feature-gated code.
3. **`NOMINMAX` leakage** — any TU that includes `<windows.h>` *before* `<algorithm>`
   can still bite; may need `#define NOMINMAX` before includes in `mmap.h` too.
4. **Vendored Core CMake** — sets no platform flags; flatbuffers codegen + slicer
   may need the same MSVC block (B2) on `dexkit_static`, not just our targets.
5. **`__attribute__`/`__builtin_*` in third_party** — flatbuffers/phmap carry MSVC
   fallbacks, but a stray GCC-ism in the vendored slicer could appear (grep was
   clean, but full-compile is the real test).
6. **`SLICER_CHECK` / `dex::` width assumptions** — the slicer assumes
   LP64-ish widths; MSVC is LLP64 (`long` is 32-bit). Audit any `long` casts in the
   width/offset math if numeric tests diverge.
7. **delvewheel DLL bundling** — the zlib DLL (vcpkg path) must be discoverable and
   stamped into the wheel; static zlib (FetchContent) sidesteps this entirely.
8. **Path/encoding** — `identify()` / load take `str` paths; verify non-ASCII paths
   round-trip through the `_wopen` branch (relevant for a triage tool on localized
   filenames).

---

## 4. Validation strategy

1. Branch `windows-support`; add the `windows-latest` CI job **first** so every push
   gets a verdict.
2. Land B1/B2/B6 → push → read the first MSVC error wall.
3. Layer B3 (zlib) once the source compiles → link stage.
4. Iterate to a green **build + import + identify**, then green **ctest parity** on
   Windows (the real correctness gate — same 28 suites as Linux/macOS).
5. Add B4/B5 wheel build; confirm a `delvewheel`-repaired wheel imports on a clean
   runner.
6. Only then merge to master and add `windows-latest` to `release.yml`'s wheel
   matrix.

Success = the 28 parity suites pass on Windows **and** a cp39–cp313 AMD64 wheel
builds, repairs, imports, and runs `identify()`.

---

## 5. Effort, risk, rollback

- **Effort:** small *diff*, but multi-round CI (the MSVC errors in §3 are sequential
  — each fix reveals the next). Realistically several CI iterations.
- **Biggest risk:** the vendored AOSP slicer / flatbuffers under MSVC C++20. If MSVC
  conformance proves intractable, **fallback = MinGW** via a cibuildwheel toolchain
  override (`CIBW_ENVIRONMENT`/`--config-settings`), which keeps the existing
  POSIX-ish `mmap.h` path (MinGW has `<unistd.h>`) and sidesteps B1/most of B2.
- **Rollback:** all changes are isolated to build config + one fork header guard +
  CI matrix entries. Nothing touches the decompiler IR or output. Reverting the
  branch restores the Linux/macOS-only status with zero residue.
- **Scope cut available:** ship Windows as **source-build only** first (no wheel) —
  i.e. land B1/B2/B3 so `pip install` from sdist works on a Windows box with MSVC +
  zlib, and defer the cibuildwheel/delvewheel wheel automation (B4/B5) to a second
  pass. Lowers risk if pre-built Windows wheels aren't urgent.
