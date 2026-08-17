cmake_minimum_required(VERSION 3.20)
project(dexllm LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Path to our vendored DexKit Core fork.
# Override with -DDEXKIT_CORE_ROOT=/path/to/dexkit if needed.
if(NOT DEFINED DEXKIT_CORE_ROOT)
    set(DEXKIT_CORE_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/vendor/dexkit_core")
endif()

if(NOT EXISTS "${DEXKIT_CORE_ROOT}/Core/CMakeLists.txt")
    message(FATAL_ERROR
        "DexKit Core not found at ${DEXKIT_CORE_ROOT}/Core. "
        "Pass -DDEXKIT_CORE_ROOT=<path> or place vendored fork at vendor/dexkit_core.")
endif()

# Pull in vendored DexKit static library (`dexkit_static` target).
add_subdirectory("${DEXKIT_CORE_ROOT}/Core" dexkit_core_build EXCLUDE_FROM_ALL)

# pybind11 + Python
find_package(Python COMPONENTS Interpreter Development.Module REQUIRED)
find_package(pybind11 CONFIG REQUIRED)

# The vendored DexKit Core (dexkit_static) uses a pthread ThreadPool, so pthread
# must be on the final link of EVERY consumer. The pybind module gets it via
# Python's link flags, but a standalone consumer (the parity-test executables,
# which link dexkit_dad -> dexkit_ext -> dexkit_static) does not — link Threads
# explicitly and propagate it, else manylinux's strict linker fails with
# `undefined reference to pthread_create` (only relied on transitively before).
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

# The shared MUTF-8 codec (an ART port, see native/dad_cpp/include/mutf8.h). Its
# own leaf target with NO dependencies, because three layers need it: the DAD
# decompiler, the pybind boundary, and — since dexllm#22 — the vendored Core's
# smali renderer, which must DECODE a pool string before escaping it. Keeping one
# implementation is the point: CLAUDE.md records that the hand-rolled copies were
# consolidated onto this file precisely because they drifted.
add_library(dexkit_mutf8 STATIC native/dad_cpp/mutf8.cpp)
target_include_directories(dexkit_mutf8 PUBLIC native/dad_cpp/include)

# Our C++ extension over DexKit.
add_library(dexkit_ext STATIC
    native/core_ext/dexkit_ext.cpp
    native/core_ext/dexitem_code_source.cpp
    native/core_ext/dex_verifier.cpp
    native/core_ext/invoke_args.cpp
    native/core_ext/analysis.cpp
)
target_include_directories(dexkit_ext PUBLIC native/core_ext/include native/dad_cpp/include)
# PRIVATE, deliberately. invoke_args.cpp reaches `utils/opcode_util.h` and
# `utils/byte_code_util.h` (GetBytecodeWidth / ReadInt / ReadLong -- the decode helpers
# the L4 analysis already used before it moved out of the vendored core, dexllm#32, and
# keeping them is what makes the move a lift rather than a rewrite). PUBLIC would
# propagate `${DEXKIT_CORE_ROOT}/Core/dexkit` through dexkit_dad to every dad_cpp TU,
# where a DexKit header would then COMPILE -- and check_dad_boundary.sh's FORBIDDEN
# pattern does not match `utils/`, so the compiler is the only thing enforcing that
# half of the boundary. No public header of dexkit_ext needs the directory
# (invoke_args.h includes only slicer/dex_format.h, already PUBLIC via dexkit_static).
target_include_directories(dexkit_ext PRIVATE ${DEXKIT_CORE_ROOT}/Core/dexkit)
target_link_libraries(dexkit_ext PUBLIC dexkit_static Threads::Threads dexkit_mutf8)
# The vendored Core's smali renderer decodes MUTF-8 before escaping (dexllm#22).
target_link_libraries(dexkit_static PRIVATE dexkit_mutf8)

# DexKit-DAD decompiler.
add_library(dexkit_dad STATIC
    native/dad_cpp/decompiler.cpp
    native/dad_cpp/util.cpp
    native/dad_cpp/node.cpp
    native/dad_cpp/basic_blocks.cpp
    native/dad_cpp/graph.cpp
    native/dad_cpp/instruction.cpp
    native/dad_cpp/opcode_ins.cpp
    native/dad_cpp/dataflow.cpp
    native/dad_cpp/control_flow.cpp
    native/dad_cpp/dast.cpp
    native/dad_cpp/writer.cpp
    native/dad_cpp/decompile.cpp
    native/dad_cpp/method_snapshot_builder.cpp
    native/dad_cpp/mock_code_source.cpp
    native/dad_cpp/instruction_dispatch.cpp
    native/dad_cpp/instruction_accept.cpp
)
target_include_directories(dexkit_dad PUBLIC native/dad_cpp/include)
target_link_libraries(dexkit_dad PUBLIC dexkit_ext dexkit_mutf8)

# pybind11 module.
pybind11_add_module(_dexkit_core MODULE
    native/binding/module.cpp
)
target_link_libraries(_dexkit_core PRIVATE dexkit_ext dexkit_dad)

# Narrowing in a braced initializer is ill-formed C++ — Clang (macOS) rejects it
# while GCC (Linux) only warns. Make it a hard error on OUR targets (not the
# vendored Core) so the Linux dev build catches what the macOS build would,
# instead of discovering it in CI. See dexitem_code_source.cpp uint16/uint32.
foreach(t dexkit_mutf8 dexkit_ext dexkit_dad _dexkit_core)
    target_compile_options(${t} PRIVATE -Werror=narrowing)
endforeach()

# Install the compiled module into the wheel root; scikit-build-core's
# `wheel.install-dir = "dexllm"` places that root under the dexllm
# package, so DESTINATION "." resolves to dexllm/_dexkit_core.*.so.
install(TARGETS _dexkit_core LIBRARY DESTINATION .)

# Parity tests — built on demand (not part of wheel). Enabled when we're
# the top-level CMake project (i.e. `cd build/... && ninja parity_tests`);
# skipped when scikit-build-core configures us for a wheel build.
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    enable_testing()
    add_subdirectory(tests/parity)
endif()
