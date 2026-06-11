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

# Our C++ extension over DexKit.
add_library(dexkit_ext STATIC
    native/core_ext/dexkit_ext.cpp
    native/core_ext/dexitem_code_source.cpp
)
target_include_directories(dexkit_ext PUBLIC native/core_ext/include native/dad_cpp/include)
target_link_libraries(dexkit_ext PUBLIC dexkit_static)

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
target_link_libraries(dexkit_dad PUBLIC dexkit_ext)

# pybind11 module.
pybind11_add_module(_dexkit_core MODULE
    native/binding/module.cpp
)
target_link_libraries(_dexkit_core PRIVATE dexkit_ext dexkit_dad)

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
