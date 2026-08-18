# Parity tests — assert byte-identical (or DAD-faithful) IR/output for each
# ported DAD module. Each *_parity_test.cpp is a standalone executable that
# returns 0 on PASS, 1 on FAIL.
#
# Targets:
#   ninja parity_tests       — build all 24 test executables (no run)
#   ctest --output-on-failure — run them all, report PASS/FAIL per file
#
# CI-friendly: ctest exit code is non-zero if any test fails.

file(GLOB PARITY_TEST_SOURCES CONFIGURE_DEPENDS "*_parity_test.cpp")

set(PARITY_TEST_TARGETS)
foreach(src ${PARITY_TEST_SOURCES})
    get_filename_component(name "${src}" NAME_WE)
    add_executable(${name} "${src}")
    target_link_libraries(${name} PRIVATE dexkit_dad)
    # dad_cpp/include is already public on dexkit_dad; slicer headers come
    # transitively via dexkit_ext -> dexkit_static. No extra include needed.
    list(APPEND PARITY_TEST_TARGETS ${name})
    add_test(NAME ${name} COMMAND ${name})
endforeach()

# dexllm(#50) — NOT a DAD parity suite, so it is outside the glob above: a
# concurrency regression test for the vendored ThreadPool. Registered explicitly
# because it includes a DexKit third_party header, which dexkit_dad must not
# carry (the hexagonal boundary keeps dad_cpp DexKit-free).
# It deliberately does NOT link dexkit_static: it defines the matcher-cache
# registry itself, so a case can assert WHICH thread ids the destructor releases
# (unobservable with the real implementation, and the only thing that guards the
# "release only the JOINED ids" fix).
add_executable(thread_pool_selfdestruct_test thread_pool_selfdestruct_test.cpp)
target_include_directories(thread_pool_selfdestruct_test PRIVATE
        "${DEXKIT_CORE_ROOT}/Core/third_party/thread_helper"
        "${DEXKIT_CORE_ROOT}/Core/dexkit/include")
target_link_libraries(thread_pool_selfdestruct_test PRIVATE Threads::Threads)
list(APPEND PARITY_TEST_TARGETS thread_pool_selfdestruct_test)
add_test(NAME thread_pool_selfdestruct_test COMMAND thread_pool_selfdestruct_test)

list(LENGTH PARITY_TEST_TARGETS PARITY_TEST_COUNT)
message(STATUS "Registered ${PARITY_TEST_COUNT} test(s)")

# Aggregate build-only target.
add_custom_target(parity_tests DEPENDS ${PARITY_TEST_TARGETS})
