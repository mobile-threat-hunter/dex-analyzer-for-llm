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

# psl_parity_test needs the public-suffix matcher, which lives in dexkit_ext.
# Compile it directly into the test (no dexkit_static link) — it only needs the
# generated PSL header (native/core_ext/gen) and the public API header.
if(TARGET psl_parity_test)
    target_sources(psl_parity_test PRIVATE
        "${CMAKE_SOURCE_DIR}/native/core_ext/public_suffix.cpp")
    target_include_directories(psl_parity_test PRIVATE
        "${CMAKE_SOURCE_DIR}/native/core_ext/include"
        "${CMAKE_SOURCE_DIR}/native/core_ext")
endif()

list(LENGTH PARITY_TEST_TARGETS PARITY_TEST_COUNT)
message(STATUS "Registered ${PARITY_TEST_COUNT} parity test(s)")

# Aggregate build-only target.
add_custom_target(parity_tests DEPENDS ${PARITY_TEST_TARGETS})
