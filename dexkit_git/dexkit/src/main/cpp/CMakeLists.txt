cmake_minimum_required(VERSION 3.4.1...3.27)
project(dexkit)

set(CMAKE_CXX_STANDARD 20)
option(DEXKIT_ENABLE_INTERNAL_METRICS "Compile internal metrics into core" OFF)
option(DEXKIT_ENABLE_INTERNAL_METRICS_API "Enable internal metrics JNI bridge" OFF)

if (DEXKIT_ENABLE_INTERNAL_METRICS_API)
    set(DEXKIT_ENABLE_INTERNAL_METRICS ON)
endif ()

add_subdirectory(../../../../Core Core)

set(JAVA_AWT_LIBRARY NotNeeded)
set(JAVA_JVM_LIBRARY NotNeeded)
set(JAVA_AWT_INCLUDE_PATH NotNeeded)
find_package(JNI REQUIRED)
include_directories(${JAVA_INCLUDE_PATH})
include_directories(${JAVA_INCLUDE_PATH2})

message(STATUS "Disable dexkit log")
if (DISABLE_DEXKIT_LOG)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DNDEXKIT_LOG")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DNDEXKIT_LOG")
endif ()

add_library(${PROJECT_NAME} SHARED
        native-bridge.cpp)

if (DEXKIT_ENABLE_INTERNAL_METRICS_API)
    target_sources(${PROJECT_NAME} PRIVATE native-bridge-metrics.cpp)
endif ()

if (WIN32)
    if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_link_options(${PROJECT_NAME} PRIVATE
                -static-libstdc++
                -static-libgcc
                -Wl,-Bstatic,--whole-archive -lwinpthread -Wl,--no-whole-archive
        )
    endif()
elseif (APPLE)
    set(CMAKE_OSX_DEPLOYMENT_TARGET "11.0" CACHE STRING "Minimum macOS deployment version" FORCE)
endif()

target_link_libraries(${PROJECT_NAME}
        dexkit_static
)
