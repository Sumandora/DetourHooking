cmake_minimum_required(VERSION 3.20)

include_guard()

project(DetourHooking)

add_library(DetourHooking INTERFACE)
target_include_directories(DetourHooking INTERFACE "${PROJECT_SOURCE_DIR}/Include")
target_compile_features(DetourHooking INTERFACE cxx_std_23)

if (NOT TARGET ExecutableMalloc)
    include("FetchContent")

    FetchContent_Declare(ExecutableMalloc
            GIT_REPOSITORY https://github.com/Sumandora/ExecutableMalloc
            GIT_PROGRESS TRUE
            GIT_TAG 2.2)
    FetchContent_MakeAvailable(ExecutableMalloc)
endif ()
if (NOT TARGET ExecutableMallocMemoryManager)
    add_subdirectory("${ExecutableMalloc_SOURCE_DIR}/Modules/MemoryManagerAllocator")
endif ()
target_link_libraries(DetourHooking INTERFACE ExecutableMallocMemoryManager)

if (PROJECT_IS_TOP_LEVEL)
    enable_testing()
    add_subdirectory("Example")
endif ()
