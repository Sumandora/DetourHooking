cmake_minimum_required(VERSION 3.20)

include_guard()

project(DetourHooking)

add_library(DetourHooking INTERFACE)
target_include_directories(DetourHooking INTERFACE "${PROJECT_SOURCE_DIR}/Include")
target_compile_features(DetourHooking INTERFACE cxx_std_23)

include(FetchContent)

if (NOT TARGET ExecutableMalloc)
    FetchContent_Declare(ExecutableMalloc
            GIT_REPOSITORY https://github.com/Sumandora/ExecutableMalloc
            GIT_PROGRESS TRUE
            GIT_TAG 2.9)
    FetchContent_MakeAvailable(ExecutableMalloc)
endif ()
if (NOT TARGET ExecutableMallocMemoryManager)
    add_subdirectory("${ExecutableMalloc_SOURCE_DIR}/Modules/MemoryManagerAllocator" "MemoryManagerAllocator")
endif ()
target_link_libraries(DetourHooking INTERFACE ExecutableMallocMemoryManager)

if (NOT TARGET LengthDisassembler)
    FetchContent_Declare(LengthDisassembler
            GIT_REPOSITORY https://github.com/Sumandora/LengthDisassembler
            GIT_PROGRESS TRUE
            GIT_TAG 1.0.1)
    FetchContent_MakeAvailable(LengthDisassembler)
endif ()
target_link_libraries(DetourHooking INTERFACE LengthDisassembler)

if (PROJECT_IS_TOP_LEVEL)
    enable_testing()
    add_subdirectory("Example")
endif ()
