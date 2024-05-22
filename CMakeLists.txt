cmake_minimum_required(VERSION 3.20)

include_guard()

project(DetourHooking)

add_library(DetourHooking STATIC "${PROJECT_SOURCE_DIR}/Source/Hook.cpp" "${PROJECT_SOURCE_DIR}/Source/Utils.cpp")
target_include_directories(DetourHooking PUBLIC "${PROJECT_SOURCE_DIR}/Include")
target_compile_options(DetourHooking PRIVATE "-Ofast")
target_compile_features(DetourHooking PRIVATE cxx_std_20)

include(FetchContent)

FetchContent_Declare(ExecutableMalloc
		GIT_REPOSITORY https://github.com/Sumandora/ExecutableMalloc
		GIT_PROGRESS TRUE
		GIT_TAG 1.0)
FetchContent_MakeAvailable(ExecutableMalloc)
add_subdirectory("${ExecutableMalloc_SOURCE_DIR}/Extensions/MemoryManagerAllocator")
target_link_libraries(DetourHooking ExecutableMallocMemoryManagerAllocator)

if(PROJECT_IS_TOP_LEVEL)
	enable_testing()
	add_subdirectory("Example")
endif()
