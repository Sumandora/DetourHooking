cmake_minimum_required(VERSION 3.20)

if(TARGET DetourHooking)
	return()
endif()

project(DetourHooking)

add_library(DetourHooking STATIC "${PROJECT_SOURCE_DIR}/Source/Hook.cpp" "${PROJECT_SOURCE_DIR}/Source/MemoryPage.cpp" "${PROJECT_SOURCE_DIR}/Source/Utils.cpp")
target_include_directories(DetourHooking PUBLIC "${PROJECT_SOURCE_DIR}/Include")
target_compile_options(DetourHooking PRIVATE "-Ofast")
target_compile_features(DetourHooking PRIVATE cxx_std_20)

include(FetchContent)

FetchContent_Declare(ForceWrite
	GIT_REPOSITORY https://github.com/Sumandora/ForceWrite
	GIT_PROGRESS TRUE
	GIT_TAG ea203ef)
FetchContent_MakeAvailable(ForceWrite)
target_link_libraries(DetourHooking ForceWrite)

if(PROJECT_IS_TOP_LEVEL)
	add_executable(DetourHookingExample "${PROJECT_SOURCE_DIR}/Example/Main.cpp")
	target_link_libraries(DetourHookingExample PRIVATE DetourHooking)
	if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8) # This is not required in a real world application
		target_compile_options(DetourHookingExample PRIVATE "-fno-pie")
	endif()

	enable_testing()
	add_test(NAME DetourHookingExample COMMAND $<TARGET_FILE:DetourHookingExample>)
endif()
