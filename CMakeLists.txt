cmake_minimum_required(VERSION 3.20)

if(TARGET DetourHooking)
	return()
endif()

project(DetourHooking)

add_library(DetourHooking STATIC
		"${PROJECT_SOURCE_DIR}/Source/Hook.cpp"
		"${PROJECT_SOURCE_DIR}/Source/RefCountedHook.cpp"
		"${PROJECT_SOURCE_DIR}/Source/MemoryPage.cpp"
		"${PROJECT_SOURCE_DIR}/Source/Utils.cpp")
target_include_directories(DetourHooking PUBLIC "${PROJECT_SOURCE_DIR}/Include")
target_compile_options(DetourHooking PRIVATE "-Ofast")
target_compile_features(DetourHooking PRIVATE cxx_std_20)

include(FetchContent)

FetchContent_Declare(ForceWrite
	GIT_REPOSITORY https://github.com/Sumandora/ForceWrite
	GIT_PROGRESS TRUE
	GIT_TAG b11fd6a)
FetchContent_MakeAvailable(ForceWrite)
target_link_libraries(DetourHooking ForceWrite)

if(PROJECT_IS_TOP_LEVEL)
	add_executable(ManualExample "${PROJECT_SOURCE_DIR}/Example/Manual.cpp")
	add_executable(RefCountedExample "${PROJECT_SOURCE_DIR}/Example/RefCounted.cpp")

	target_link_libraries(ManualExample PRIVATE DetourHooking)
	target_link_libraries(RefCountedExample PRIVATE DetourHooking)

	target_compile_features(ManualExample PRIVATE cxx_std_20) # template requires
	target_compile_features(RefCountedExample PRIVATE cxx_std_20)

	if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8) # This is not required in a real world application
		target_compile_options(ManualExample PRIVATE "-fno-pie")
		target_compile_options(RefCountedExample PRIVATE "-fno-pie")
	endif()

	enable_testing()

	add_test(NAME ManualExample COMMAND $<TARGET_FILE:ManualExample>)
	add_test(NAME RefCountedExample COMMAND $<TARGET_FILE:RefCountedExample>)
endif()
