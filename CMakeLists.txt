cmake_minimum_required(VERSION 3.20)
project(DetourHooking)

set(CMAKE_CXX_STANDARD 23)

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
	add_compile_options("-fno-pie")
endif()

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

add_library(DetourHooking STATIC "${PROJECT_SOURCE_DIR}/Source/Hook.cpp" "${PROJECT_SOURCE_DIR}/Source/MemoryPage.cpp" "${PROJECT_SOURCE_DIR}/Source/Utils.cpp")
target_include_directories(DetourHooking PUBLIC "${PROJECT_SOURCE_DIR}/Include")

add_executable(DetourHookingExample "${PROJECT_SOURCE_DIR}/Example/Main.cpp")
target_link_libraries(DetourHookingExample PRIVATE DetourHooking)

enable_testing()
add_test(NAME DetourHookingExample COMMAND $<TARGET_FILE:DetourHookingExample>)
