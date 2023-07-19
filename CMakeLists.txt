cmake_minimum_required(VERSION 3.20)
project(DetourHooking)

set(CMAKE_CXX_STANDARD 23)

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
	add_compile_options("-fno-pie")
endif()

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

add_executable(DetourHooking Source/Hook.cpp Source/MemoryPage.cpp Source/Utils.cpp Example/Main.cpp)
target_include_directories(DetourHooking PRIVATE include)
