cmake_minimum_required(VERSION 3.20)
project(DetourHooking)

set(CMAKE_CXX_STANDARD 23)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

add_executable(DetourHooking Source/Hook.cpp Source/MemoryPage.cpp Source/Utils.cpp Example/Main.cpp)
target_include_directories(DetourHooking PRIVATE include)
