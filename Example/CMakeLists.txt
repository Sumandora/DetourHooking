add_subdirectory("${MemoryManager_SOURCE_DIR}/Modules/Linux" "LinuxMemoryManager")

add_executable(DetourHookingExample "Source/Main.cpp")
target_link_libraries(DetourHookingExample PRIVATE DetourHooking LinuxMemoryManager)
if (NOT CMAKE_SIZEOF_VOID_P EQUAL 8) # This is not required in a real world application
    target_compile_options(DetourHookingExample PRIVATE "-fno-pie")
endif ()

add_test(NAME DetourHookingExample COMMAND $<TARGET_FILE:DetourHookingExample>)