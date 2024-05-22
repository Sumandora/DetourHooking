add_subdirectory("${MemoryManager_SOURCE_DIR}/Modules/Local" "LocalMemoryManager")

add_executable(DetourHookingExample "Source/Main.cpp")
target_link_libraries(DetourHookingExample PRIVATE DetourHooking LocalMemoryManager)
if (NOT CMAKE_SIZEOF_VOID_P EQUAL 8) # This is not required in a real world application
    target_compile_options(DetourHookingExample PRIVATE "-fno-pie")
endif ()
target_compile_features(DetourHookingExample PRIVATE cxx_std_20)

add_test(NAME DetourHookingExample COMMAND $<TARGET_FILE:DetourHookingExample>)