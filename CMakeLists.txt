project(perf-example)
cmake_minimum_required(VERSION 3.15)

set (CMAKE_CXX_STANDARD 20)

option(BUILD_WITH_MUTEX "Build with mutex" OFF)
option(BUILD_WITH_ATOMIC "Build with atomic" OFF)
option(BUILD_WITH_ASAN "Build with address sanitizer" OFF)
option(BUILD_WITH_TSAN "Build with address sanitizer" OFF)
option(BUILD_WITH_COUT_INFO "Build with cout info output" OFF)
option(BUILD_WITH_CHRONO "Build with chrono" OFF)
option(BUILD_WITH_MAIN_THREAD_WORK "Build with chrono" OFF)

if(BUILD_WITH_ASAN)
  add_compile_options(-fsanitize=address -fno-omit-frame-pointer)
  add_link_options(-fsanitize=address -fno-omit-frame-pointer)
endif()

if(BUILD_WITH_TSAN)
  add_compile_options(-fsanitize=thread)
  add_link_options(-fsanitize=thread)
endif()

if(BUILD_WITH_MUTEX)
  add_compile_definitions(ENABLE_MUTEX)
endif()

if(BUILD_WITH_ATOMIC)
  add_compile_definitions(ENABLE_ATOMIC)
endif()

if(BUILD_WITH_COUT_INFO)
  add_compile_definitions(ENABLE_INFO_COUT)
endif()

if(BUILD_WITH_CHRONO)
  add_compile_definitions(ENABLE_CHRONO)
endif()

if(BUILD_WITH_MAIN_THREAD_WORK)
  add_compile_definitions(ENABLE_MAIN_THREAD_WORK)
endif()

add_executable(perf-example main.cpp)
