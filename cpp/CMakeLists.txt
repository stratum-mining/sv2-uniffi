cmake_minimum_required(VERSION 3.20)

project(
  sv2cpp
  VERSION 0.1.0
  DESCRIPTION "C++ bindings, tests, and examples for sv2-uniffi"
  LANGUAGES CXX
)

option(SV2CPP_BUILD_TESTS "Build C++ tests" ON)
option(SV2CPP_BUILD_EXAMPLES "Build C++ examples" ON)
option(SV2CPP_ENABLE_WARNINGS "Enable common compiler warnings" ON)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Build type" FORCE)
endif()

set(SV2CPP_ROOT "${CMAKE_CURRENT_SOURCE_DIR}")

if(APPLE)
  set(SV2CPP_RUST_LIBRARY "${SV2CPP_ROOT}/libsv2.dylib")
elseif(UNIX)
  set(SV2CPP_RUST_LIBRARY "${SV2CPP_ROOT}/libsv2.so")
else()
  message(FATAL_ERROR "Unsupported platform: sv2cpp currently expects libsv2.dylib on macOS or libsv2.so on Linux")
endif()

foreach(required_file
  "${SV2CPP_ROOT}/sv2.hpp"
  "${SV2CPP_ROOT}/sv2.cpp"
  "${SV2CPP_ROOT}/sv2_scaffolding.hpp"
  "${SV2CPP_RUST_LIBRARY}"
)
  if(NOT EXISTS "${required_file}")
    message(
      FATAL_ERROR
      "Missing required generated binding artifact: ${required_file}\n"
      "Generate the C++ bindings first with one of:\n"
      "  bash ./scripts/generate-macos.sh\n"
      "  bash ./scripts/generate-linux.sh"
    )
  endif()
endforeach()

add_library(sv2cpp_bindings STATIC sv2.cpp)
add_library(sv2cpp::bindings ALIAS sv2cpp_bindings)

target_include_directories(
  sv2cpp_bindings
  PUBLIC
    "${SV2CPP_ROOT}"
)

target_link_libraries(
  sv2cpp_bindings
  PUBLIC
    "${SV2CPP_RUST_LIBRARY}"
)

target_compile_features(sv2cpp_bindings PUBLIC cxx_std_20)

if(APPLE)
  target_link_options(
    sv2cpp_bindings
    PUBLIC
      "LINKER:-rpath,${SV2CPP_ROOT}"
  )
elseif(UNIX)
  target_link_options(
    sv2cpp_bindings
    PUBLIC
      "LINKER:-rpath,${SV2CPP_ROOT}"
  )
endif()

if(SV2CPP_ENABLE_WARNINGS)
  target_compile_options(
    sv2cpp_bindings
    PRIVATE
      -Wall
      -Wextra
      -Wpedantic
  )
endif()

function(sv2cpp_add_executable target_name source_file)
  add_executable("${target_name}" "${source_file}")

  target_link_libraries(
    "${target_name}"
    PRIVATE
      sv2cpp::bindings
  )

  target_compile_features("${target_name}" PRIVATE cxx_std_20)

  if(SV2CPP_ENABLE_WARNINGS)
    target_compile_options(
      "${target_name}"
      PRIVATE
        -Wall
        -Wextra
        -Wpedantic
    )
  endif()

  if(APPLE)
    set_target_properties(
      "${target_name}"
      PROPERTIES
        BUILD_RPATH "${SV2CPP_ROOT}"
        INSTALL_RPATH "${SV2CPP_ROOT}"
    )
  elseif(UNIX)
    set_target_properties(
      "${target_name}"
      PROPERTIES
        BUILD_RPATH "${SV2CPP_ROOT}"
        INSTALL_RPATH "${SV2CPP_ROOT}"
    )
  endif()
endfunction()

if(SV2CPP_BUILD_TESTS)
  enable_testing()

  file(GLOB SV2CPP_TEST_SOURCES CONFIGURE_DEPENDS "${SV2CPP_ROOT}/tests/*.cpp")

  if(SV2CPP_TEST_SOURCES)
    foreach(test_source IN LISTS SV2CPP_TEST_SOURCES)
      get_filename_component(test_name "${test_source}" NAME_WE)
      set(test_target "sv2cpp_${test_name}")

      sv2cpp_add_executable("${test_target}" "${test_source}")

      add_test(
        NAME "${test_name}"
        COMMAND "${test_target}"
        WORKING_DIRECTORY "${SV2CPP_ROOT}"
      )
    endforeach()
  else()
    message(STATUS "SV2CPP_BUILD_TESTS is ON, but no C++ test sources were found in ${SV2CPP_ROOT}/tests")
  endif()
endif()

if(SV2CPP_BUILD_EXAMPLES)
  file(GLOB SV2CPP_EXAMPLE_SOURCES CONFIGURE_DEPENDS "${SV2CPP_ROOT}/examples/*.cpp")

  if(SV2CPP_EXAMPLE_SOURCES)
    foreach(example_source IN LISTS SV2CPP_EXAMPLE_SOURCES)
      get_filename_component(example_name "${example_source}" NAME_WE)
      set(example_target "sv2cpp_example_${example_name}")

      sv2cpp_add_executable("${example_target}" "${example_source}")
    endforeach()
  else()
    message(STATUS "SV2CPP_BUILD_EXAMPLES is ON, but no C++ example sources were found in ${SV2CPP_ROOT}/examples")
  endif()
endif()

add_custom_target(
  sv2cpp_check
  COMMAND "${CMAKE_CTEST_COMMAND}" --output-on-failure
  DEPENDS
    $<$<BOOL:${SV2CPP_BUILD_TESTS}>:sv2cpp_bindings>
  WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
  COMMENT "Running sv2cpp tests"
)