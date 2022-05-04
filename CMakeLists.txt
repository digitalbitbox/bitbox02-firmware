# Copyright (c) 2015-2016 Lucas Betschart, Douglas J. Bakkum
# Copyright 2019 Shift Cryptosecurity AG
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required(VERSION 3.10)

# Set a default build type if none was specified
set(default_build_type "RelWithDebInfo")

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  message(STATUS "Setting build type to '${default_build_type}' as none was specified.")
  set(CMAKE_BUILD_TYPE "${default_build_type}" CACHE STRING "Choose the type of build." FORCE)
  # We don't use the builtin MinSizeRel because Release always optimizes for size.
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "RelWithDebInfo")
endif()

# TODO: Using ${CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE}} does not work the first time due to this.
string(TOUPPER ${CMAKE_BUILD_TYPE} CMAKE_BUILD_TYPE)

if(
  NOT CMAKE_BUILD_TYPE STREQUAL "DEBUG" AND
  NOT CMAKE_BUILD_TYPE STREQUAL "RELEASE" AND
  NOT CMAKE_BUILD_TYPE STREQUAL "RELWITHDEBINFO"
)
  message(FATAL_ERROR "Invalid CMAKE_BUILD_TYPE ${CMAKE_BUILD_TYPE}")
endif()

project(bitbox02 C)

# nosys is set in arm.cmake so that `project(c)` above works. Remove it since it interferes with compile options
if(CMAKE_CROSSCOMPILING)
  string(REPLACE "--specs=nosys.specs" "" CMAKE_EXE_LINKER_FLAGS ${CMAKE_EXE_LINKER_FLAGS})
endif()

# Where to find custom cmake modules
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_SOURCE_DIR}/tools/nanopb/extra)

#-----------------------------------------------------------------------------
# Options for building

option(COVERAGE "Compile with test coverage flags." OFF)
option(SANITIZE_ADDRESS "Compile with asan." OFF)
option(SANITIZE_UNDEFINED "Compile with ubsan." OFF)
option(CMAKE_VERBOSE_MAKEFILE "Verbose build." OFF)
option(SEMIHOSTING "Enable semihosting." OFF)
# Generate compile_command.json (for tidy and other tools)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(SEMIHOSTING AND NOT CMAKE_CROSSCOMPILING)
  message(FATAL_ERROR "It doesn't make sense to semihost for the build machine")
endif()

#-----------------------------------------------------------------------------
# Force out-of-source build

if(${CMAKE_CURRENT_SOURCE_DIR} STREQUAL ${CMAKE_CURRENT_BINARY_DIR})
message(FATAL_ERROR
  "CMake generation is not allowed within the source directory!\n"
  "Remove the CMakeCache.txt file and try again from another folder, e.g.:\n\n"
  "  rm CMakeCache.txt\n"
  "  mkdir build\n"
  "  cd build\n"
  "  cmake ..\n"
)
endif()

# Finds objcopy and other utilities for us
if(CMAKE_CROSSCOMPILING)
  include(CMakeFindBinUtils)
  find_program(CMAKE_SIZE "${TOOLCHAIN_PREFIX}size")
  message(STATUS "size: ${CMAKE_SIZE} ${TOOLCHAIN_PREFIX}size")
endif()


#-----------------------------------------------------------------------------
# Create version header file
#
# Versions MUST contain three parts and start with lowercase 'v'.
# Example 'v1.0.0'. They MUST not contain a pre-release label such as '-beta'.
set(FIRMWARE_VERSION "v9.11.0")
set(FIRMWARE_BTC_ONLY_VERSION "v9.11.0")
set(BOOTLOADER_VERSION "v1.0.4")

find_package(PythonInterp 3.6 REQUIRED)

find_package(Git)
if(GIT_FOUND AND PYTHONINTERP_FOUND)
  # TODO: --verify cannot be used in container. Add our pubkeys to image?
  execute_process(
    COMMAND ${PYTHON_EXECUTABLE} ./scripts/get_version firmware --check-semver --check-gpg
    RESULT_VARIABLE exit_code
    OUTPUT_VARIABLE GIT_FIRMWARE_VERSION_STRING
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )
  if(NOT exit_code EQUAL "0")
    set(GIT_FIRMWARE_VERSION_STRING "v0.0.0")
  endif()
  execute_process(
    COMMAND ${PYTHON_EXECUTABLE} ./scripts/get_version firmware-btc-only --check-semver --check-gpg
    RESULT_VARIABLE exit_code
    OUTPUT_VARIABLE GIT_FIRMWARE_BTC_ONLY_VERSION_STRING
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )
  if(NOT exit_code EQUAL "0")
    set(GIT_FIRMWARE_BTC_ONLY_VERSION_STRING "v0.0.0")
  endif()
  execute_process(
    COMMAND ${PYTHON_EXECUTABLE} ./scripts/get_version bootloader --check-semver --check-gpg
    RESULT_VARIABLE exit_code
    OUTPUT_VARIABLE GIT_BOOTLOADER_VERSION_STRING
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )
  if(NOT exit_code EQUAL "0")
    set(GIT_BOOTLOADER_VERSION_STRING "v0.0.0")
  endif()

  execute_process(
    COMMAND ${GIT_EXECUTABLE} rev-parse HEAD
    RESULT_VARIABLE exit_code
    OUTPUT_VARIABLE GIT_COMMIT_HASH
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )
  if(NOT exit_code EQUAL "0")
    set(GIT_COMMIT_HASH "0000000000000000000000000000000000000000")
  endif()
  execute_process(
    COMMAND ${GIT_EXECUTABLE} rev-parse --short=10 HEAD
    RESULT_VARIABLE exit_code
    OUTPUT_VARIABLE GIT_COMMIT_HASH_SHORT
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )
  if(NOT exit_code EQUAL "0")
    set(GIT_COMMIT_HASH_SHORT "000000")
  endif()
else()
  set(GIT_FIRMWARE_VERSION_STRING "v0.0.0")
  set(GIT_FIRMWARE_BTC_ONLY_VERSION_STRING "v0.0.0")
  set(GIT_BOOTLOADER_VERSION_STRING "v0.0.0")
  set(GIT_COMMIT_HASH "0000000000000000000000000000000000000000")
  set(GIT_COMMIT_HASH_SHORT "0000000000")
endif()

# MULTI

# If the current HEAD is not on the matching tag append '-pre' for "pre-release"
set(FIRMWARE_VERSION_FULL ${FIRMWARE_VERSION})
if(NOT FIRMWARE_VERSION STREQUAL GIT_FIRMWARE_VERSION_STRING)
  string(APPEND FIRMWARE_VERSION_FULL "-pre+${GIT_COMMIT_HASH_SHORT}")
endif()

string(REPLACE "." ";" VERSION_LIST ${FIRMWARE_VERSION})
list(GET VERSION_LIST 0 vMAJOR)
list(GET VERSION_LIST 1 MINOR)
list(GET VERSION_LIST 2 PATCH)
string(REPLACE "v" "" MAJOR ${vMAJOR})

string(LENGTH ${FIRMWARE_VERSION_FULL} FIRMWARE_VERSION_FULL_LEN)
string(REGEX REPLACE "(.)" "'\\1', 0, " FIRMWARE_VERSION_FULL_W16 ${FIRMWARE_VERSION_FULL})
set(FIRMWARE_VERSION_MAJOR ${MAJOR})
set(FIRMWARE_VERSION_MINOR ${MINOR})
set(FIRMWARE_VERSION_PATCH ${PATCH})

# BTC-ONLY

# If the current HEAD is not on the matching tag append '-pre' for "pre-release"
set(FIRMWARE_BTC_ONLY_VERSION_FULL ${FIRMWARE_BTC_ONLY_VERSION})
if(NOT FIRMWARE_BTC_ONLY_VERSION STREQUAL GIT_FIRMWARE_BTC_ONLY_VERSION_STRING)
  string(APPEND FIRMWARE_BTC_ONLY_VERSION_FULL "-pre+${GIT_COMMIT_HASH_SHORT}")
endif()

string(REPLACE "." ";" VERSION_LIST ${FIRMWARE_BTC_ONLY_VERSION})
list(GET VERSION_LIST 0 vMAJOR)
list(GET VERSION_LIST 1 MINOR_BTC_ONLY)
list(GET VERSION_LIST 2 PATCH_BTC_ONLY)
string(REPLACE "v" "" MAJOR_BTC_ONLY ${vMAJOR})

string(LENGTH ${FIRMWARE_BTC_ONLY_VERSION_FULL} FIRMWARE_BTC_ONLY_VERSION_FULL_LEN)
string(REGEX REPLACE "(.)" "'\\1', 0, " FIRMWARE_BTC_ONLY_VERSION_FULL_W16 ${FIRMWARE_BTC_ONLY_VERSION_FULL})
set(FIRMWARE_BTC_ONLY_VERSION_MAJOR ${MAJOR_BTC_ONLY})
set(FIRMWARE_BTC_ONLY_VERSION_MINOR ${MINOR_BTC_ONLY})
set(FIRMWARE_BTC_ONLY_VERSION_PATCH ${PATCH_BTC_ONLY})

# BOOTLOADER

set(BOOTLOADER_VERSION_FULL ${BOOTLOADER_VERSION})
if(NOT BOOTLOADER_VERSION STREQUAL GIT_BOOTLOADER_VERSION_STRING)
  string(APPEND BOOTLOADER_VERSION_FULL "-pre+${GIT_COMMIT_HASH_SHORT}")
  add_definitions("-DBOOTLOADER_VERSION_HAS_METADATA")
endif()

string(LENGTH ${BOOTLOADER_VERSION_FULL} BOOTLOADER_VERSION_FULL_LEN)
string(REGEX REPLACE "(.)" "'\\1', 0, " BOOTLOADER_VERSION_FULL_W16 ${BOOTLOADER_VERSION_FULL})

configure_file(src/version.h.in src/version.h)
configure_file(src/bootloader/bootloader_version.h.in src/bootloader/bootloader_version.h)

#-----------------------------------------------------------------------------
# Set the default compiler options (Only set global options that truly are necessary for all files)

string(APPEND CMAKE_C_FLAGS " -std=c99 -pipe")
if(CMAKE_CROSSCOMPILING)
  set(CMAKE_C_FLAGS "\
    ${CMAKE_C_FLAGS} -mcpu=cortex-m4 -mthumb -mlong-calls \
    -mfloat-abi=softfp -mfpu=fpv4-sp-d16 -fomit-frame-pointer -D__SAMD51J20A__ \
    "
  )
  # Allow gc-sections at linking stage. (TODO: move to targets that use that linking option)
  string(APPEND CMAKE_C_FLAGS " -ffunction-sections -fdata-sections")
  set(CMAKE_C_LINK_FLAGS "\
    ${CMAKE_C_LINK_FLAGS} -mcpu=cortex-m4 -mthumb  -Wl,--gc-sections \
    "
  )
endif()

# Optimize for size by default
set(CMAKE_C_FLAGS_RELEASE "-Os -DNDEBUG")
# Allow gdb extensions if available
set(CMAKE_C_FLAGS_DEBUG "-Og -ggdb")
set(CMAKE_C_FLAGS_RELWITHDEBINFO "-Os -ggdb -DNDEBUG")

#-----------------------------------------------------------------------------
# Print system information and build options

execute_process(
  COMMAND ${CMAKE_C_COMPILER} -dumpversion
  OUTPUT_VARIABLE C_COMPILER_VERSION
  OUTPUT_STRIP_TRAILING_WHITESPACE
)

message(STATUS "\n\n=============================================")
message(STATUS "            - General -")
message(STATUS "Firmware version:       ${FIRMWARE_VERSION_FULL}")
message(STATUS "Firmware v. (git):      ${GIT_FIRMWARE_VERSION_STRING}")
message(STATUS "Firmware-btc version:   ${FIRMWARE_BTC_ONLY_VERSION_FULL}")
message(STATUS "Firmware-btc v. (git):  ${GIT_FIRMWARE_BTC_ONLY_VERSION_STRING}")
message(STATUS "Bootloader version:     ${BOOTLOADER_VERSION_FULL}")
message(STATUS "Bootloader v. (git):    ${GIT_BOOTLOADER_VERSION_STRING}")
message(STATUS "CMake version:          ${CMAKE_VERSION}")
message(STATUS "System:                 ${CMAKE_SYSTEM}")
message(STATUS "Processor:              ${CMAKE_SYSTEM_PROCESSOR}")
message(STATUS "             - Build -")
message(STATUS "Compiler version:       ${CMAKE_C_COMPILER_ID} ${C_COMPILER_VERSION}")
message(STATUS "Compiler:               ${CMAKE_C_COMPILER}")
message(STATUS "Linker:                 ${CMAKE_LINKER}")
message(STATUS "Archiver:               ${CMAKE_AR}")
message(STATUS "Default CFLAGS:         ${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE}}")
message(STATUS "Default EXE LDFLAGS:    ${CMAKE_EXE_LINKER_FLAGS}")
message(STATUS "            - Options -")
message(STATUS "Build type:             ${CMAKE_BUILD_TYPE}")
message(STATUS "Hardware version:       ${HARDWARE}")
message(STATUS "Verbose:                ${CMAKE_VERBOSE_MAKEFILE}")
message(STATUS "Coverage flags:         ${COVERAGE}")
message(STATUS "\n=============================================\n\n")

#-----------------------------------------------------------------------------
# Collect all binaries into bin/lib subdirectory

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)


#-----------------------------------------------------------------------------
# Compiler
# more specific CFLAGS might be added in the subdirectories src/ and test/.

# Compile all code with additional warnings by default and treat warnings as errors
# Excerpt from GCC manual to avoid manually enabling warnings
#    -Wall:
#     -Waddress -Warray-bounds=1 (only with -O2) -Wbool-compare -Wbool-operation -Wc++11-compat  -Wc++14-compat
#     -Wcatch-value (C++ and Objective-C++ only) -Wchar-subscripts -Wcomment -Wduplicate-decl-specifier (C and
#     Objective-C only) -Wenum-compare (in C/ObjC; this is on by default in C++) -Wformat -Wint-in-bool-context
#     -Wimplicit (C and Objective-C only) -Wimplicit-int (C and Objective-C only) -Wimplicit-function-declaration (C
#     and Objective-C only) -Winit-self (only for C++) -Wlogical-not-parentheses -Wmain (only for C/ObjC and unless
#     -ffreestanding) -Wmaybe-uninitialized -Wmemset-elt-size -Wmemset-transposed-args -Wmisleading-indentation (only
#     for C/C++) -Wmissing-attributes -Wmissing-braces (only for C/ObjC) -Wmultistatement-macros -Wnarrowing (only for
#     C++) -Wnonnull -Wnonnull-compare -Wopenmp-simd -Wparentheses -Wpointer-sign -Wreorder -Wrestrict -Wreturn-type
#     -Wsequence-point -Wsign-compare (only in C++) -Wsizeof-pointer-div -Wsizeof-pointer-memaccess -Wstrict-aliasing
#     -Wstrict-overflow=1 -Wstringop-truncation -Wswitch -Wtautological-compare -Wtrigraphs -Wuninitialized
#     -Wunknown-pragmas -Wunused-function -Wunused-label -Wunused-value -Wunused-variable -Wvolatile-register-var
#
#    -Wextra:
#     -Wclobbered -Wcast-function-type -Wempty-body -Wignored-qualifiers -Wimplicit-fallthrough=3
#     -Wmissing-field-initializers -Wmissing-parameter-type (C only) -Wold-style-declaration (C only) -Woverride-init
#     -Wsign-compare (C only) -Wtype-limits -Wuninitialized -Wshift-negative-value (in C++03 and in C99 and newer)
#     -Wunused-parameter (only with -Wunused or -Wall) -Wunused-but-set-parameter (only with -Wunused or -Wall)
#
#    -Wformat=2:
#     Enable -Wformat plus additional format checks.  Currently equivalent to -Wformat -Wformat-nonliteral
#     -Wformat-security -Wformat-y2k.

string(APPEND CMAKE_C_FLAGS " -Wall -Wextra -Wpedantic")
string(APPEND CMAKE_C_FLAGS " -Wmissing-prototypes -Werror-implicit-function-declaration ")
string(APPEND CMAKE_C_FLAGS " -Wpointer-arith -Wunused -Wfloat-equal -Wshadow -Wbad-function-cast")
string(APPEND CMAKE_C_FLAGS " -Wformat=2 -Wformat-signedness -Wwrite-strings ")
string(APPEND CMAKE_C_FLAGS " -Wmissing-declarations -Wmissing-format-attribute -Wpacked ")
string(APPEND CMAKE_C_FLAGS " -Wredundant-decls -Wnested-externs -Wmultichar -Winit-self ")
string(APPEND CMAKE_C_FLAGS " -Wold-style-definition -Wswitch-default -Wattributes ")
string(APPEND CMAKE_C_FLAGS " -Wdeprecated-declarations -Wcast-qual -Wstrict-prototypes")
string(APPEND CMAKE_C_FLAGS " -Wundef -Wmissing-include-dirs")

# Disable builtin warning
string(APPEND CMAKE_C_FLAGS " -Wno-cast-function-type")

# Hardening
string(APPEND CMAKE_C_FLAGS " -fstack-protector-all")

# For `struct timespec` and `strdup`
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_XOPEN_SOURCE=600")

string(LENGTH "${CMAKE_SOURCE_DIR}/" SOURCE_PATH_SIZE)
add_definitions("-DSOURCE_PATH_SIZE=${SOURCE_PATH_SIZE}")


# protoc is used to generate API messages
find_program(PROTOC protoc)
if (PROTOC STREQUAL "PROTOC-NOTFOUND")
  message(FATAL_ERROR "Could not find 'protoc'.")
endif()

#-----------------------------------------------------------------------------
# Build

add_subdirectory(external)
add_subdirectory(messages)
add_subdirectory(src)
add_subdirectory(scripts)

#-----------------------------------------------------------------------------
# Build Documentation


set(DOC_GRAPHS "YES" CACHE STRING "Create dependency graphs (needs graphviz)")
set(DOC_FULLGRAPHS "NO" CACHE STRING "Create call/callee graphs (large)")

find_program(DOT_PATH dot)

if(DOT_PATH STREQUAL "DOT_PATH-NOTFOUND")
  message("Doxygen: graphviz not found - graphs disabled")
  set(DOC_GRAPHS "NO")
endif()

add_custom_target(doc)
find_package(Doxygen)
if(DOXYGEN_FOUND)
  configure_file("doc/Doxyfile.in" "Doxyfile" @ONLY)
  add_custom_target(doxygen-docs
    ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    COMMENT "Generating API documentation with Doxygen.." VERBATIM)
  add_dependencies(doxygen-docs generate-protobufs)
  add_dependencies(doc doxygen-docs)
else()
  message("Doxygen: doxygen not found - docs disabled")
endif()

if(CMAKE_CROSSCOMPILING)
  add_dependencies(doc rust-docs)
else()
  include(CTest)
  add_subdirectory(test/unit-test)
  if(COVERAGE)
    find_program(GCOVR gcovr)
    if(NOT GCOVR STREQUAL "GCOVR-NOTFOUND")
      # __dummy is used to always force regeneration of coverage file (There is no reasonable way to track generation of gcda files...)
      add_custom_command(
        OUTPUT gcovr/coverage.html __dummy
        COMMAND ${CMAKE_COMMAND} -E make_directory gcovr
        COMMAND ${GCOVR} --gcov-executable gcov-8 --delete --html-details -o gcovr/coverage.html -r ${CMAKE_SOURCE_DIR} -f ${CMAKE_SOURCE_DIR}/src
      )
      add_custom_target(
        coverage
        COMMAND ${CMAKE_COMMAND} -E echo Coverage at file:///${CMAKE_BINARY_DIR}/gcovr/coverage.html
        DEPENDS gcovr/coverage.html
      )
    endif()
    find_program(LCOV lcov)
    find_program(GENHTML genhtml)
    if(NOT LCOV STREQUAL "LOCV-NOTFOUND" AND NOT GENHTML STREQUAL "GENHTML-NOTFOUND")
      add_custom_command(
        OUTPUT lcovr/raw_coverage.info lcovr/coverage.info lcovr/index.html __dummy
        COMMAND ${CMAKE_COMMAND} -E make_directory lcovr
        COMMAND ${LCOV} --capture --directory ${CMAKE_BINARY_DIR} --output-file lcovr/raw_coverage.info
        COMMAND ${LCOV} --remove lcovr/raw_coverage.info --output-file lcovr/coverage.info '*/test/*' '*/external/*' '*/src/drivers/*' '/usr/include/*' '*/tools/*'
        COMMAND ${GENHTML} lcovr/coverage.info --output-directory lcovr
      )
      add_custom_target(
        coverage-lcovr
        COMMAND ${CMAKE_COMMAND} -E echo Coverage at file:///${CMAKE_BINARY_DIR}/lcovr/index.html
        DEPENDS lcovr/index.html
      )
    endif()
  endif()
endif()

#-----------------------------------------------------------------------------
# Clean

set(removefiles "bin/*.* lib/*.*")
set_directory_properties(PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES "${removefiles}")
