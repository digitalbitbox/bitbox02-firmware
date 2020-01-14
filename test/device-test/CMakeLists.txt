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


#-----------------------------------------------------------------------------
# Source files

include_directories(${NANOPB_INCLUDE_DIRS})

set(BBBASE-SOURCES
  ${BITBOXBASE-FIRMWARE-SOURCES}
  ${DBB-FIRMWARE-UI-SOURCES}
  ${DRIVER-SOURCES}
  ${DBB-FIRMWARE-PROTOBUF-SOURCES}
  ${CRYPTOAUTHLIB-SOURCES}
  ${ETHEREUM-SOURCES}
  ${CMAKE_SOURCE_DIR}/src/common_main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/src/framework/test_common.c
)

set(BB02-SOURCES
  ${BITBOX02-FIRMWARE-SOURCES}
  ${DBB-FIRMWARE-UI-SOURCES}
  ${FIRMWARE-DRIVER-SOURCES}
  ${DRIVER-SOURCES}
  ${DBB-FIRMWARE-PROTOBUF-SOURCES}
  ${CRYPTOAUTHLIB-SOURCES}
  ${ETHEREUM-SOURCES}
  ${FIRMWARE-U2F-SOURCES}
  ${CMAKE_SOURCE_DIR}/src/common_main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/src/framework/test_common.c
)

# CMake is a bit retarted and doesn't keep some properties between directories...
set_source_files_properties(
  ${DBB-FIRMWARE-PROTOBUF-SOURCES}
  PROPERTIES GENERATED TRUE
)

set(INCLUDES
    include/
    ${FIRMWARE-INCLUDES}
    ${INCLUDES}
    ${CMAKE_BINARY_DIR}/src
)

add_library(bitbox02-test-platform
  STATIC
  ${BB02-SOURCES}
)

target_link_libraries(bitbox02-test-platform PUBLIC bitbox02-platform)
target_include_directories(bitbox02-test-platform PUBLIC ${INCLUDES})
target_include_directories(bitbox02-test-platform SYSTEM PUBLIC ${SYSTEMINCLUDES})
target_include_directories(bitbox02-test-platform SYSTEM PUBLIC ${NANOPB_INCLUDE_DIRS})
target_compile_definitions(bitbox02-test-platform PUBLIC "PB_NO_PACKED_STRUCTS=1" "PB_FIELD_16BIT=1")
target_compile_definitions(bitbox02-test-platform PUBLIC "APP_U2F=1" "APP_ETH=1")
add_dependencies(bitbox02-test-platform generate-protobufs)
# needed to find version.h
target_include_directories(bitbox02-test-platform SYSTEM PUBLIC ${CMAKE_BINARY_DIR}/src)
target_link_libraries(bitbox02-test-platform
  PUBLIC
    wallycore
    secp256k1
  PRIVATE
    fatfs
    noiseprotocol
    cryptoauthlib
    base32
    bignum # TODO: only eth
    sha3   # TODO: Only eth
    ctaes
    app_btc-multi
    -Wl,-u,exception_table
)

# Always enable semihosting for the test firmwares
target_compile_definitions(bitbox02-test-platform PUBLIC "PLATFORM_BITBOX02=1" "EDITION_STANDARD=1" SEMIHOSTING)
target_link_libraries(bitbox02-test-platform PUBLIC --specs=nano.specs --specs=rdimon.specs)
target_compile_options(bitbox02-test-platform PUBLIC --specs=nano.specs --specs=rdimon.specs)

set(BB02_TEST_LIST
  all_variants_menu
  backup
  bip39
  button_tap
  confirm_bip39
  entry_screen
  mpu
  scroll_menu
  scroll_menu_2
  simple_slide
  slide_info
  smarteeprom
  ssp
  tap_menu
  trace
  usb_cmd_process
  usb_composed_ep_in
  usb_composed_ep_out
  usb_d_init
  usb_hww_ep_in
  usb_hww_ep_out
  usb_u2f_ep_in
  usb_u2f_ep_out
  usbdc_init
  write_sd
)

add_custom_target(device-tests)

foreach(name ${BB02_TEST_LIST})
  set(elf fw_test_${name}.elf)
  add_executable(${elf} ${CMAKE_CURRENT_SOURCE_DIR}/src/test_${name}.c)

  target_link_libraries(${elf} PRIVATE "-Wl,-Map=\"${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test_${name}.map\" -T\"${CMAKE_CURRENT_SOURCE_DIR}/device-test.ld\"")
  target_link_libraries(${elf} PRIVATE -Wl,--defsym=STACK_SIZE=${STACK_SIZE} -Wl,-defsym=HEAP_SIZE=${HEAP_SIZE})

  # Since noiseprotocol and wallycore are external projects we need to specify the dependency
  add_dependencies(${elf} noise-c)
  add_dependencies(${elf} libwally-core)
  # We must link against libc before libbitbox because malloc depends on _sbrk
  # We must mark "exception_table" as used, otherwise it won't be linked in since it is in a static library
  target_link_libraries(${elf}
    PRIVATE
      c
      "-Wl,--start-group"
      workflows
      bitbox02-test-platform
      "-Wl,--end-group"
      asf4-drivers-min
      ${QTOUCHLIB_A}
      ${QTOUCHLIB_B}
      ${QTOUCHLIB_T}
  )

  add_custom_command(
    TARGET ${elf} POST_BUILD
    COMMAND ${CMAKE_SIZE} ${elf}
    COMMAND ${CMAKE_OBJCOPY} -O binary ${elf} fw_test_${name}.bin
    WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
    COMMENT "\nGenerating binary fw_test_${name}.bin"
  )
  if(PYTHONINTERP_FOUND)
    execute_process(
      COMMAND ${PYTHON_EXECUTABLE} ${CMAKE_SOURCE_DIR}/scripts/expand_template ${CMAKE_SOURCE_DIR}/scripts/template-firmware.jlink file=build/bin/fw_test_${name}.bin -o fw_test_${name}.jlink
      WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    )
  add_dependencies(device-tests ${elf})
  endif()
endforeach()


add_library(bitboxbase-test-platform
  STATIC
  ${BBBASE-SOURCES}
)

target_link_libraries(bitboxbase-test-platform PUBLIC bitboxbase-platform)
target_include_directories(bitboxbase-test-platform PUBLIC ${INCLUDES})
target_include_directories(bitboxbase-test-platform SYSTEM PUBLIC ${SYSTEMINCLUDES})
target_include_directories(bitboxbase-test-platform SYSTEM PUBLIC ${NANOPB_INCLUDE_DIRS})
target_compile_definitions(bitboxbase-test-platform PUBLIC "PB_NO_PACKED_STRUCTS=1" "PB_FIELD_16BIT=1")
target_compile_definitions(bitboxbase-test-platform PUBLIC "APP_BTC=0" "APP_LTC=0" "APP_U2F=0" "APP_ETH=0")
add_dependencies(bitboxbase-test-platform generate-protobufs)
# needed to find version.h
target_include_directories(bitboxbase-test-platform SYSTEM PUBLIC ${CMAKE_BINARY_DIR}/src)
target_link_libraries(bitboxbase-test-platform
  PUBLIC
    wallycore
    secp256k1
  PRIVATE
    fatfs
    noiseprotocol
    cryptoauthlib
    base32
    bignum # TODO: only eth
    sha3   # TODO: Only eth
    ctaes
    -Wl,-u,exception_table
)
add_dependencies(bitboxbase-test-platform rust-cbindgen)

# Always enable semihosting for the test firmwares
target_compile_definitions(bitboxbase-test-platform PUBLIC "PLATFORM_BITBOXBASE=1" "EDITION_STANDARD=1" SEMIHOSTING)
target_link_libraries(bitboxbase-test-platform PUBLIC --specs=nano.specs --specs=rdimon.specs)
target_compile_options(bitboxbase-test-platform PUBLIC --specs=nano.specs --specs=rdimon.specs)

set(BBB_TEST_LIST
  bitboxbase_touch_demo
)

foreach(name ${BBB_TEST_LIST})
  set(elf fw_test_${name}.elf)
  add_executable(${elf} ${CMAKE_CURRENT_SOURCE_DIR}/src/test_${name}.c)

  target_link_libraries(${elf} PRIVATE "-Wl,-Map=\"${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test_${name}.map\" -T\"${CMAKE_CURRENT_SOURCE_DIR}/device-test.ld\"")
  target_link_libraries(${elf} PRIVATE -Wl,--defsym=STACK_SIZE=${STACK_SIZE} -Wl,-defsym=HEAP_SIZE=${HEAP_SIZE})

  # Since noiseprotocol and wallycore are external projects we need to specify the dependency
  add_dependencies(${elf} noise-c)
  add_dependencies(${elf} libwally-core)
  # We must link against libc before libbitbox because malloc depends on _sbrk
  # We must mark "exception_table" as used, otherwise it won't be linked in since it is in a static library
  target_link_libraries(${elf}
    PRIVATE
      asf4-drivers-min
      asf4-drivers
      bitboxbase-test-platform
      c
      ${QTOUCHLIB_A}
      ${QTOUCHLIB_B}
      ${QTOUCHLIB_T}
  )

  add_custom_command(
    TARGET ${elf} POST_BUILD
    COMMAND ${CMAKE_SIZE} ${elf}
    COMMAND ${CMAKE_OBJCOPY} -O binary ${elf} fw_test_${name}.bin
    WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
    COMMENT "\nGenerating binary fw_test_${name}.bin"
  )
  if(PYTHONINTERP_FOUND)
    execute_process(
      COMMAND ${PYTHON_EXECUTABLE} ${CMAKE_SOURCE_DIR}/scripts/expand_template ${CMAKE_SOURCE_DIR}/scripts/template-firmware.jlink file=build/bin/fw_test_${name}.bin -o fw_test_${name}.jlink
      WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    )
  add_dependencies(device-tests ${elf})
  endif()
endforeach()

# We need the "asm" extension for the MPU test.
set_target_properties(fw_test_mpu.elf PROPERTIES COMPILE_FLAGS "-std=gnu99")
