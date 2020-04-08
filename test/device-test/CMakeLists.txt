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

set(SOURCES
  ${DBB-FIRMWARE-SOURCES}
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

set(LIBRARIES
      samd51a-ds
      asf4-drivers
      ${QTOUCHLIB_A}
      ${QTOUCHLIB_B}
      ${QTOUCHLIB_T}
      tinycbor
      wallycore
      secp256k1
      noiseprotocol
      cryptoauthlib
      base32
      bignum # TODO: only eth
      sha3   # TODO: Only eth
      ctaes
      c
      asf4-drivers-min
  )

set(BITBOX02_LIBRARIES
  -Wl,--start-group
  fatfs
  bitbox02-platform
  -Wl,--end-group
  bitbox02_rust_c
  ${LIBRARIES}
)

set(BITBOXBASE_LIBRARIES
  -Wl,--start-group
  fatfs
  bitboxbase-platform
  -Wl,--end-group
  bitboxbase_rust_c
  ${LIBRARIES}
)

add_library(bitbox02-platform
  STATIC
  ${SOURCES}
  ${PLATFORM-BITBOX02-SOURCES}
)

add_library(bitbox02_rust_c STATIC IMPORTED)
set_property(TARGET bitbox02_rust_c PROPERTY IMPORTED_LOCATION ${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}/libfirmware_rust_c.a)

target_include_directories(bitbox02-platform PUBLIC ${INCLUDES})
target_include_directories(bitbox02-platform SYSTEM PUBLIC ${SYSTEMINCLUDES})
target_include_directories(bitbox02-platform SYSTEM PUBLIC ${NANOPB_INCLUDE_DIRS})
target_compile_definitions(bitbox02-platform PUBLIC "PB_NO_PACKED_STRUCTS=1" "PB_FIELD_16BIT=1")
target_compile_definitions(bitbox02-platform PUBLIC "APP_BTC=1" "APP_LTC=1" "APP_U2F=1" "APP_ETH=1")
add_dependencies(bitbox02-platform generate-protobufs)
add_dependencies(bitbox02-platform firmware-rust)
# needed to find version.h
target_include_directories(bitbox02-platform SYSTEM PUBLIC ${CMAKE_BINARY_DIR}/src)
target_link_libraries(bitbox02-platform
  PUBLIC
    wallycore
    secp256k1
    tinycbor
  PRIVATE
    bitbox02_rust_c
    fatfs
    noiseprotocol
    cryptoauthlib
    base32
    bignum # TODO: only eth
    sha3   # TODO: Only eth
    ctaes
    asf4-drivers-min
    asf4-drivers
    samd51a-ds
)
set_property(TARGET bitbox02-platform PROPERTY INTERFACE_LINK_LIBRARIES "")

target_compile_definitions(bitbox02-platform PUBLIC PRODUCT_BITBOX_MULTI)
target_compile_options(bitbox02-platform PRIVATE --specs=nano.specs)
if(SEMIHOSTING)
  target_compile_definitions(bitbox02-platform PUBLIC SEMIHOSTING)
  target_compile_options(bitbox02-platform PRIVATE --specs=rdimon.specs)
else()
  target_compile_options(bitbox02-platform PRIVATE --specs=nosys.specs)
endif()

set(BB02_TEST_LIST
  all_variants_menu
  backup
  bip39
  button_tap
  confirm_bip39
  entry_screen
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
  token_pub
)

add_custom_target(device-tests)

foreach(name ${BB02_TEST_LIST})
  set(elf fw_test_${name}.elf)
  add_executable(${elf} ${CMAKE_CURRENT_SOURCE_DIR}/src/test_${name}.c)
  target_link_libraries(${elf} PRIVATE --specs=nano.specs --specs=rdimon.specs)
  target_compile_options(${elf} PRIVATE --specs=nano.specs --specs=rdimon.specs)

  target_link_libraries(${elf} PRIVATE "-Wl,-Map=\"${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test_${name}.map\" -T\"${CMAKE_CURRENT_SOURCE_DIR}/device-test.ld\"")
  target_link_libraries(${elf} PRIVATE -Wl,--defsym=STACK_SIZE=${STACK_SIZE} -Wl,-defsym=HEAP_SIZE=${HEAP_SIZE})


  # Since noiseprotocol and wallycore are external projects we need to specify the dependency
  add_dependencies(${elf} noise-c)
  add_dependencies(${elf} libwally-core)
  # We must link against libc before asf4-drivers-min because malloc depends on _sbrk
  # We must mark "exception_table" as used, otherwise it won't be linked in since it is in a static library
  # There are circular dependencies between fatfs and bitbox02-platform (therefore group them with linking commands)
  target_link_libraries(${elf}
    PRIVATE
      -Wl,-u,exception_table
      ${BITBOX02_LIBRARIES}
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


add_library(bitboxbase-platform
  STATIC
  ${SOURCES}
  ${PLATFORM-BITBOXBASE-SOURCES}
)

target_include_directories(bitboxbase-platform PUBLIC ${INCLUDES})
target_include_directories(bitboxbase-platform SYSTEM PUBLIC ${SYSTEMINCLUDES})
target_include_directories(bitboxbase-platform SYSTEM PUBLIC ${NANOPB_INCLUDE_DIRS})
target_compile_definitions(bitboxbase-platform PUBLIC "PB_NO_PACKED_STRUCTS=1" "PB_FIELD_16BIT=1")
target_compile_definitions(bitboxbase-platform PUBLIC "APP_BTC=1" "APP_LTC=1" "APP_U2F=1" "APP_ETH=1")
add_dependencies(bitboxbase-platform generate-protobufs)
add_dependencies(bitboxbase-platform firmware-bitboxbase-rust)
# needed to find version.h
target_include_directories(bitboxbase-platform SYSTEM PUBLIC ${CMAKE_BINARY_DIR}/src)
target_link_libraries(bitboxbase-platform
  PUBLIC
    wallycore
    secp256k1
    tinycbor
  PRIVATE
    asf4-drivers-min
    asf4-drivers
    samd51a-ds
    bitboxbase_rust_c
    fatfs
    noiseprotocol
    cryptoauthlib
    base32
    bignum # TODO: only eth
    sha3   # TODO: Only eth
    ctaes
)
set_property(TARGET bitboxbase-platform PROPERTY INTERFACE_LINK_LIBRARIES "")

target_compile_definitions(bitboxbase-platform PUBLIC PRODUCT_BITBOX_BASE)

target_compile_options(bitboxbase-platform PRIVATE --specs=nano.specs)
if(SEMIHOSTING)
  target_compile_definitions(bitboxbase-platform PUBLIC SEMIHOSTING)
  target_compile_options(bitboxbase-platform PRIVATE --specs=rdimon.specs)
else()
  target_compile_options(bitboxbase-platform PRIVATE --specs=nosys.specs)
endif()

add_library(bitboxbase_rust_c STATIC IMPORTED)
set_property(TARGET bitboxbase_rust_c PROPERTY IMPORTED_LOCATION ${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}/libfirmware-bitboxbase_rust_c.a)


set(BBB_TEST_LIST
  bitboxbase_touch_demo
)

foreach(name ${BBB_TEST_LIST})
  set(elf fw_test_${name}.elf)
  add_executable(${elf} ${CMAKE_CURRENT_SOURCE_DIR}/src/test_${name}.c)
  target_link_libraries(${elf} PRIVATE --specs=nano.specs --specs=rdimon.specs)
  target_compile_options(${elf} PRIVATE --specs=nano.specs --specs=rdimon.specs)

  target_link_libraries(${elf} PRIVATE "-Wl,-Map=\"${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test_${name}.map\" -T\"${CMAKE_CURRENT_SOURCE_DIR}/device-test.ld\"")
  target_link_libraries(${elf} PRIVATE -Wl,--defsym=STACK_SIZE=${STACK_SIZE} -Wl,-defsym=HEAP_SIZE=${HEAP_SIZE})

  # Since noiseprotocol and wallycore are external projects we need to specify the dependency
  add_dependencies(${elf} noise-c)
  add_dependencies(${elf} libwally-core)
  add_dependencies(${elf} firmware-bitboxbase-rust)
  # We must link against libc before asf4-drivers-min because malloc depends on _sbrk
  # We must mark "exception_table" as used, otherwise it won't be linked in since it is in a static library
  target_link_libraries(${elf}
    PRIVATE
      -Wl,-u,exception_table
      ${BITBOXBASE_LIBRARIES}
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



# The MPU tests are special, we don't want to link with the regular interrupt handlers
set(name mpu)
set(elf fw_test_${name}.elf)
add_executable(${elf} ${CMAKE_CURRENT_SOURCE_DIR}/src/test_${name}.c)
# We need the "asm" extension for the MPU test.
set_target_properties(fw_test_mpu.elf PROPERTIES COMPILE_FLAGS "-std=gnu99")
target_link_libraries(${elf} PRIVATE --specs=nano.specs --specs=rdimon.specs)
target_compile_options(${elf} PRIVATE --specs=nano.specs --specs=rdimon.specs)

target_link_libraries(${elf} PRIVATE "-Wl,-Map=\"${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test_${name}.map\" -T\"${CMAKE_CURRENT_SOURCE_DIR}/device-test.ld\"")
target_link_libraries(${elf} PRIVATE -Wl,--defsym=STACK_SIZE=${STACK_SIZE} -Wl,-defsym=HEAP_SIZE=${HEAP_SIZE})


# CREATE A SPECIAL PLATFORM LIBRARY WITHOUT HANDLERS
add_custom_target(bitbox02-platform-ohni-handlers-gen
  ${CMAKE_OBJCOPY} -L HardFault_Handler -L MemManage_Handler
  ${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}/libbitbox02-platform.a
  ${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}/libbitbox02-platform-ohni-handlers.a)
add_dependencies(bitbox02-platform-ohni-handlers-gen bitbox02-platform)
add_dependencies(${elf} bitbox02-platform-ohni-handlers-gen)
add_library(bitbox02-platform-ohni-handlers STATIC IMPORTED)
set_property(
  TARGET bitbox02-platform-ohni-handlers
  PROPERTY IMPORTED_LOCATION
    ${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}/libbitbox02-platform-ohni-handlers.a)
get_property(BITBOX02_PLATFORM_INCLUDES TARGET bitbox02-platform PROPERTY INTERFACE_INCLUDE_DIRECTORIES)
target_include_directories(${elf} PRIVATE ${BITBOX02_PLATFORM_INCLUDES})


# Since noiseprotocol and wallycore are external projects we need to specify the dependency
add_dependencies(${elf} noise-c)
add_dependencies(${elf} libwally-core)
target_link_libraries(${elf}
  PRIVATE
    -Wl,-u,exception_table
    -Wl,--start-group
    fatfs
    bitbox02-platform-ohni-handlers
    -Wl,--end-group
    bitbox02_rust_c
    ${LIBRARIES}
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
