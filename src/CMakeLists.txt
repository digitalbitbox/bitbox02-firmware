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

set(DBB-FIRMWARE-COMMON-SOURCES
  ${CMAKE_SOURCE_DIR}/src/commander/commander.c
  ${CMAKE_SOURCE_DIR}/src/commander/commander_states.c
  ${CMAKE_SOURCE_DIR}/src/keystore.c
  ${CMAKE_SOURCE_DIR}/src/random.c
  ${CMAKE_SOURCE_DIR}/src/attestation.c
  ${CMAKE_SOURCE_DIR}/src/hardfault.c
  ${CMAKE_SOURCE_DIR}/src/sd.c
  ${CMAKE_SOURCE_DIR}/src/hww.c
  ${CMAKE_SOURCE_DIR}/src/memory/bitbox02_smarteeprom.c
  ${CMAKE_SOURCE_DIR}/src/memory/memory.c
  ${CMAKE_SOURCE_DIR}/src/salt.c
  ${CMAKE_SOURCE_DIR}/src/i2c_ecc.c
  ${CMAKE_SOURCE_DIR}/src/usb/noise.c
  ${CMAKE_SOURCE_DIR}/src/backup.c
  ${CMAKE_SOURCE_DIR}/src/restore.c
  ${CMAKE_SOURCE_DIR}/src/reset.c
  ${CMAKE_SOURCE_DIR}/src/cipher/cipher.c
  ${CMAKE_SOURCE_DIR}/src/queue.c
  ${CMAKE_SOURCE_DIR}/src/usb/usb_processing.c
  ${CMAKE_SOURCE_DIR}/src/workflow/reboot.c
  ${CMAKE_SOURCE_DIR}/src/workflow/restore.c
  ${CMAKE_SOURCE_DIR}/src/apps/common/bip32.c
  ${CMAKE_SOURCE_DIR}/src/workflow/restore_from_mnemonic.c
  ${CMAKE_SOURCE_DIR}/src/workflow/workflow.c
)
set(DBB-FIRMWARE-COMMON-SOURCES ${DBB-FIRMWARE-COMMON-SOURCES} PARENT_SCOPE)

set(DBB-FIRMWARE-USB-SOURCES
  ${CMAKE_SOURCE_DIR}/src/usb/usb_packet.c
  ${CMAKE_SOURCE_DIR}/src/u2f/u2f_packet.c
)
set(DBB-FIRMWARE-USB-SOURCES ${DBB-FIRMWARE-USB-SOURCES} PARENT_SCOPE)

set(DBB-FIRMWARE-USART-SOURCES
  ${CMAKE_SOURCE_DIR}/src/usart/usart_frame.c
)
set(DBB-FIRMWARE-USART-SOURCES ${DBB-FIRMWARE-USART-SOURCES} PARENT_SCOPE)

set(DBB-FIRMWARE-UI-COMMON-SOURCES
    ${CMAKE_SOURCE_DIR}/src/ui/fonts/font_a_9X9.c
    ${CMAKE_SOURCE_DIR}/src/ui/fonts/font_a_11X12.c
    ${CMAKE_SOURCE_DIR}/src/ui/fonts/font_a_13X14.c
    ${CMAKE_SOURCE_DIR}/src/ui/fonts/font_a_15X16.c
    ${CMAKE_SOURCE_DIR}/src/ui/fonts/font_a_17X18.c
    ${CMAKE_SOURCE_DIR}/src/ui/fonts/monogram_5X9.c
    ${CMAKE_SOURCE_DIR}/src/ui/fonts/password_9X9.c
    ${CMAKE_SOURCE_DIR}/src/ui/fonts/password_11X12.c
    ${CMAKE_SOURCE_DIR}/src/ui/screen_stack.c
    ${CMAKE_SOURCE_DIR}/src/ui/event_handler.c
    ${CMAKE_SOURCE_DIR}/src/ui/ui_util.c
)
set(DBB-FIRMWARE-UI-COMMON-SOURCES ${DBB-FIRMWARE-UI-COMMON-SOURCES} PARENT_SCOPE)

# UI items that are tied to their platform.
set(DBB-FIRMWARE-UI-SOURCES
    ${CMAKE_SOURCE_DIR}/src/ui/components/show_logo.c
    ${CMAKE_SOURCE_DIR}/src/ui/components/waiting.c
    ${CMAKE_SOURCE_DIR}/src/ui/screen_process.c
    ${CMAKE_SOURCE_DIR}/src/ui/ugui/ugui.c
    ${CMAKE_SOURCE_DIR}/src/touch/gestures.c
)
set(DBB-FIRMWARE-UI-SOURCES ${DBB-FIRMWARE-UI-SOURCES} PARENT_SCOPE)

# Component files that are not tied to a particular platform.
set(DBB-FIRMWARE-COMPONENT-SOURCES
    ${CMAKE_SOURCE_DIR}/src/ui/components/trinary_choice.c
    ${CMAKE_SOURCE_DIR}/src/ui/components/trinary_input_char.c
    ${CMAKE_SOURCE_DIR}/src/ui/components/trinary_input_string.c
    ${CMAKE_SOURCE_DIR}/src/ui/components/entry_screen.c
    ${CMAKE_SOURCE_DIR}/src/ui/components/knight_rider.c
    ${CMAKE_SOURCE_DIR}/src/ui/components/right_arrow.c
    ${CMAKE_SOURCE_DIR}/src/ui/components/left_arrow.c
    ${CMAKE_SOURCE_DIR}/src/ui/components/icon_button.c
    ${CMAKE_SOURCE_DIR}/src/ui/components/confirm_gesture.c
    ${CMAKE_SOURCE_DIR}/src/ui/components/label.c
    ${CMAKE_SOURCE_DIR}/src/ui/components/confirm.c
    ${CMAKE_SOURCE_DIR}/src/ui/components/confirm_button.c
    ${CMAKE_SOURCE_DIR}/src/ui/components/keyboard_switch.c
    ${CMAKE_SOURCE_DIR}/src/ui/components/orientation_arrows.c
    ${CMAKE_SOURCE_DIR}/src/ui/components/info_centered.c
    ${CMAKE_SOURCE_DIR}/src/ui/components/scroll_through_all_variants.c
    ${CMAKE_SOURCE_DIR}/src/ui/components/status.c
    ${CMAKE_SOURCE_DIR}/src/ui/components/image.c
    ${CMAKE_SOURCE_DIR}/src/ui/components/button.c
    ${CMAKE_SOURCE_DIR}/src/ui/components/insert_sd_card.c
    ${CMAKE_SOURCE_DIR}/src/ui/components/remove_sd_card.c
    ${CMAKE_SOURCE_DIR}/src/ui/components/confirm_mnemonic.c
    ${CMAKE_SOURCE_DIR}/src/ui/components/ui_images.c
    ${CMAKE_SOURCE_DIR}/src/ui/components/confirm_transaction.c
)
set(DBB-FIRMWARE-COMPONENT-SOURCES ${DBB-FIRMWARE-COMPONENT-SOURCES} PARENT_SCOPE)

# All workflows that don't depend on a particular platform.
set(DBB-FIRMWARE-WORKFLOW-SOURCES
  ${CMAKE_SOURCE_DIR}/src/workflow/blocking.c
  ${CMAKE_SOURCE_DIR}/src/workflow/cancel.c
  ${CMAKE_SOURCE_DIR}/src/workflow/trinary_input.c
  ${CMAKE_SOURCE_DIR}/src/workflow/confirm.c
  ${CMAKE_SOURCE_DIR}/src/workflow/confirm_time.c
  ${CMAKE_SOURCE_DIR}/src/workflow/status.c
  ${CMAKE_SOURCE_DIR}/src/workflow/password.c
  ${CMAKE_SOURCE_DIR}/src/workflow/password_enter.c
  ${CMAKE_SOURCE_DIR}/src/workflow/create_seed.c
  ${CMAKE_SOURCE_DIR}/src/workflow/unlock.c
  ${CMAKE_SOURCE_DIR}/src/workflow/show_mnemonic.c
  ${CMAKE_SOURCE_DIR}/src/workflow/pairing.c
  ${CMAKE_SOURCE_DIR}/src/workflow/verify_pub.c
  ${CMAKE_SOURCE_DIR}/src/workflow/verify_recipient.c
  ${CMAKE_SOURCE_DIR}/src/workflow/verify_total.c
  ${CMAKE_SOURCE_DIR}/src/workflow/sdcard.c
  ${CMAKE_SOURCE_DIR}/src/workflow/backup.c
  ${CMAKE_SOURCE_DIR}/src/workflow/reset.c
)
set(DBB-FIRMWARE-WORKFLOW-SOURCES ${DBB-FIRMWARE-WORKFLOW-SOURCES} PARENT_SCOPE)

set(DBB-BOOTLOADER-SOURCES
  ${CMAKE_SOURCE_DIR}/src/pukcc/curve_p256.c
  ${CMAKE_SOURCE_DIR}/src/pukcc/pukcc.c
  ${CMAKE_SOURCE_DIR}/src/bootloader/bootloader.c
  ${CMAKE_SOURCE_DIR}/src/bootloader/startup.c
  ${CMAKE_SOURCE_DIR}/src/bootloader/mpu_regions.c
  ${CMAKE_SOURCE_DIR}/src/queue.c
  ${CMAKE_SOURCE_DIR}/src/usb/usb_processing.c
  ${CMAKE_SOURCE_DIR}/src/ui/ugui/ugui.c
  ${CMAKE_SOURCE_DIR}/src/ui/fonts/font_a_9X9.c
  ${CMAKE_SOURCE_DIR}/src/hardfault.c
  ${CMAKE_SOURCE_DIR}/src/ui/components/ui_images.c
)
set(DBB-BOOTLOADER-SOURCES ${DBB-BOOTLOADER-SOURCES} PARENT_SCOPE)

set(DRIVER-SOURCES
  ${CMAKE_SOURCE_DIR}/src/memory/mpu.c
  ${CMAKE_SOURCE_DIR}/src/memory/nvmctrl.c
  ${CMAKE_SOURCE_DIR}/src/memory/smarteeprom.c
  ${CMAKE_SOURCE_DIR}/src/screen.c
  ${CMAKE_SOURCE_DIR}/src/platform/driver_init.c
  ${CMAKE_SOURCE_DIR}/src/platform/platform_init.c
  ${CMAKE_SOURCE_DIR}/src/qtouch/qtouch.c
  ${CMAKE_SOURCE_DIR}/src/ui/oled/oled.c
)
set(DRIVER-SOURCES ${DRIVER-SOURCES} PARENT_SCOPE)

# Modules that provide HW support for the BitBox02,
# and don't depend on any PRODUCT_* macro definition.
set(PLATFORM-BITBOX02-SOURCES
  ${CMAKE_SOURCE_DIR}/src/usb/class/hid/hid.c
  ${CMAKE_SOURCE_DIR}/src/usb/class/hid/hww/hid_hww.c
  ${DBB-FIRMWARE-USB-SOURCES}
)
set(PLATFORM-BITBOX02-SOURCES ${PLATFORM-BITBOX02-SOURCES} PARENT_SCOPE)

# Modules that provide HW support for the BitBoxBase,
# and don't depend on any PRODUCT_* macro definition.
set(PLATFORM-BITBOXBASE-SOURCES
  ${CMAKE_SOURCE_DIR}/src/platform/bitboxbase/leds.c
  ${CMAKE_SOURCE_DIR}/src/usart/usart_hww.c
  ${DBB-FIRMWARE-USART-SOURCES}
)
set(PLATFORM-BITBOXBASE-SOURCES ${PLATFORM-BITBOXBASE-SOURCES} PARENT_SCOPE)

# Modules specific to the BitBoxBase platform,
# that depend on the PRODUCT_* macros.
set(BITBOXBASE-ONLY-SOURCES
  ${CMAKE_SOURCE_DIR}/src/usart/usart.c
  )

# Modules specific to the BitBox02 platform,
# that depend on the PRODUCT_* macros.
set(BITBOX02-ONLY-SOURCES
  ${CMAKE_SOURCE_DIR}/src/usb/usb.c
  ${CMAKE_SOURCE_DIR}/src/usb/usb_frame.c
  ${CMAKE_SOURCE_DIR}/src/sd_mmc/sd_mmc_start.c
  )

set(BITBOXBASE-FIRMWARE-SOURCES
  ${DBB-FIRMWARE-COMMON-SOURCES}
  ${BITBOXBASE-ONLY-SOURCES}
  ${CMAKE_SOURCE_DIR}/src/bitboxbase/bitboxbase_background.c
  ${CMAKE_SOURCE_DIR}/src/bitboxbase/bitboxbase_watchdog.c
  ${CMAKE_SOURCE_DIR}/src/bitboxbase/bitboxbase_screensaver.c
  ${CMAKE_SOURCE_DIR}/src/bitboxbase/bitboxbase_status.c
)
set(BITBOXBASE-FIRMWARE-SOURCES ${BITBOXBASE-FIRMWARE-SOURCES} PARENT_SCOPE)

set(BITBOX02-FIRMWARE-SOURCES
  ${DBB-FIRMWARE-COMMON-SOURCES}
  ${BITBOX02-ONLY-SOURCES}
  ${CMAKE_SOURCE_DIR}/src/firmware_main_loop.c
)
set(BITBOX02-FIRMWARE-SOURCES ${BITBOX02-FIRMWARE-SOURCES} PARENT_SCOPE)

set(CRYPTOAUTHLIB-SOURCES
  ${CMAKE_SOURCE_DIR}/src/securechip/securechip.c
)
set(CRYPTOAUTHLIB-SOURCES ${CRYPTOAUTHLIB-SOURCES} PARENT_SCOPE)

set(ETHEREUM-SOURCES
  ${CMAKE_SOURCE_DIR}/src/apps/eth/eth.c
  ${CMAKE_SOURCE_DIR}/src/apps/eth/eth_common.c
  ${CMAKE_SOURCE_DIR}/src/apps/eth/eth_params.c
  ${CMAKE_SOURCE_DIR}/src/apps/eth/eth_sighash.c
  ${CMAKE_SOURCE_DIR}/src/apps/eth/eth_sign.c
  ${CMAKE_SOURCE_DIR}/src/apps/eth/eth_sign_msg.c
  ${CMAKE_SOURCE_DIR}/src/apps/eth/eth_verify.c
  ${CMAKE_SOURCE_DIR}/src/commander/commander_eth.c
)
set(ETHEREUM-SOURCES ${ETHEREUM-SOURCES} PARENT_SCOPE)

set(FIRMWARE-DRIVER-SOURCES
  ${CMAKE_SOURCE_DIR}/src/usb/class/hid/u2f/hid_u2f.c
)
set(FIRMWARE-DRIVER-SOURCES ${FIRMWARE-DRIVER-SOURCES} PARENT_SCOPE)

set(FIRMWARE-U2F-SOURCES
  ${CMAKE_SOURCE_DIR}/src/u2f.c
  ${CMAKE_SOURCE_DIR}/src/u2f/u2f_app.c
)
set(FIRMWARE-U2F-SOURCES ${FIRMWARE-U2F-SOURCES} PARENT_SCOPE)

#-----------------------------------------------------------------------------
# Include directories

set(INCLUDES
  ${CMAKE_SOURCE_DIR}/src
  ${CMAKE_SOURCE_DIR}/src/platform
  ${CMAKE_SOURCE_DIR}/src/platform/bitboxbase
  ${CMAKE_SOURCE_DIR}/src/qtouch
  ${CMAKE_SOURCE_DIR}/src/usb/class
  ${CMAKE_SOURCE_DIR}/src/usb/class/hid
  ${CMAKE_SOURCE_DIR}/src/usb/class/hid/hww
  ${CMAKE_SOURCE_DIR}/src/usb/class/hid/u2f
)
set(INCLUDES ${INCLUDES} PARENT_SCOPE)

set(SYSTEMINCLUDES
  ${CMAKE_BINARY_DIR}/messages
)
set(SYSTEMINCLUDES ${SYSTEMINCLUDES} PARENT_SCOPE)

#-----------------------------------------------------------------------------
# Build embedded firmware

# TODO: Not needed when building bootlaoder..
# Since the nanopb is included in the source tree and not in the sysroot (/usr/local/arm-none-eabi) we have to disable searching in the sysroot.
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE NEVER)
find_package(Nanopb REQUIRED)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

set(APP-BTC-SOURCES
  ${CMAKE_SOURCE_DIR}/src/commander/commander_btc.c
  ${CMAKE_SOURCE_DIR}/src/apps/btc/btc.c
  ${CMAKE_SOURCE_DIR}/src/apps/btc/btc_common.c
  ${CMAKE_SOURCE_DIR}/src/apps/btc/btc_params.c
  ${CMAKE_SOURCE_DIR}/src/apps/btc/btc_sign.c
  ${CMAKE_SOURCE_DIR}/src/apps/btc/btc_bip143.c
  ${CMAKE_SOURCE_DIR}/src/apps/btc/confirm_multisig.c
  ${CMAKE_SOURCE_DIR}/src/apps/btc/confirm_locktime_rbf.c
  )
set(APP-BTC-SOURCES ${APP-BTC-SOURCES} PARENT_SCOPE)

get_property(WALLY_INCLUDES TARGET wallycore PROPERTY INTERFACE_INCLUDE_DIRECTORIES)

add_library(util
  ${CMAKE_SOURCE_DIR}/src/util.c
  ${CMAKE_SOURCE_DIR}/src/util/util_string.c
)
target_include_directories(util PRIVATE ${INCLUDES})
target_include_directories(util SYSTEM PUBLIC ${SYSTEMINCLUDES})
target_include_directories(util SYSTEM PUBLIC ${NANOPB_INCLUDE_DIRS})
target_include_directories(util SYSTEM PUBLIC ${CMAKE_BINARY_DIR}/src)

set(FIRMWARE-SOURCES
  ${DBB-FIRMWARE-SOURCES}
  ${DBB-FIRMWARE-UI-SOURCES}
  ${FIRMWARE-DRIVER-SOURCES}
  ${DRIVER-SOURCES}
  ${DBB-FIRMWARE-PROTOBUF-SOURCES}
  ${CRYPTOAUTHLIB-SOURCES}
  ${ETHEREUM-SOURCES}
  ${CMAKE_SOURCE_DIR}/src/common_main.c
)

set(BOOTLOADER-SOURCES
  ${DBB-BOOTLOADER-SOURCES}
  ${DBB-FIRMWARE-UI-SOURCES}
  ${DRIVER-SOURCES}
)

set_source_files_properties(
  ${DBB-FIRMWARE-PROTOBUF-SOURCES}
  PROPERTIES GENERATED TRUE
)

if(CMAKE_CROSSCOMPILING)
  get_property(SAMD51A_INCLUDES TARGET samd51a-ds PROPERTY INTERFACE_INCLUDE_DIRECTORIES)
  get_property(ASF4_MIN_INCLUDES TARGET asf4-drivers-min PROPERTY INTERFACE_INCLUDE_DIRECTORIES)
  get_property(ASF4_INCLUDES TARGET asf4-drivers PROPERTY INTERFACE_INCLUDE_DIRECTORIES)
  get_property(CMSIS_INCLUDES TARGET CMSIS PROPERTY INTERFACE_INCLUDE_DIRECTORIES)
  get_property(WALLY_INCLUDES TARGET wallycore PROPERTY INTERFACE_INCLUDE_DIRECTORIES)

  set(helper_libraries app_btc-btc app_btc-multi ui_common components workflows)
  add_library(app_btc-btc ${APP-BTC-SOURCES})
  target_compile_definitions(app_btc-btc PUBLIC "APP_BTC=1" "APP_LTC=0")
  target_link_libraries(app_btc-btc noiseprotocol wallycore secp256k1)

  add_library(app_btc-multi ${APP-BTC-SOURCES})
  target_compile_definitions(app_btc-multi PUBLIC "APP_BTC=1" "APP_LTC=1")
  target_link_libraries(app_btc-multi noiseprotocol wallycore secp256k1 util)

  add_library(ui_common ${DBB-FIRMWARE-UI-COMMON-SOURCES})

  add_library(components ${DBB-FIRMWARE-COMPONENT-SOURCES})
  target_link_libraries(components ui_common)

  add_library(workflows ${DBB-FIRMWARE-WORKFLOW-SOURCES})
  target_link_libraries(workflows components secp256k1)


  foreach(include ${INCLUDES} ${SYSTEMINCLUDES} ${SAMD51A_INCLUDES} ${ASF4_INCLUDES} ${ASF4_MIN_INCLUDES} ${CMSIS_INCLUDES} ${NANOPB_INCLUDE_DIRS} ${WALLY_INCLUDES})
    list(APPEND RUST_INCLUDES -I${include})
    target_include_directories(components SYSTEM PRIVATE ${include})
    target_include_directories(workflows SYSTEM PRIVATE ${include})
    foreach (library ${helper_libraries})
      target_include_directories(${library} PRIVATE ${INCLUDES})
      target_include_directories(${library} SYSTEM PUBLIC ${SYSTEMINCLUDES})
      target_include_directories(${library} SYSTEM PUBLIC ${NANOPB_INCLUDE_DIRS})
      target_include_directories(${library} SYSTEM PUBLIC ${CMAKE_BINARY_DIR}/src)
      target_link_libraries(${library} base32 util)
    endforeach()
  endforeach()

  if(CMAKE_BUILD_TYPE STREQUAL "DEBUG")
    set(RUST_PROFILE "debug")
  else()
    set(RUST_PROFILE "release")
    set(RUST_CARGO_FLAG "--release")
    set(RUSTFLAGS --remap-path-prefix=${CMAKE_CURRENT_SOURCE_DIR}/rust=src)
  endif()

  add_dependencies(workflows generate-protobufs)

  set(LIBBITBOX02_RUST_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/rust/bitbox02-rust)
  set(LIBBITBOX02_RUST_BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR}/rust/bitbox02-rust/target)
  set(LIBBITBOX02_RUST ${CMAKE_CURRENT_BINARY_DIR}/rust/bitbox02-rust/target/thumbv7em-none-eabi/${RUST_PROFILE}/libbitbox02_rust.a)

  # rust-bindgen to generate rust declarations from c-headers.
  # The compiled binary to avoid recompiling bindgen on every clean build
  find_program(BINDGEN bindgen)
  # cbindgen is used to generate the c-headers from rust code.
  find_program(CBINDGEN cbindgen)
  # cargo is the rust build system and dependency manager
  find_program(CARGO cargo)

  add_custom_target(rust-bindgen
    # Generate rust bindings
    COMMAND
      ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_BINARY_DIR}/rust
    COMMAND
      ${BINDGEN}
      --output ${CMAKE_CURRENT_BINARY_DIR}/rust/bindings.rs
      --use-core
      --ctypes-prefix c_types
      --whitelist-function delay_us
      --whitelist-function delay_ms
      --whitelist-function UG_PutString
      --whitelist-function UG_FontSelect
      --whitelist-function UG_ClearBuffer
      --whitelist-function UG_SendBuffer
      --whitelist-function workflow_confirm
      --whitelist-function screen_print_debug
      --whitelist-function ui_screen_stack_push
      --whitelist-function ui_screen_stack_pop
      --whitelist-function label_create
      --whitelist-function bitboxbase_watchdog_reset
      --whitelist-function bitboxbase_screensaver_reset
      --whitelist-function leds_turn_small_led
      --whitelist-function leds_turn_big_led
      --whitelist-function wally_sha256
      --whitelist-type component_t
      --whitelist-type commander_error_t
      --whitelist-type BitBoxBaseRequest
      --whitelist-var ".*_tag"
      --whitelist-var font_font_a_9X9
      --whitelist-var font_monogram_5X9
      --whitelist-var WALLY_OK
      ${CMAKE_CURRENT_SOURCE_DIR}/rust/bitbox02-sys/wrapper.h --
      -D__SAMD51J20A__ -DPB_NO_PACKED_STRUCTS=1 -DPB_FIELD_16BIT=1 -fshort-enums --target=thumbv7em-none-eabi -mcpu=cortex-m4 -mthumb -mfloat-abi=soft --sysroot=${CMAKE_SYSROOT} ${RUST_INCLUDES}
    )
  add_dependencies(rust-bindgen generate-protobufs)

  add_custom_target(rust
    # Build rust library
    COMMAND
      ${CMAKE_COMMAND} -E env CMAKE_CURRENT_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR} RUSTFLAGS=${RUSTFLAGS} ${CARGO} build --manifest-path ${LIBBITBOX02_RUST_SOURCE_DIR}/Cargo.toml --target-dir ${LIBBITBOX02_RUST_BINARY_DIR} ${RUST_CARGO_FLAG} --target thumbv7em-none-eabi
    # Rust packages stdlib functions which we must remove/weaken
    COMMAND
      ${CMAKE_OBJCOPY} -N memset -N memcpy -N memmove -W memcmp ${LIBBITBOX02_RUST}
    BYPRODUCTS
      ${LIBBITBOX02_RUST}
  )
  add_dependencies(rust rust-bindgen)

  # The autogenerated bindings cannot be tested right now. We anyway generate them for another platform so the tests are invalid.
  add_custom_target(rust-test
    #COMMAND
    #  ${CMAKE_COMMAND} -E env CMAKE_CURRENT_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR} ${CARGO} test --manifest-path ${CMAKE_CURRENT_SOURCE_DIR}/rust/bitbox02-sys/Cargo.toml --target-dir ${LIBBITBOX02_RUST_BINARY_DIR} ${RUST_CARGO_FLAG}
    COMMAND
      ${CMAKE_COMMAND} -E env CMAKE_CURRENT_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR} ${CARGO} test --manifest-path ${CMAKE_CURRENT_SOURCE_DIR}/rust/bitbox02/Cargo.toml --target-dir ${LIBBITBOX02_RUST_BINARY_DIR} ${RUST_CARGO_FLAG}
    COMMAND
      ${CMAKE_COMMAND} -E env CMAKE_CURRENT_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR} ${CARGO} test --manifest-path ${LIBBITBOX02_RUST_SOURCE_DIR}/Cargo.toml --target-dir ${LIBBITBOX02_RUST_BINARY_DIR} ${RUST_CARGO_FLAG}
    )
  add_dependencies(rust-test rust-bindgen)

  add_custom_target(rust-cbindgen
    # Generate c-headers for the rust library
    COMMAND
      ${CBINDGEN} --quiet --config ${CMAKE_CURRENT_SOURCE_DIR}/rust/cbindgen.toml --output ${CMAKE_CURRENT_BINARY_DIR}/rust/bitbox02_rust.h ${LIBBITBOX02_RUST_SOURCE_DIR}
    BYPRODUCTS
      ${CMAKE_CURRENT_BINARY_DIR}/rust/bitbox02_rust.h
  )

  # TODO(nc): Add dependency on global "doc" target on this when api-docs branch is merged
  add_custom_target(rust-docs
    COMMAND
      ${CMAKE_COMMAND} -E env SYSROOT=${CMAKE_SYSROOT} INCLUDES="${RUST_INCLUDES}" ${CARGO} doc --document-private-items --manifest-path ${LIBBITBOX02_RUST_SOURCE_DIR}/Cargo.toml --target-dir ${CMAKE_BINARY_DIR}/docs-rust ${RUST_CARGO_FLAG} --target thumbv7em-none-eabi
    COMMAND
      ${CMAKE_COMMAND} -E echo "See docs at file://${CMAKE_BINARY_DIR}/docs-rust/thumbv7em-none-eabi/doc/bitbox02_rust/index.html"
  )

  add_library(bitbox02_rust STATIC IMPORTED)
  set_property(TARGET bitbox02_rust PROPERTY IMPORTED_LOCATION ${LIBBITBOX02_RUST})

  set(STACK_SIZE "0x10000" CACHE STRING "Specify stack size for bootloader/firmware")
  set(STACK_SIZE ${STACK_SIZE} PARENT_SCOPE)
  set(HEAP_SIZE "0x18000" CACHE STRING "Specify heap size for bootloader/firmware")
  set(HEAP_SIZE ${HEAP_SIZE} PARENT_SCOPE)

  add_library(bitbox02-platform ${PLATFORM-BITBOX02-SOURCES})
  target_link_libraries(bitbox02-platform asf4-drivers-min util workflows)
  target_include_directories(bitbox02-platform PRIVATE ${INCLUDES})
  target_include_directories(bitbox02-platform SYSTEM PUBLIC ${SYSTEMINCLUDES})
  target_include_directories(bitbox02-platform SYSTEM PUBLIC ${NANOPB_INCLUDE_DIRS})
  target_include_directories(bitbox02-platform SYSTEM PUBLIC ${CMAKE_BINARY_DIR}/src)

  add_library(bitboxbase-platform ${PLATFORM-BITBOXBASE-SOURCES})
  target_link_libraries(bitboxbase-platform asf4-drivers util workflows)
  target_include_directories(bitboxbase-platform PRIVATE ${INCLUDES})
  target_include_directories(bitboxbase-platform SYSTEM PUBLIC ${SYSTEMINCLUDES})
  target_include_directories(bitboxbase-platform SYSTEM PUBLIC ${NANOPB_INCLUDE_DIRS})
  target_include_directories(bitboxbase-platform SYSTEM PUBLIC ${CMAKE_BINARY_DIR}/src)

  # If a bootloader that locks the bootloader is flashed the bootloader area is permanently read-only.
  set(BOOTLOADERS-BITBOX02
    bootloader # Runs signed firmware
    bootloader-development # Runs signed/unsigned firmware and has bootloader menu
    bootloader-development-locked # Runs signed/unsigned firmware, has bootloader menu and bootloader is locked
    bootloader-semihosting # Runs signed/unsigned firmware, has bootloader menu and enables semihosting
    bootloader-production # Runs signed firmware and bootloader is locked
    bootloader-btc # Runs signed (btc-only keys) firmware
    bootloader-btc-development # Runs signed/unsigned firmware and has bootloader menu
    bootloader-btc-production # Runs signed (btc-only keys) firmware and bootloader is locked
  )
  set(BOOTLOADERS-BITBOXBASE
    bootloader-bitboxbase # Runs signed (base keys) firmware
    bootloader-bitboxbase-development # Runs signed/unsigned firmware and has bootloader menu
    bootloader-bitboxbase-semihosting # Runs signed/unsigned firmware, has bootloader menu and enables semihosting
    bootloader-bitboxbase-production # Runs signed (base keys) firmware and bootloader is locked
  )
  set(BOOTLOADERS
    ${BOOTLOADERS-BITBOX02}
    ${BOOTLOADERS-BITBOXBASE}
  )
  set(BOOTLOADERS ${BOOTLOADERS} PARENT_SCOPE)
  foreach(bootloader ${BOOTLOADERS})
    set(elf ${bootloader}.elf)
    add_executable(${elf} ${BOOTLOADER-SOURCES})
    add_dependencies(${elf} noise-c)
    target_link_libraries(${elf} PRIVATE c asf4-drivers-min -Wl,-u,exception_table)
    target_include_directories(${elf} PRIVATE ${INCLUDES})
    target_include_directories(${elf} SYSTEM PRIVATE ${SYSTEMINCLUDES})
    target_compile_definitions(${elf} PRIVATE BOOTLOADER "APP_BTC=0" "APP_LTC=0" "APP_ETH=0" "APP_U2F=0")
    # needed to find version.h
    target_include_directories(${elf} PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
    # needed to find bootloader_version.h
    target_include_directories(${elf} PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/bootloader)
    target_link_libraries(${elf} PRIVATE "-Wl,-Map=\"${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${bootloader}.map\" -T\"${CMAKE_SOURCE_DIR}/bootloader.ld\"")
    target_link_libraries(${elf} PRIVATE -Wl,--defsym=STACK_SIZE=${STACK_SIZE} -Wl,-defsym=HEAP_SIZE=${HEAP_SIZE})
    target_link_libraries(${elf} PRIVATE ${QTOUCHLIB_A} ${QTOUCHLIB_B} ${QTOUCHLIB_T})
    # Select the smaller version of libc called nano.
    target_compile_options(${elf} PRIVATE --specs=nano.specs)
    target_link_libraries(${elf} PRIVATE --specs=nano.specs)
    string(FIND ${bootloader} semihosting SEMIHOSTING_FOUND)
    target_compile_definitions(${elf} PRIVATE "APP_U2F=0" "APP_BTC=0" "APP_ETH=0" "APP_LTC=0")
    if(SEMIHOSTING_FOUND EQUAL -1)
      target_compile_options(${elf} PRIVATE --specs=nosys.specs)
      target_link_libraries(${elf} PRIVATE --specs=nosys.specs)
    else()
      # Select an implementation of the system calls that can communicate with the debugger
      target_compile_options(${elf} PRIVATE --specs=rdimon.specs)
      target_link_libraries(${elf} PRIVATE --specs=rdimon.specs)
    endif()
  endforeach(bootloader)

  foreach(bootloader ${BOOTLOADERS-BITBOX02})
    target_link_libraries(${bootloader}.elf PRIVATE bitbox02-platform)
    target_sources(${bootloader}.elf PRIVATE ${BITBOX02-ONLY-SOURCES})
  endforeach(bootloader)

  foreach(bootloader ${BOOTLOADERS-BITBOXBASE})
    target_link_libraries(${bootloader}.elf PRIVATE bitboxbase-platform)
    target_sources(${bootloader}.elf PRIVATE ${BITBOXBASE-ONLY-SOURCES})
  endforeach(bootloader)

  target_compile_definitions(bootloader.elf PRIVATE PRODUCT_BITBOX_MULTI)
  target_compile_definitions(bootloader-development.elf PRIVATE PRODUCT_BITBOX_MULTI BOOTLOADER_DEVDEVICE)
  target_compile_definitions(bootloader-semihosting.elf PRIVATE PRODUCT_BITBOX_MULTI BOOTLOADER_DEVDEVICE SEMIHOSTING)
  target_compile_definitions(bootloader-development-locked.elf PRIVATE PRODUCT_BITBOX_MULTI BOOTLOADER_DEVDEVICE BOOTLOADER_PRODUCTION)
  set_property(TARGET bootloader-development-locked.elf PROPERTY EXCLUDE_FROM_ALL ON)


  target_compile_definitions(bootloader-production.elf PRIVATE PRODUCT_BITBOX_MULTI BOOTLOADER_PRODUCTION)
  set_property(TARGET bootloader-production.elf PROPERTY EXCLUDE_FROM_ALL ON)

  target_compile_definitions(bootloader-btc.elf PRIVATE PRODUCT_BITBOX_BTCONLY)
  target_compile_definitions(bootloader-btc-development.elf PRIVATE PRODUCT_BITBOX_BTCONLY BOOTLOADER_DEVDEVICE)
  target_compile_definitions(bootloader-btc-production.elf PRIVATE PRODUCT_BITBOX_BTCONLY BOOTLOADER_PRODUCTION)
  set_property(TARGET bootloader-btc-production.elf PROPERTY EXCLUDE_FROM_ALL ON)

  target_compile_definitions(bootloader-bitboxbase.elf PRIVATE PRODUCT_BITBOX_BASE)
  target_compile_definitions(bootloader-bitboxbase-development.elf PRIVATE BOOTLOADER_DEVDEVICE PRODUCT_BITBOX_BASE)
  target_compile_definitions(bootloader-bitboxbase-semihosting.elf PRIVATE BOOTLOADER_DEVDEVICE PRODUCT_BITBOX_BASE SEMIHOSTING)
  target_compile_definitions(bootloader-bitboxbase-production.elf PRIVATE BOOTLOADER_PRODUCTION PRODUCT_BITBOX_BASE)
  set_property(TARGET bootloader-bitboxbase-production.elf PROPERTY EXCLUDE_FROM_ALL ON)

  set(FIRMWARES-BITBOX02
    firmware # Firmware MULTI
    firmware-semihosting # Firmware MULTI with semihosting enabled
    firmware-btc # Firmware BTC-ONLY
    factory-setup # Factory-setup
  )
  set(FIRMWARES-BITBOXBASE
    firmware-bitboxbase # Firmware BASE
    firmware-bitboxbase-semihosting # Firmware BASE with semihosting
    factory-setup-bitboxbase # Factory-setup
  )
  set(FIRMWARES ${FIRMWARES-BITBOX02} ${FIRMWARES-BITBOXBASE})
  set(FIRMWARES ${FIRMWARES} PARENT_SCOPE)

  foreach(firmware ${FIRMWARES})
    set(elf ${firmware}.elf)
    add_executable(${elf} ${FIRMWARE-SOURCES})
    target_link_libraries(${elf}
      PRIVATE
        cryptoauthlib
        fatfs
        base32
        bignum # TODO: only eth
        sha3   # TODO: Only eth
        ctaes
        c
        samd51a-ds
        asf4-drivers-min
        asf4-drivers
        -Wl,-u,exception_table)
    add_dependencies(${elf} generate-protobufs)
    target_include_directories(${elf} PRIVATE ${INCLUDES})
    target_include_directories(${elf} SYSTEM PRIVATE ${SYSTEMINCLUDES})

    # Include and provide configuration for nanopb
    target_include_directories(${elf} SYSTEM PRIVATE ${NANOPB_INCLUDE_DIRS})
    target_compile_definitions(${elf} PRIVATE "PB_NO_PACKED_STRUCTS=1" "PB_FIELD_16BIT=1")

    # needed to find version.h
    target_include_directories(${elf} PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
    target_link_libraries(${elf} PRIVATE "-Wl,-Map=\"${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${firmware}.map\" -T\"${CMAKE_SOURCE_DIR}/firmware.ld\"")
    target_link_libraries(${elf} PRIVATE -Wl,--defsym=STACK_SIZE=${STACK_SIZE} -Wl,-defsym=HEAP_SIZE=${HEAP_SIZE})

    add_dependencies(${elf} noise-c)
    target_link_libraries(${elf} PRIVATE noiseprotocol)

    add_dependencies(${elf} libwally-core)
    target_link_libraries(${elf} PRIVATE wallycore secp256k1)
    target_link_libraries(${elf} PRIVATE ${QTOUCHLIB_A} ${QTOUCHLIB_B} ${QTOUCHLIB_T})
    # Must manually link against C so that malloc can find _sbrk

    # Select the smaller version of libc called nano.
    target_compile_options(${elf} PRIVATE --specs=nano.specs)
    target_link_libraries(${elf} PRIVATE --specs=nano.specs)
    string(FIND ${elf} semihosting SEMIHOSTING_FOUND)
    if(SEMIHOSTING_FOUND EQUAL -1)
      target_compile_options(${elf} PRIVATE --specs=nosys.specs)
      target_link_libraries(${elf} PRIVATE --specs=nosys.specs)
    else()
      # Select an implementation of the system calls that can communicate with the debugger
      target_compile_options(${elf} PRIVATE --specs=rdimon.specs)
      target_link_libraries(${elf} PRIVATE --specs=rdimon.specs)
    endif()
  endforeach(firmware)

  foreach(firmware ${FIRMWARES-BITBOX02})
    target_sources(${firmware}.elf PRIVATE ${BITBOX02-FIRMWARE-SOURCES})
  endforeach(firmware)
  foreach(firmware ${FIRMWARES-BITBOXBASE})
    target_sources(${firmware}.elf PRIVATE ${BITBOXBASE-FIRMWARE-SOURCES})
  endforeach(firmware)

  target_sources(firmware.elf PRIVATE firmware.c)
  target_compile_definitions(firmware.elf PRIVATE PRODUCT_BITBOX_MULTI "APP_ETH=1" "APP_U2F=1")
  target_sources(firmware.elf PRIVATE ${FIRMWARE-U2F-SOURCES})
  target_link_libraries(firmware.elf PRIVATE bitbox02-platform)
  target_link_libraries(firmware.elf PRIVATE app_btc-multi)

  target_sources(firmware-semihosting.elf PRIVATE firmware.c)
  target_sources(firmware-semihosting.elf PRIVATE ${FIRMWARE-U2F-SOURCES})
  target_link_libraries(firmware-semihosting.elf PRIVATE bitbox02-platform)
  target_link_libraries(firmware-semihosting.elf PRIVATE app_btc-multi)

  # Select an implementation of the system calls that can communicate with the debugger
  target_compile_definitions(firmware-semihosting.elf PRIVATE PRODUCT_BITBOX_MULTI "APP_ETH=1" "APP_U2F=1")
  target_compile_definitions(firmware-semihosting.elf PRIVATE SEMIHOSTING)

  target_sources(firmware-btc.elf PRIVATE firmware.c)
  target_compile_definitions(firmware-btc.elf PRIVATE PRODUCT_BITBOX_BTCONLY "APP_ETH=0" "APP_U2F=0")
  target_link_libraries(firmware-btc.elf PRIVATE bitbox02-platform)
  target_link_libraries(firmware-btc.elf PRIVATE app_btc-btc)

  target_sources(firmware-bitboxbase.elf PRIVATE bitboxbase/bitboxbase.c)
  target_compile_definitions(firmware-bitboxbase.elf PRIVATE PRODUCT_BITBOX_BASE "APP_BTC=0" "APP_LTC=0" "APP_ETH=0" "APP_U2F=0")
  target_sources(firmware-bitboxbase.elf PRIVATE ${BITBOXBASE-FIRMWARE-SOURCES})
  target_link_libraries(firmware-bitboxbase.elf PRIVATE bitboxbase-platform)

  target_sources(firmware-bitboxbase-semihosting.elf PRIVATE bitboxbase/bitboxbase.c)
  target_compile_definitions(firmware-bitboxbase-semihosting.elf PRIVATE PRODUCT_BITBOX_BASE SEMIHOSTING "APP_BTC=0" "APP_LTC=0" "APP_ETH=0" "APP_U2F=0")
  target_sources(firmware-bitboxbase-semihosting.elf PRIVATE ${BITBOXBASE-FIRMWARE-SOURCES})
  target_link_libraries(firmware-bitboxbase-semihosting.elf PRIVATE bitboxbase-platform)

  target_link_libraries(firmware-bitboxbase.elf PRIVATE bitbox02_rust)
  add_dependencies(firmware-bitboxbase.elf rust rust-cbindgen)

  target_sources(factory-setup.elf PRIVATE factorysetup.c)
  target_compile_definitions(factory-setup.elf PRIVATE PRODUCT_BITBOX02_FACTORYSETUP "APP_BTC=0" "APP_LTC=0" "APP_ETH=0" "APP_U2F=0")
  target_link_libraries(factory-setup.elf PRIVATE bitbox02-platform)

  target_sources(factory-setup-bitboxbase.elf PRIVATE factorysetup.c)
  target_compile_definitions(factory-setup-bitboxbase.elf PRIVATE PRODUCT_BITBOXBASE_FACTORYSETUP "APP_BTC=0" "APP_LTC=0" "APP_ETH=0" "APP_U2F=0")
  target_link_libraries(factory-setup-bitboxbase.elf PRIVATE bitboxbase-platform)

  foreach(name ${BOOTLOADERS} ${FIRMWARES})
    add_custom_command(
      TARGET ${name}.elf POST_BUILD
      COMMAND ${CMAKE_SIZE} ${name}.elf
      COMMAND ${CMAKE_OBJCOPY} -O binary ${name}.elf ${name}.bin
      WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
      COMMENT "\nGenerating binary ${name}.bin"
    )
    # Fail on warnings for our builds
    target_compile_options(${name}.elf PRIVATE "-Werror")
  endforeach()
endif()
