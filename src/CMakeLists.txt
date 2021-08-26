# Copyright (c) 2015-2016 Lucas Betschart, Douglas J. Bakkum
# Copyright 2019 Shift Cryptosecurity AG
# Copyright 2020 Shift Crypto AG
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

set(DBB-FIRMWARE-SOURCES
  ${CMAKE_SOURCE_DIR}/src/firmware_main_loop.c
  ${CMAKE_SOURCE_DIR}/src/commander/commander.c
  ${CMAKE_SOURCE_DIR}/src/commander/commander_btc.c
  ${CMAKE_SOURCE_DIR}/src/commander/commander_states.c
  ${CMAKE_SOURCE_DIR}/src/commander/protobuf.c
  ${CMAKE_SOURCE_DIR}/src/keystore.c
  ${CMAKE_SOURCE_DIR}/src/keystore/keystore_antiklepto.c
  ${CMAKE_SOURCE_DIR}/src/random.c
  ${CMAKE_SOURCE_DIR}/src/hardfault.c
  ${CMAKE_SOURCE_DIR}/src/systick.c
  ${CMAKE_SOURCE_DIR}/src/util.c
  ${CMAKE_SOURCE_DIR}/src/sd.c
  ${CMAKE_SOURCE_DIR}/src/system.c
  ${CMAKE_SOURCE_DIR}/src/hww.c
  ${CMAKE_SOURCE_DIR}/src/memory/bitbox02_smarteeprom.c
  ${CMAKE_SOURCE_DIR}/src/memory/memory.c
  ${CMAKE_SOURCE_DIR}/src/memory/mpu.c
  ${CMAKE_SOURCE_DIR}/src/memory/nvmctrl.c
  ${CMAKE_SOURCE_DIR}/src/memory/smarteeprom.c
  ${CMAKE_SOURCE_DIR}/src/salt.c
  ${CMAKE_SOURCE_DIR}/src/i2c_ecc.c
  ${CMAKE_SOURCE_DIR}/src/touch/gestures.c
  ${CMAKE_SOURCE_DIR}/src/backup/backup.c
  ${CMAKE_SOURCE_DIR}/src/backup/restore.c
  ${CMAKE_SOURCE_DIR}/src/backup/backup_common.c
  ${CMAKE_SOURCE_DIR}/src/reset.c
  ${CMAKE_SOURCE_DIR}/src/cipher/cipher.c
  ${CMAKE_SOURCE_DIR}/src/workflow/blocking.c
  ${CMAKE_SOURCE_DIR}/src/workflow/confirm.c
  ${CMAKE_SOURCE_DIR}/src/workflow/confirm_time.c
  ${CMAKE_SOURCE_DIR}/src/workflow/idle_workflow.c
  ${CMAKE_SOURCE_DIR}/src/workflow/password.c
  ${CMAKE_SOURCE_DIR}/src/workflow/restore.c
  ${CMAKE_SOURCE_DIR}/src/workflow/orientation_screen.c
  ${CMAKE_SOURCE_DIR}/src/workflow/status.c
  ${CMAKE_SOURCE_DIR}/src/workflow/unlock_bip39.c
  ${CMAKE_SOURCE_DIR}/src/workflow/verify_recipient.c
  ${CMAKE_SOURCE_DIR}/src/workflow/verify_total.c
  ${CMAKE_SOURCE_DIR}/src/workflow/workflow.c
  ${CMAKE_SOURCE_DIR}/src/apps/common/bip32.c
  ${CMAKE_SOURCE_DIR}/src/apps/btc/btc.c
  ${CMAKE_SOURCE_DIR}/src/apps/btc/btc_common.c
  ${CMAKE_SOURCE_DIR}/src/apps/btc/btc_params.c
  ${CMAKE_SOURCE_DIR}/src/apps/btc/btc_sign.c
  ${CMAKE_SOURCE_DIR}/src/apps/btc/btc_sign_validate.c
  ${CMAKE_SOURCE_DIR}/src/apps/btc/confirm_locktime_rbf.c
  ${CMAKE_SOURCE_DIR}/src/apps/btc/confirm_multisig.c
  ${CMAKE_SOURCE_DIR}/src/queue.c
  ${CMAKE_SOURCE_DIR}/src/usb/usb_processing.c
)
set(DBB-FIRMWARE-SOURCES ${DBB-FIRMWARE-SOURCES} PARENT_SCOPE)

set(DBB-FIRMWARE-USB-SOURCES
  ${CMAKE_SOURCE_DIR}/src/usb/usb.c
  ${CMAKE_SOURCE_DIR}/src/usb/usb_frame.c
  ${CMAKE_SOURCE_DIR}/src/usb/usb_packet.c
  ${CMAKE_SOURCE_DIR}/src/u2f/u2f_packet.c
)
set(DBB-FIRMWARE-USB-SOURCES ${DBB-FIRMWARE-USB-SOURCES} PARENT_SCOPE)

set(DBB-FIRMWARE-USART-SOURCES
  ${CMAKE_SOURCE_DIR}/src/usart/usart_frame.c
)
set(DBB-FIRMWARE-USART-SOURCES ${DBB-FIRMWARE-USART-SOURCES} PARENT_SCOPE)

set(DBB-FIRMWARE-UI-SOURCES
    ${CMAKE_SOURCE_DIR}/src/screen.c
    ${CMAKE_SOURCE_DIR}/src/ui/graphics/graphics.c
    ${CMAKE_SOURCE_DIR}/src/ui/graphics/lock_animation.c
    ${CMAKE_SOURCE_DIR}/src/ui/ugui/ugui.c
    ${CMAKE_SOURCE_DIR}/src/ui/fonts/font_a_9X9.c
    ${CMAKE_SOURCE_DIR}/src/ui/fonts/font_a_11X10.c
    ${CMAKE_SOURCE_DIR}/src/ui/fonts/font_a_11X12.c
    ${CMAKE_SOURCE_DIR}/src/ui/fonts/font_a_13X14.c
    ${CMAKE_SOURCE_DIR}/src/ui/fonts/font_a_15X16.c
    ${CMAKE_SOURCE_DIR}/src/ui/fonts/font_a_17X18.c
    ${CMAKE_SOURCE_DIR}/src/ui/fonts/monogram_5X9.c
    ${CMAKE_SOURCE_DIR}/src/ui/fonts/password_9X9.c
    ${CMAKE_SOURCE_DIR}/src/ui/fonts/password_11X12.c
    ${CMAKE_SOURCE_DIR}/src/ui/screen_saver.c
    ${CMAKE_SOURCE_DIR}/src/ui/screen_stack.c
    ${CMAKE_SOURCE_DIR}/src/ui/screen_process.c
    ${CMAKE_SOURCE_DIR}/src/ui/event_handler.c
    ${CMAKE_SOURCE_DIR}/src/ui/ui_util.c
    ${CMAKE_SOURCE_DIR}/src/ui/components/trinary_choice.c
    ${CMAKE_SOURCE_DIR}/src/ui/components/trinary_input_char.c
    ${CMAKE_SOURCE_DIR}/src/ui/components/trinary_input_string.c
    ${CMAKE_SOURCE_DIR}/src/ui/components/waiting.c
    ${CMAKE_SOURCE_DIR}/src/ui/components/screensaver.c
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
    ${CMAKE_SOURCE_DIR}/src/ui/components/menu.c
    ${CMAKE_SOURCE_DIR}/src/ui/components/status.c
    ${CMAKE_SOURCE_DIR}/src/ui/components/image.c
    ${CMAKE_SOURCE_DIR}/src/ui/components/button.c
    ${CMAKE_SOURCE_DIR}/src/ui/components/empty.c
    ${CMAKE_SOURCE_DIR}/src/ui/components/progress.c
    ${CMAKE_SOURCE_DIR}/src/ui/components/sdcard.c
    ${CMAKE_SOURCE_DIR}/src/ui/components/ui_images.c
    ${CMAKE_SOURCE_DIR}/src/ui/components/confirm_transaction.c
)
set(DBB-FIRMWARE-UI-SOURCES ${DBB-FIRMWARE-UI-SOURCES} PARENT_SCOPE)

set(DBB-BOOTLOADER-SOURCES
  ${CMAKE_SOURCE_DIR}/src/util.c
  ${CMAKE_SOURCE_DIR}/src/pukcc/curve_p256.c
  ${CMAKE_SOURCE_DIR}/src/pukcc/pukcc.c
  ${CMAKE_SOURCE_DIR}/src/bootloader/bootloader.c
  ${CMAKE_SOURCE_DIR}/src/bootloader/startup.c
  ${CMAKE_SOURCE_DIR}/src/bootloader/mpu_regions.c
  ${CMAKE_SOURCE_DIR}/src/memory/mpu.c
  ${CMAKE_SOURCE_DIR}/src/memory/nvmctrl.c
  ${CMAKE_SOURCE_DIR}/src/queue.c
  ${CMAKE_SOURCE_DIR}/src/usb/usb_processing.c
  ${CMAKE_SOURCE_DIR}/src/ui/ugui/ugui.c
  ${CMAKE_SOURCE_DIR}/src/ui/fonts/font_a_9X9.c
  ${CMAKE_SOURCE_DIR}/src/ui/fonts/font_a_11X10.c
  ${CMAKE_SOURCE_DIR}/src/ui/fonts/monogram_5X9.c
  ${CMAKE_SOURCE_DIR}/src/screen.c
  ${CMAKE_SOURCE_DIR}/src/hardfault.c
  ${CMAKE_SOURCE_DIR}/src/ui/components/ui_images.c
)
set(DBB-BOOTLOADER-SOURCES ${DBB-BOOTLOADER-SOURCES} PARENT_SCOPE)

set(DRIVER-SOURCES
  ${CMAKE_SOURCE_DIR}/src/platform/platform_init.c
  ${CMAKE_SOURCE_DIR}/src/platform/driver_init.c
  ${CMAKE_SOURCE_DIR}/src/qtouch/qtouch.c
  ${CMAKE_SOURCE_DIR}/src/ui/oled/oled.c
)
set(DRIVER-SOURCES ${DRIVER-SOURCES} PARENT_SCOPE)

set(PLATFORM-BITBOX02-SOURCES
  ${CMAKE_SOURCE_DIR}/src/sd_mmc/sd_mmc_start.c
  ${CMAKE_SOURCE_DIR}/src/usb/class/hid/hid.c
  ${CMAKE_SOURCE_DIR}/src/usb/class/hid/hww/hid_hww.c
  ${DBB-FIRMWARE-USB-SOURCES}
)
set(PLATFORM-BITBOX02-SOURCES ${PLATFORM-BITBOX02-SOURCES} PARENT_SCOPE)

set(PLATFORM-BITBOXBASE-SOURCES
  ${CMAKE_SOURCE_DIR}/src/platform/bitboxbase/leds.c
  ${CMAKE_SOURCE_DIR}/src/usart/usart.c
  ${CMAKE_SOURCE_DIR}/src/usart/usart_hww.c
  ${DBB-FIRMWARE-USART-SOURCES}
)
set(PLATFORM-BITBOXBASE-SOURCES ${PLATFORM-BITBOXBASE-SOURCES} PARENT_SCOPE)

set(BITBOXBASE-FIRMWARE-SOURCES
  ${CMAKE_SOURCE_DIR}/src/bitboxbase/bitboxbase_background.c
  ${CMAKE_SOURCE_DIR}/src/bitboxbase/bitboxbase_watchdog.c
  ${CMAKE_SOURCE_DIR}/src/bitboxbase/bitboxbase_screensaver.c
  ${CMAKE_SOURCE_DIR}/src/bitboxbase/bitboxbase_status.c
)
set(BITBOXBASE-FIRMWARE-SOURCES ${BITBOXBASE-FIRMWARE-SOURCES} PARENT_SCOPE)

set(CRYPTOAUTHLIB-SOURCES
  ${CMAKE_SOURCE_DIR}/src/securechip/securechip.c
)
set(CRYPTOAUTHLIB-SOURCES ${CRYPTOAUTHLIB-SOURCES} PARENT_SCOPE)

set(ETHEREUM-SOURCES
  ${CMAKE_SOURCE_DIR}/src/apps/eth/eth_params.c
  ${CMAKE_SOURCE_DIR}/src/apps/eth/eth_sighash.c
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

set(FIRMWARE-SOURCES
  ${DBB-FIRMWARE-SOURCES}
  ${DBB-FIRMWARE-UI-SOURCES}
  ${FIRMWARE-DRIVER-SOURCES}
  ${DRIVER-SOURCES}
  ${DBB-FIRMWARE-PROTOBUF-SOURCES}
  ${CRYPTOAUTHLIB-SOURCES}
  ${CMAKE_SOURCE_DIR}/src/common_main.c
)

set(BOOTLOADER-SOURCES
  ${DBB-BOOTLOADER-SOURCES}
  ${DRIVER-SOURCES}
)

set_source_files_properties(
  ${DBB-FIRMWARE-PROTOBUF-SOURCES}
  PROPERTIES GENERATED TRUE
)

# rust-bindgen to generate rust declarations from c-headers.
# The compiled binary to avoid recompiling bindgen on every clean build
find_program(BINDGEN bindgen)
# cbindgen is used to generate the c-headers from rust code.
find_program(CBINDGEN cbindgen)
# cargo is the rust build system and dependency manager
find_program(CARGO cargo)

if(CMAKE_BUILD_TYPE STREQUAL "DEBUG")
  set(RUST_PROFILE "debug")
else()
  set(RUST_PROFILE "release")
  set(RUST_CARGO_FLAG "--release")
  set(RUSTFLAGS --remap-path-prefix=${CMAKE_CURRENT_SOURCE_DIR}/rust=src)
endif()

if(CMAKE_CROSSCOMPILING)
  set(RUST_TARGET_ARCH thumbv7em-none-eabi)
  set(RUST_TARGET_ARCH_DIR ${RUST_TARGET_ARCH})
  set(RUST_TARGET_ARCH_ARG --target ${RUST_TARGET_ARCH})
else()
  set(RUST_TARGET_ARCH_DIR .)
endif()

set(RUST_BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR}/rust/target)
set(LIBBITBOX02_RUST_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/rust/bitbox02-rust-c)
set(LIBBITBOX02_RUST ${LIBBITBOX02_RUST} PARENT_SCOPE)

# Generate c-headers for the rust library
# We generate two headers so that one of them can avoid using types only available for the firmware.
# * bitbox02_rust.h should be includeable everywhere, even in the bootloader
# * commander_rust.h can only be included in targets that have access to protobuf types
add_custom_target(rust-cbindgen
  COMMAND
    ${CBINDGEN} --quiet --config ${CMAKE_CURRENT_SOURCE_DIR}/rust/bitbox02-cbindgen.toml --output ${CMAKE_CURRENT_BINARY_DIR}/rust/rust.h ${LIBBITBOX02_RUST_SOURCE_DIR}
  BYPRODUCTS
    ${CMAKE_CURRENT_BINARY_DIR}/rust/rust.h
)

if(CMAKE_CROSSCOMPILING)
  get_property(SAMD51A_INCLUDES TARGET samd51a-ds PROPERTY INTERFACE_INCLUDE_DIRECTORIES)
  get_property(ASF4_MIN_INCLUDES TARGET asf4-drivers-min PROPERTY INTERFACE_INCLUDE_DIRECTORIES)
  get_property(ASF4_INCLUDES TARGET asf4-drivers PROPERTY INTERFACE_INCLUDE_DIRECTORIES)
  get_property(CMSIS_INCLUDES TARGET CMSIS PROPERTY INTERFACE_INCLUDE_DIRECTORIES)
endif()
get_property(WALLY_INCLUDES TARGET wallycore PROPERTY INTERFACE_INCLUDE_DIRECTORIES)
get_property(SECP256k1_INCLUDES TARGET secp256k1 PROPERTY INTERFACE_INCLUDE_DIRECTORIES)

foreach(include ${INCLUDES} ${SYSTEMINCLUDES} ${SAMD51A_INCLUDES} ${ASF4_INCLUDES} ${ASF4_MIN_INCLUDES} ${CMSIS_INCLUDES} ${NANOPB_INCLUDE_DIRS} ${WALLY_INCLUDES} ${SECP256k1_INCLUDES})
  list(APPEND RUST_INCLUDES -I${include})
endforeach()

if(CMAKE_CROSSCOMPILING)
  set(RUST_BINDGEN_FLAGS -D__SAMD51J20A__ --target=thumbv7em-none-eabi -mcpu=cortex-m4 -mthumb -mfloat-abi=soft --sysroot=${CMAKE_SYSROOT}
    # APP_ vars active when compiling C code to be used in Rust.  It
    # is okay to activate all of them here - Rust's 'app-' features
    # control usage/compilation in Rust.
    -DAPP_U2F=1 # needed to wrap securechip_u2f_counter_set() in Rust.
    )
else()
  set(RUST_BINDGEN_FLAGS -DTESTING=1)
endif()

add_custom_target(rust-bindgen
  # Generate rust bindings
  COMMAND
    ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_BINARY_DIR}/rust
  COMMAND
    ${BINDGEN}
    --output ${CMAKE_CURRENT_BINARY_DIR}/rust/bindings.rs.out
    --use-core
    --ctypes-prefix util::c_types
    --rustified-enum backup_error_t
    --whitelist-function wally_free_string
    --whitelist-function backup_check
    --whitelist-function backup_create
    --whitelist-function memory_is_initialized
    --whitelist-function memory_set_initialized
    --whitelist-function memory_is_mnemonic_passphrase_enabled
    --whitelist-function memory_get_attestation_pubkey_and_certificate
    --whitelist-function memory_bootloader_hash
    --whitelist-function memory_get_noise_static_private_key
    --whitelist-function memory_check_noise_remote_static_pubkey
    --whitelist-function memory_add_noise_remote_static_pubkey
    --whitelist-function memory_get_device_name
    --whitelist-function memory_set_device_name
    --whitelist-function memory_set_mnemonic_passphrase_enabled
    --whitelist-function memory_set_seed_birthdate
    --whitelist-var MEMORY_DEVICE_NAME_MAX_LEN
    --whitelist-function securechip_attestation_sign
    --whitelist-function securechip_monotonic_increments_remaining
    --whitelist-function securechip_u2f_counter_set
    --whitelist-function securechip_model
    --rustified-enum securechip_model_t
    --whitelist-function keystore_is_locked
    --whitelist-function keystore_unlock
    --whitelist-function keystore_unlock_bip39
    --whitelist-function keystore_lock
    --whitelist-function keystore_create_and_store_seed
    --whitelist-function keystore_get_bip39_mnemonic
    --whitelist-function keystore_get_bip39_word
    --whitelist-function keystore_secp256k1_pubkey_uncompressed
    --whitelist-function keystore_secp256k1_nonce_commit
    --whitelist-function keystore_secp256k1_sign
    --whitelist-function keystore_bip39_mnemonic_to_seed
    --whitelist-function keystore_get_root_fingerprint
    --whitelist-function mock_state
    --whitelist-var EC_PUBLIC_KEY_UNCOMPRESSED_LEN
    --whitelist-var EC_PUBLIC_KEY_LEN
    --whitelist-function keystore_encode_xpub_at_keypath
    --whitelist-function keystore_encrypt_and_store_seed
    --rustified-enum xpub_type_t
    --whitelist-var XPUB_ENCODED_LEN
    --whitelist-function lock_animation_start
    --whitelist-function lock_animation_stop
    --whitelist-function delay_us
    --rustified-enum keystore_error_t
    --rustified-enum keystore_secp256k1_pubkey_format
    --whitelist-function util_format_datetime
    --whitelist-function util_version_short
    --whitelist-function delay_ms
    --whitelist-function UG_PutString
    --whitelist-function UG_FontSelect
    --whitelist-function UG_ClearBuffer
    --whitelist-function UG_SendBuffer
    --whitelist-function screen_print_debug
    --whitelist-function ui_screen_stack_push
    --whitelist-function ui_screen_stack_pop
    --whitelist-function ui_screen_stack_pop_all
    --whitelist-function screen_process
    --whitelist-function label_create
    --whitelist-function confirm_create
    --whitelist-function status_create
    --whitelist-function sdcard_create
    --whitelist-function menu_create
    --whitelist-function trinary_choice_create
    --rustified-enum trinary_choice_t
    --whitelist-function bitboxbase_watchdog_reset
    --whitelist-function bitboxbase_screensaver_reset
    --whitelist-function leds_turn_small_led
    --whitelist-function leds_turn_big_led
    --whitelist-function wally_sha256
    --whitelist-function random_32_bytes_mcu
    --whitelist-type component_t
    --whitelist-type confirm_params_t
    --whitelist-type commander_error_t
    --rustified-enum commander_error_t
    --whitelist-function commander
    --whitelist-function commander_states_can_call
    --whitelist-function commander_states_clear_force_next
    --whitelist-type BitBoxBaseRequest
    --whitelist-var ".*_tag"
    --whitelist-var MAX_LABEL_SIZE
    --whitelist-var font_font_a_9X9
    --whitelist-var font_font_a_11X10
    --whitelist-var font_monogram_5X9
    --whitelist-var font_password_11X12
    --whitelist-var WALLY_OK
    --whitelist-type trinary_input_string_params_t
    --whitelist-var INPUT_STRING_MAX_SIZE
    --whitelist-function trinary_input_string_create
    --whitelist-function trinary_input_string_set_input
    --whitelist-function confirm_transaction_address_create
    --whitelist-function confirm_transaction_fee_create
    --whitelist-function reset_reset
    --whitelist-function sd_card_inserted
    --whitelist-var BIP39_WORDLIST_LEN
    --whitelist-function app_eth_params_get
    --whitelist-function app_eth_erc20_params_get
    --whitelist-function app_eth_sighash
    --whitelist-function app_btc_address_simple
    --whitelist-function reboot
    ${CMAKE_CURRENT_SOURCE_DIR}/rust/bitbox02-sys/wrapper.h --
    -DPB_NO_PACKED_STRUCTS=1 -DPB_FIELD_16BIT=1 -fshort-enums ${RUST_BINDGEN_FLAGS} ${RUST_INCLUDES}
  COMMAND
    ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_BINARY_DIR}/rust/bindings.rs.out ${CMAKE_CURRENT_BINARY_DIR}/rust/bindings.rs
  )
add_dependencies(rust-bindgen generate-protobufs)


# Test rust crates that contain business logic. Avoid testing crates that depend on hardware.
if(NOT CMAKE_CROSSCOMPILING)
  # Since we build with all features we need to use a separate build directory.
  # Otherwise we invalidate the result from the normal compilation that uses a
  # different set of features.
  add_custom_target(rust-test
    COMMAND
      ${CMAKE_COMMAND} -E env
        CMAKE_CURRENT_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}
        # enable nightly features in the stable release - needed to activate alloc_error_handler.
        # see src/rust/bitbox02-rust-c/src/lib.rs.
        # https://github.com/rust-lang/rust/issues/66740
        RUSTC_BOOTSTRAP=1
        ${CARGO} test $<$<BOOL:${CMAKE_VERBOSE_MAKEFILE}>:-v> --all-features --target-dir ${RUST_BINARY_DIR}/all-features ${RUST_CARGO_FLAG} -- --nocapture
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/rust/
    )
  add_dependencies(rust-test bitbox_merged)

  add_custom_target(rust-clippy
    COMMAND
      # Force clippy to fully re-run. It is bad at figuring out when to run again and when to use caches.
      ${CARGO} clean --target-dir ${RUST_BINARY_DIR}
    COMMAND
      ${CMAKE_COMMAND} -E env
        CMAKE_CURRENT_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}
        # enable nightly features in the stable release - needed to activate alloc_error_handler.
        # see src/rust/bitbox02-rust-c/src/lib.rs.
        # https://github.com/rust-lang/rust/issues/66740
        RUSTC_BOOTSTRAP=1
        ${CARGO} clippy
          $<$<BOOL:${CMAKE_VERBOSE_MAKEFILE}>:-v>
          --all-features
          --target-dir ${RUST_BINARY_DIR}/all-features
          --release
          -- # disabled linters:
            -A clippy::large_enum_variant
            -A clippy::identity_op
            -A clippy::match_bool
            -A clippy::new_without_default
            -A clippy::single_match
            -A clippy::iter_nth_zero
            -A clippy::redundant_clone
            -A clippy::type_complexity
            -A clippy::collapsible-if
            -A clippy::len_without_is_empty
            -A clippy::result_unit_err
            -A clippy::upper_case_acronyms
            -A clippy::manual_range_contains
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/rust/
    )
  add_dependencies(rust-clippy rust-bindgen)
endif()

# If a bootloader that locks the bootloader is flashed the bootloader area is permanently read-only.
set(BOOTLOADERS-BITBOX02
  bootloader # Runs signed firmware
  bootloader-development # Runs signed/unsigned firmware and has bootloader menu
  bootloader-development-locked # Runs signed/unsigned firmware, has bootloader menu and bootloader is locked
  bootloader-production # Runs signed firmware and bootloader is locked
  bootloader-btc # Runs signed (btc-only keys) firmware
  bootloader-btc-development # Runs signed/unsigned firmware and has bootloader menu
  bootloader-btc-production # Runs signed (btc-only keys) firmware and bootloader is locked
  )
set(BOOTLOADERS
  ${BOOTLOADERS-BITBOX02}
  )
set(BOOTLOADERS ${BOOTLOADERS} PARENT_SCOPE)

set(FIRMWARES
  firmware # Firmware MULTI
  firmware-btc # Firmware BTC-ONLY
  firmware-bitboxbase # Firmware BASE
  factory-setup # Factory-setup
  )
set(FIRMWARES ${FIRMWARES} PARENT_SCOPE)

if(CMAKE_CROSSCOMPILING)
  set(RUST_LIBS ${FIRMWARES} ${BOOTLOADERS})
else()
  set(RUST_LIBS c-unit-tests)
endif()

#  Create static libraries from rust code. Either:
#  *  c-unit-tests_rust_c
#  or
#  *  firmware_rust_c
#  *  firmware-btc_rust_c
#  *  firmware-bitboxbase_rust_c
#  *  factory-setup_rust_c
foreach(type ${RUST_LIBS})
  set(lib ${RUST_BINARY_DIR}/feature-${type}/${RUST_TARGET_ARCH_DIR}/${RUST_PROFILE}/libbitbox02_rust_c.a)
  # The dummy output is to always trigger rebuild (cargo is clever enough to
  # only rebuild if something changed)
  add_custom_command(
    OUTPUT ${lib} ${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}/lib${type}_rust_c.a dummy
    COMMAND
      ${CMAKE_COMMAND} -E env
      CMAKE_CURRENT_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}
      RUSTFLAGS=${RUSTFLAGS}
      # enable nightly features in the stable release - needed to activate alloc_error_handler.
      # see src/rust/bitbox02-rust-c/src/lib.rs.
      # https://github.com/rust-lang/rust/issues/66740
      RUSTC_BOOTSTRAP=1
      ${CARGO} build $<$<BOOL:${CMAKE_VERBOSE_MAKEFILE}>:-v> --features target-${type} --target-dir ${RUST_BINARY_DIR}/feature-${type} ${RUST_CARGO_FLAG} ${RUST_TARGET_ARCH_ARG}
    COMMAND
      ${CMAKE_COMMAND} -E copy_if_different ${lib} ${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}/lib${type}_rust_c.a
    # DEPFILES are only supported with the Ninja build tool
    #DEPFILE ${RUST_BINARY_DIR}/feature-${type}/${RUST_TARGET_ARCH_DIR}/${RUST_PROFILE}/libbitbox02_rust_c.d
    WORKING_DIRECTORY ${LIBBITBOX02_RUST_SOURCE_DIR}
    DEPENDS rust-bindgen
    COMMENT "Building Rust library lib${type}_rust_c.a"
  )
  add_custom_target(${type}-rust-target DEPENDS ${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}/lib${type}_rust_c.a)
  add_library(${type}_rust_c STATIC IMPORTED GLOBAL)
  # Any target that depends on the library also depends on the header file
  # which is generated by rust-cbindgen. So we might as well depend on it here.
  add_dependencies(${type}_rust_c ${type}-rust-target rust-cbindgen)
  set_property(TARGET ${type}_rust_c PROPERTY IMPORTED_LOCATION ${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}/lib${type}_rust_c.a)
endforeach()


if(CMAKE_CROSSCOMPILING)
  add_custom_target(rust-docs
    COMMAND
      ${CMAKE_COMMAND} -E env
      # enable nightly features in the stable release - needed to activate alloc_error_handler.
      # see src/rust/bitbox02-rust-c/src/lib.rs.
      # https://github.com/rust-lang/rust/issues/66740
      RUSTC_BOOTSTRAP=1
      CMAKE_CURRENT_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}
      SYSROOT=${CMAKE_SYSROOT}
      INCLUDES="${RUST_INCLUDES}"
      ${CARGO} doc --document-private-items --target-dir ${CMAKE_BINARY_DIR}/docs-rust ${RUST_CARGO_FLAG} --target thumbv7em-none-eabi
    COMMAND
      ${CMAKE_COMMAND} -E echo "See docs at file://${CMAKE_BINARY_DIR}/docs-rust/thumbv7em-none-eabi/doc/bitbox02_rust/index.html"
    WORKING_DIRECTORY ${LIBBITBOX02_RUST_SOURCE_DIR}
  )
  add_dependencies(rust-docs rust-bindgen)

  set(STACK_SIZE "0x10000" CACHE STRING "Specify stack size for bootloader/firmware")
  set(STACK_SIZE ${STACK_SIZE} PARENT_SCOPE)
  set(HEAP_SIZE "0x18000" CACHE STRING "Specify heap size for bootloader/firmware")
  set(HEAP_SIZE ${HEAP_SIZE} PARENT_SCOPE)

  foreach(bootloader ${BOOTLOADERS})
    set(elf ${bootloader}.elf)
    add_executable(${elf} ${BOOTLOADER-SOURCES})
    target_link_libraries(${elf} PRIVATE c asf4-drivers-min samd51a-ds -Wl,-u,exception_table)
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

    target_link_libraries(${elf} PRIVATE ${bootloader}_rust_c)

    # Select the smaller version of libc called nano.
    target_compile_options(${elf} PRIVATE --specs=nano.specs)
    target_link_libraries(${elf} PRIVATE --specs=nano.specs)
    if(SEMIHOSTING)
      # Select an implementation of the system calls that can communicate with the debugger
      target_compile_options(${elf} PRIVATE --specs=rdimon.specs)
      target_link_libraries(${elf} PRIVATE --specs=rdimon.specs)
      target_compile_definitions(${elf} PRIVATE SEMIHOSTING)
    else()
      target_compile_options(${elf} PRIVATE --specs=nosys.specs)
      target_link_libraries(${elf} PRIVATE --specs=nosys.specs)
    endif()
  endforeach(bootloader)

  foreach(bootloader ${BOOTLOADERS-BITBOX02})
    target_sources(${bootloader}.elf PRIVATE ${PLATFORM-BITBOX02-SOURCES})
  endforeach(bootloader)

  target_compile_definitions(bootloader.elf PRIVATE PRODUCT_BITBOX_MULTI)
  target_compile_definitions(bootloader-development.elf PRIVATE PRODUCT_BITBOX_MULTI BOOTLOADER_DEVDEVICE)
  target_compile_definitions(bootloader-development-locked.elf PRIVATE PRODUCT_BITBOX_MULTI BOOTLOADER_DEVDEVICE BOOTLOADER_PRODUCTION)
  set_property(TARGET bootloader-development-locked.elf PROPERTY EXCLUDE_FROM_ALL ON)


  target_compile_definitions(bootloader-production.elf PRIVATE PRODUCT_BITBOX_MULTI BOOTLOADER_PRODUCTION)
  set_property(TARGET bootloader-production.elf PROPERTY EXCLUDE_FROM_ALL ON)

  target_compile_definitions(bootloader-btc.elf PRIVATE PRODUCT_BITBOX_BTCONLY)
  target_compile_definitions(bootloader-btc-development.elf PRIVATE PRODUCT_BITBOX_BTCONLY BOOTLOADER_DEVDEVICE)
  target_compile_definitions(bootloader-btc-production.elf PRIVATE PRODUCT_BITBOX_BTCONLY BOOTLOADER_PRODUCTION)
  set_property(TARGET bootloader-btc-production.elf PROPERTY EXCLUDE_FROM_ALL ON)

  foreach(firmware ${FIRMWARES})
    set(elf ${firmware}.elf)
    add_executable(${elf} ${FIRMWARE-SOURCES})
    # Must manually link against C so that malloc can find _sbrk
    target_link_libraries(${elf}
      PRIVATE
        cryptoauthlib
        fatfs
        base32
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

    add_dependencies(${elf} libwally-core)
    target_link_libraries(${elf} PRIVATE wallycore secp256k1)
    target_link_libraries(${elf} PRIVATE ${QTOUCHLIB_A} ${QTOUCHLIB_B} ${QTOUCHLIB_T})

    # Select the smaller version of libc called nano.
    target_compile_options(${elf} PRIVATE --specs=nano.specs)
    target_link_libraries(${elf} PRIVATE --specs=nano.specs)
    if(SEMIHOSTING)
      # Select an implementation of the system calls that can communicate with the debugger
      target_compile_options(${elf} PRIVATE --specs=rdimon.specs)
      target_link_libraries(${elf} PRIVATE --specs=rdimon.specs)
      target_compile_definitions(${elf} PRIVATE SEMIHOSTING)
    else()
      target_compile_options(${elf} PRIVATE --specs=nosys.specs)
      target_link_libraries(${elf} PRIVATE --specs=nosys.specs)
    endif()

    target_link_libraries(${elf} PRIVATE ${firmware}_rust_c)
  endforeach(firmware)

  target_sources(firmware.elf PRIVATE firmware.c)
  target_compile_definitions(firmware.elf PRIVATE PRODUCT_BITBOX_MULTI "APP_BTC=1" "APP_LTC=1" "APP_ETH=1" "APP_U2F=1")
  target_sources(firmware.elf PRIVATE ${FIRMWARE-U2F-SOURCES} ${ETHEREUM-SOURCES} ${PLATFORM-BITBOX02-SOURCES})

  target_sources(firmware-btc.elf PRIVATE firmware.c)
  target_compile_definitions(firmware-btc.elf PRIVATE PRODUCT_BITBOX_BTCONLY "APP_BTC=1" "APP_LTC=0" "APP_ETH=0" "APP_U2F=0")
  target_sources(firmware-btc.elf PRIVATE ${PLATFORM-BITBOX02-SOURCES})

  target_sources(firmware-bitboxbase.elf PRIVATE bitboxbase/bitboxbase.c)
  target_compile_definitions(firmware-bitboxbase.elf PRIVATE PRODUCT_BITBOX_BASE "APP_BTC=0" "APP_LTC=0" "APP_ETH=0" "APP_U2F=0")
  target_sources(firmware-bitboxbase.elf PRIVATE ${PLATFORM-BITBOXBASE-SOURCES} ${BITBOXBASE-FIRMWARE-SOURCES})

  target_sources(factory-setup.elf PRIVATE factorysetup.c)
  target_compile_definitions(factory-setup.elf PRIVATE PRODUCT_BITBOX02_FACTORYSETUP "APP_BTC=0" "APP_LTC=0" "APP_ETH=0" "APP_U2F=0")
  target_sources(factory-setup.elf PRIVATE ${PLATFORM-BITBOX02-SOURCES})

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
