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
  ${CMAKE_SOURCE_DIR}/src/bip32.c
  ${CMAKE_SOURCE_DIR}/src/firmware_main_loop.c
  ${CMAKE_SOURCE_DIR}/src/keystore.c
  ${CMAKE_SOURCE_DIR}/src/random.c
  ${CMAKE_SOURCE_DIR}/src/hardfault.c
  ${CMAKE_SOURCE_DIR}/src/util.c
  ${CMAKE_SOURCE_DIR}/src/sd.c
  ${CMAKE_SOURCE_DIR}/src/system.c
  ${CMAKE_SOURCE_DIR}/src/hww.c
  ${CMAKE_SOURCE_DIR}/src/memory/bitbox02_smarteeprom.c
  ${CMAKE_SOURCE_DIR}/src/memory/memory.c
  ${CMAKE_SOURCE_DIR}/src/memory/memory_shared.c
  ${CMAKE_SOURCE_DIR}/src/memory/mpu.c
  ${CMAKE_SOURCE_DIR}/src/memory/nvmctrl.c
  ${CMAKE_SOURCE_DIR}/src/memory/smarteeprom.c
  ${CMAKE_SOURCE_DIR}/src/salt.c
  ${CMAKE_SOURCE_DIR}/src/i2c_ecc.c
  ${CMAKE_SOURCE_DIR}/src/touch/gestures.c
  ${CMAKE_SOURCE_DIR}/src/reset.c
  ${CMAKE_SOURCE_DIR}/src/cipher/cipher.c
  ${CMAKE_SOURCE_DIR}/src/workflow/blocking.c
  ${CMAKE_SOURCE_DIR}/src/workflow/idle_workflow.c
  ${CMAKE_SOURCE_DIR}/src/workflow/orientation_screen.c
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
  ${CMAKE_SOURCE_DIR}/src/memory/memory_shared.c
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
  ${CMAKE_SOURCE_DIR}/src/ui/oled/oled_writer.c
)
set(DRIVER-SOURCES ${DRIVER-SOURCES} PARENT_SCOPE)

set(PLATFORM-BITBOX02-SOURCES
  ${CMAKE_SOURCE_DIR}/src/sd_mmc/sd_mmc_start.c
  ${CMAKE_SOURCE_DIR}/src/usb/class/hid/hid.c
  ${CMAKE_SOURCE_DIR}/src/usb/class/hid/hww/hid_hww.c
  ${CMAKE_SOURCE_DIR}/src/ui/oled/sh1107.c
  ${CMAKE_SOURCE_DIR}/src/ui/oled/ssd1312.c
  ${DBB-FIRMWARE-USB-SOURCES}
)
set(PLATFORM-BITBOX02-SOURCES ${PLATFORM-BITBOX02-SOURCES} PARENT_SCOPE)

set(SECURECHIP-SOURCES
  ${CMAKE_SOURCE_DIR}/src/atecc/atecc.c
  ${CMAKE_SOURCE_DIR}/src/securechip/securechip.c
  ${CMAKE_SOURCE_DIR}/src/optiga-pal/pal.c
  ${CMAKE_SOURCE_DIR}/src/optiga-pal/pal_crypt_mbedtls.c
  ${CMAKE_SOURCE_DIR}/src/optiga-pal/pal_gpio.c
  ${CMAKE_SOURCE_DIR}/src/optiga-pal/pal_i2c.c
  ${CMAKE_SOURCE_DIR}/src/optiga-pal/pal_ifx_i2c_config.c
  ${CMAKE_SOURCE_DIR}/src/optiga-pal/pal_logger.c
  ${CMAKE_SOURCE_DIR}/src/optiga-pal/pal_os_datastore.c
  ${CMAKE_SOURCE_DIR}/src/optiga-pal/pal_os_event.c
  ${CMAKE_SOURCE_DIR}/src/optiga-pal/pal_os_lock.c
  ${CMAKE_SOURCE_DIR}/src/optiga-pal/pal_os_timer.c
  ${CMAKE_SOURCE_DIR}/src/optiga-pal/pal_os_memory.c
  ${CMAKE_SOURCE_DIR}/src/optiga-pal/optiga.c
)
set(SECURECHIP-SOURCES ${SECURECHIP-SOURCES} PARENT_SCOPE)

set(ETHEREUM-SOURCES
  ${CMAKE_SOURCE_DIR}/src/apps/eth/eth_params.c
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

set(FIRMWARE-SOURCES
  ${DBB-FIRMWARE-SOURCES}
  ${DBB-FIRMWARE-UI-SOURCES}
  ${FIRMWARE-DRIVER-SOURCES}
  ${DRIVER-SOURCES}
  ${SECURECHIP-SOURCES}
  ${CMAKE_SOURCE_DIR}/src/common_main.c
)

set(BOOTLOADER-SOURCES
  ${DBB-BOOTLOADER-SOURCES}
  ${DRIVER-SOURCES}
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
  # For binary reproducibility, strip path prefixes that can be different depending on environment (e.g. /home/<user>, etc.).
  set(RUSTFLAGS "--remap-path-prefix=${CMAKE_CURRENT_SOURCE_DIR}/rust=src --remap-path-prefix=$ENV{HOME}=")
endif()
# Use libsecp256k1 that we link ourselves (included via external/libwally-core).
# See https://github.com/rust-bitcoin/rust-secp256k1/tree/7c8270a8506e31731e540fab7ee1abde1f48314e/secp256k1-sys#linking-to-external-symbols
set(RUSTFLAGS "${RUSTFLAGS} --cfg=rust_secp_no_symbol_renaming")

# Apply workaround for a potential miscompilation bug:
# See
# - https://github.com/rust-embedded/cortex-m/discussions/503
# - https://github.com/rust-lang/rust/issues/118867
# We have not observed any abnormal behavior even though we fulfil all the criteria to be affected
# (opt-level='z', thumbv7em-none-eabi target, Rust toolchain 1.74.0 being >= 1.73.0), but we apply
# the workaround just in case.
#
# This increases the binary size of the `make firmware` (Multi) build by 11568 bytes at the time of
# adding this workaround. This can be removed again once the issue above is fixed and we have
# updated to a Rust toolchain that contains the fix.
set(RUSTFLAGS "${RUSTFLAGS} -Cllvm-args=--enable-machine-outliner=never")

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

foreach(include ${INCLUDES} ${SYSTEMINCLUDES} ${SAMD51A_INCLUDES} ${ASF4_INCLUDES} ${ASF4_MIN_INCLUDES} ${CMSIS_INCLUDES} ${WALLY_INCLUDES} ${SECP256k1_INCLUDES})
  list(APPEND RUST_INCLUDES -I${include})
endforeach()
if(NOT CMAKE_CROSSCOMPILING)
  list(APPEND RUST_INCLUDES -I${CMAKE_SOURCE_DIR}/test/unit-test/framework/includes)
endif()

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
    --with-derive-default
    --ctypes-prefix util::c_types
    --allowlist-function bip32_derive_xpub
    --allowlist-function strftime
    --allowlist-function localtime
    --allowlist-function wally_free_string
    --allowlist-function mock_memory_factoryreset
    --allowlist-function memory_setup
    --allowlist-function memory_is_initialized
    --allowlist-function memory_set_initialized
    --allowlist-function memory_is_seeded
    --allowlist-function memory_is_mnemonic_passphrase_enabled
    --allowlist-function memory_get_attestation_pubkey_and_certificate
    --allowlist-function memory_bootloader_hash
    --allowlist-function memory_get_noise_static_private_key
    --allowlist-function memory_check_noise_remote_static_pubkey
    --allowlist-function memory_add_noise_remote_static_pubkey
    --allowlist-function memory_get_device_name
    --allowlist-function memory_set_device_name
    --allowlist-function memory_set_mnemonic_passphrase_enabled
    --allowlist-var MEMORY_MULTISIG_NAME_MAX_LEN
    --allowlist-function memory_set_seed_birthdate
    --allowlist-function memory_get_seed_birthdate
    --allowlist-function memory_multisig_get_by_hash
    --allowlist-function memory_multisig_set_by_hash
    --allowlist-function smarteeprom_bb02_config
    --allowlist-function bitbox02_smarteeprom_init
    --rustified-enum memory_result_t
    --allowlist-var MEMORY_DEVICE_NAME_MAX_LEN
    --allowlist-function securechip_attestation_sign
    --allowlist-function securechip_monotonic_increments_remaining
    --allowlist-function securechip_u2f_counter_set
    --allowlist-function securechip_model
    --rustified-enum securechip_model_t
    --allowlist-var KEYSTORE_MAX_SEED_LENGTH
    --allowlist-function keystore_is_locked
    --allowlist-function keystore_unlock
    --allowlist-function keystore_unlock_bip39
    --allowlist-function keystore_lock
    --allowlist-function keystore_create_and_store_seed
    --allowlist-function keystore_copy_seed
    --allowlist-function keystore_get_bip39_mnemonic
    --allowlist-function keystore_get_bip39_word
    --allowlist-function keystore_get_ed25519_seed
    --allowlist-function keystore_bip85_bip39
    --allowlist-function keystore_secp256k1_compressed_to_uncompressed
    --allowlist-function keystore_secp256k1_nonce_commit
    --allowlist-function keystore_secp256k1_sign
    --allowlist-function keystore_secp256k1_schnorr_bip86_sign
    --allowlist-function keystore_bip39_mnemonic_to_seed
    --allowlist-function keystore_mock_unlocked
    --allowlist-var EC_PUBLIC_KEY_UNCOMPRESSED_LEN
    --allowlist-var EC_PUBLIC_KEY_LEN
    --allowlist-function keystore_encode_xpub_at_keypath
    --allowlist-function keystore_encrypt_and_store_seed
    --allowlist-var XPUB_ENCODED_LEN
    --allowlist-var BIP32_SERIALIZED_LEN
    --allowlist-function lock_animation_start
    --allowlist-function lock_animation_stop
    --allowlist-function delay_us
    --rustified-enum keystore_error_t
    --rustified-enum keystore_secp256k1_pubkey_format
    --allowlist-function keystore_secp256k1_schnorr_bip86_pubkey
    --allowlist-function util_format_datetime
    --allowlist-type buffer_t
    --allowlist-function delay_ms
    --allowlist-function UG_PutString
    --allowlist-function UG_FontSelect
    --allowlist-function UG_ClearBuffer
    --allowlist-function UG_SendBuffer
    --allowlist-function screen_print_debug
    --allowlist-function ui_screen_stack_push
    --allowlist-function ui_screen_stack_pop
    --allowlist-function ui_screen_stack_pop_all
    --allowlist-function screen_saver_disable
    --allowlist-function screen_saver_enable
    --allowlist-function screen_process
    --allowlist-function label_create
    --allowlist-function confirm_create
    --allowlist-function status_create
    --allowlist-function sdcard_create
    --allowlist-function menu_create
    --allowlist-function trinary_choice_create
    --rustified-enum trinary_choice_t
    --allowlist-var BASE58_CHECKSUM_LEN
    --allowlist-function random_32_bytes_mcu
    --allowlist-function random_mock_reset
    --allowlist-type component_t
    --allowlist-type confirm_params_t
    --allowlist-var MAX_LABEL_SIZE
    --allowlist-var font_font_a_9X9
    --allowlist-var font_font_a_11X10
    --allowlist-var font_monogram_5X9
    --allowlist-var font_password_11X12
    --allowlist-type trinary_input_string_params_t
    --allowlist-var INPUT_STRING_MAX_SIZE
    --allowlist-function trinary_input_string_create
    --allowlist-function trinary_input_string_set_input
    --allowlist-function confirm_transaction_address_create
    --allowlist-function confirm_transaction_fee_create
    --allowlist-function progress_create
    --allowlist-function progress_set
    --allowlist-function empty_create
    --allowlist-function reset_reset
    --allowlist-function sd_card_inserted
    --allowlist-function sd_format
    --allowlist-function sd_list_subdir
    --allowlist-function sd_erase_file_in_subdir
    --allowlist-function sd_load_bin
    --allowlist-function sd_write_bin
    --allowlist-var SD_MAX_FILE_SIZE
    --allowlist-function sd_free_list
    --allowlist-var BIP39_WORDLIST_LEN
    --allowlist-function app_eth_erc20_params_get
    --rustified-enum simple_type_t
    --rustified-enum multisig_script_type_t
    --rustified-enum output_type_t
    --allowlist-var MAX_VARINT_SIZE
    --allowlist-var MAX_PK_SCRIPT_SIZE
    --allowlist-function reboot
    --allowlist-function secp256k1_ecdsa_anti_exfil_host_commit
    --allowlist-function wally_get_secp_context
    --allowlist-function wally_hash160
    --allowlist-function printf
    ${CMAKE_CURRENT_SOURCE_DIR}/rust/bitbox02-sys/wrapper.h --
    -DPB_NO_PACKED_STRUCTS=1 -DPB_FIELD_16BIT=1 -fshort-enums ${RUST_BINDGEN_FLAGS} ${RUST_INCLUDES}
  COMMAND
    ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_BINARY_DIR}/rust/bindings.rs.out ${CMAKE_CURRENT_BINARY_DIR}/rust/bindings.rs
  )


# Test rust crates that contain business logic. Avoid testing crates that depend on hardware.
if(NOT CMAKE_CROSSCOMPILING)
  # Since we build with all features we need to use a separate build directory.
  # Otherwise we invalidate the result from the normal compilation that uses a
  # different set of features.
  add_custom_target(rust-test
    COMMAND
      ${CMAKE_COMMAND} -E env
        CMAKE_CURRENT_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}
        FIRMWARE_VERSION_SHORT=${FIRMWARE_VERSION}
        # only one test thread because of unsafe concurrent access to `SafeData`, `mock_sd()` and `mock_memory()`. Using mutexes instead leads to mutex poisoning and very messy output in case of a unit test failure.
        ${CARGO} test $<$<BOOL:${CMAKE_VERBOSE_MAKEFILE}>:-v> --all-features --target-dir ${RUST_BINARY_DIR}/all-features ${RUST_CARGO_FLAG} -- --nocapture --test-threads 1
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/rust/
    )
  add_dependencies(rust-test bitbox_merged generate-protobufs)

  add_custom_target(rust-clippy
    COMMAND
      # Force clippy to fully re-run. It is bad at figuring out when to run again and when to use caches.
      ${CARGO} clean --target-dir ${RUST_BINARY_DIR}
    COMMAND
      ${CMAKE_COMMAND} -E env
        CMAKE_CURRENT_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}
        FIRMWARE_VERSION_SHORT=${FIRMWARE_VERSION}
        ${CARGO} clippy
          $<$<BOOL:${CMAKE_VERBOSE_MAKEFILE}>:-v>
          --all-features
          --target-dir ${RUST_BINARY_DIR}/all-features
          --release
          --tests
          -- # disabled linters:
            -A clippy::large_enum_variant
            -A clippy::identity_op
            -A clippy::new_without_default
            -A clippy::single_match
            -A clippy::redundant_clone
            -A clippy::type_complexity
            -A clippy::len_without_is_empty
            -A clippy::result_unit_err
            -A clippy::enum_variant_names
            -A clippy::derive_partial_eq_without_eq
            -A clippy::forget_non_drop
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/rust/
    )
  add_dependencies(rust-clippy rust-bindgen generate-protobufs)
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
      FIRMWARE_VERSION_SHORT=${FIRMWARE_VERSION}
      $<$<BOOL:${SCCACHE_PROGRAM}>:RUSTC_WRAPPER=${SCCACHE_PROGRAM}>
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
  add_dependencies(${type}_rust_c ${type}-rust-target generate-protobufs rust-cbindgen)
  set_property(TARGET ${type}_rust_c PROPERTY IMPORTED_LOCATION ${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}/lib${type}_rust_c.a)
endforeach()


if(CMAKE_CROSSCOMPILING)
  add_custom_target(rust-docs
    COMMAND
      ${CMAKE_COMMAND} -E env
      FIRMWARE_VERSION_SHORT=${FIRMWARE_VERSION}
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
    add_dependencies(${elf} mbedtls-project)
    # Must manually link against C so that malloc can find _sbrk
    target_link_libraries(${elf}
      PRIVATE
        mbedtls
        mbedx509
        mbedcrypto
        optiga
        cryptoauthlib
        fatfs
        ctaes
        c
        samd51a-ds
        asf4-drivers-min
        asf4-drivers
        -Wl,-u,exception_table)
    target_include_directories(${elf} PRIVATE ${INCLUDES})
    target_include_directories(${elf} SYSTEM PRIVATE ${SYSTEMINCLUDES})

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
