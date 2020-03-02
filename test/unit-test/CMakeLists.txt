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
# Build bitbox lib to use in tests

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-unused-parameter -Wno-missing-prototypes -Wno-missing-declarations -Wno-implicit-function-declaration -Wno-bad-function-cast")

set(DBB-FILTERED-SOURCES
  ${DBB-FIRMWARE-COMMON-SOURCES}
  ${DBB-FIRMWARE-UI-COMMON-SOURCES}
  ${DBB-FIRMWARE-UI-SOURCES}
  ${DBB-FIRMWARE-PROTOBUF-SOURCES}
  ${FIRMWARE-U2F-SOURCES}
  ${DBB-FIRMWARE-USB-SOURCES}
  ${DBB-FIRMWARE-USART-SOURCES}
  )

set(IGNORE_SOURCES
    "src/screen.c"
    "src/memory/nvmctrl.c"
    "src/memory/smarteeprom.c"
    "src/memory.mpu.c"
    )

# Exclude some files which depends on the hardware.
foreach(SOURCEFILE ${IGNORE_SOURCES})
    list(FILTER DBB-FILTERED-SOURCES EXCLUDE REGEX ".*/${SOURCEFILE}$")
endforeach()

message("FILTERED SOURCES: ${DBB-FILTERED-SOURCES}")

set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/tools/nanopb/extra)
find_package(Nanopb REQUIRED)

add_library(bitbox
  STATIC
  ${DBB-FIRMWARE-COMPONENT-SOURCES}
  ${DBB-FIRMWARE-WORKFLOW-SOURCES}
  ${APP-BTC-SOURCES}
  ${DBB-FILTERED-SOURCES}
  ${CTAES-SOURCES}
  ${ETHEREUM-SOURCES}
  # The usb.c file mixes together hardware and testing code... This should be split.
  ${CMAKE_SOURCE_DIR}/src/usb/usb.c
  ${CMAKE_SOURCE_DIR}/src/usb/usb_frame.c
  framework/mock_blocking.c
  framework/mock_screen.c
  framework/mock_screen_stack.c
  framework/mock_memory.c
  framework/mock_qtouch.c
  framework/mock_gestures.c
  framework/mock_component.c
  framework/mock_ff.c
  framework/mock_sd.c
  framework/mock_smarteeprom.c
  framework/mock_securechip.c
  framework/btc_util.c
)

target_include_directories(
  bitbox
  SYSTEM PUBLIC
  ${SYSTEMINCLUDES}
  ${CMAKE_SOURCE_DIR}/external
  ${CMAKE_SOURCE_DIR}/external/ctaes
)
target_include_directories(
  bitbox
  PUBLIC
  ${INCLUDES}
  ${CMAKE_CURRENT_SOURCE_DIR}/framework/includes
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_BINARY_DIR}/src
)

set_source_files_properties(
  ${DBB-FIRMWARE-PROTOBUF-SOURCES}
  PROPERTIES GENERATED TRUE
)
target_include_directories(bitbox SYSTEM PUBLIC ${NANOPB_INCLUDE_DIRS})
target_include_directories(bitbox PRIVATE ${CMAKE_SOURCE_DIR}/external/FatFs/source)
target_compile_definitions(bitbox PUBLIC "PB_NO_PACKED_STRUCTS=1" "PB_FIELD_16BIT=1")
target_compile_definitions(bitbox PUBLIC "PRODUCT_BITBOX_MULTI=1" "APP_BTC=1" "APP_LTC=1" "APP_U2F=1" "APP_ETH=1")
add_dependencies(bitbox generate-protobufs)

# Since noiseprotocol and wallycore are external projects we need to specify the dependency
add_dependencies(bitbox noise-c)
add_dependencies(bitbox libwally-core)

target_compile_definitions(bitbox PUBLIC TESTING)

target_link_libraries(bitbox
  PUBLIC
    noiseprotocol
    wallycore
    secp256k1
    bignum
    sha3
    util
  PRIVATE
    base32
    ctaes
)

if(SANITIZE_ADDRESS)
  target_compile_options(bitbox PUBLIC "-fsanitize=address")
endif()
if(SANTIZE_UNDEFINED)
  target_compile_options(bitbox PUBLIC "-fsanitize=undefined")
endif()
if(COVERAGE)
  target_link_libraries(bitbox PUBLIC "--coverage")
  target_compile_options(bitbox PUBLIC "--coverage")
endif()

add_library(u2f-util
  STATIC
  u2f/sha2.c
  u2f/ecc.c
  u2f/uECC.c
  u2f/u2f_util_t.c
)
target_include_directories(
  u2f-util
  SYSTEM PUBLIC
  ${SYSTEMINCLUDES}
  ${CMAKE_CURRENT_SOURCE_DIR}
)
target_include_directories(
  u2f-util
  PUBLIC
  ${INCLUDES}
  ${CMAKE_BINARY_DIR}/src
)
target_compile_definitions(u2f-util PUBLIC "TESTING" PRODUCT_BITBOX_MULTI "APP_U2F=1" "APP_BTC=1" "APP_LTC=1" "APP_ETH=1")
target_compile_definitions(u2f-util PUBLIC "USE_KECCAK")


#-----------------------------------------------------------------------------
# Tests

set(TEST_LIST
   simple
   ""
   cleanup
   "-Wl,--wrap=util_cleanup_32"
   hww
   "-Wl,--wrap=random_32_bytes,--wrap=workflow_confirm_dismiss"
   keystore
   "-Wl,--wrap=secp256k1_ecdsa_sign_recoverable,--wrap=memory_is_initialized,--wrap=memory_is_seeded,--wrap=memory_get_failed_unlock_attempts,--wrap=memory_reset_failed_unlock_attempts,--wrap=memory_increment_failed_unlock_attempts,--wrap=memory_set_encrypted_seed_and_hmac,--wrap=memory_get_encrypted_seed_and_hmac,--wrap=reset_reset,--wrap=salt_hash_data,--wrap=cipher_aes_hmac_encrypt"
   keystore_functional
   "-Wl,--wrap=memory_is_initialized,--wrap=memory_is_seeded,--wrap=memory_set_encrypted_seed_and_hmac,--wrap=memory_get_encrypted_seed_and_hmac,--wrap=memory_get_salt_root,--wrap=memory_get_failed_unlock_attempts,--wrap=memory_reset_failed_unlock_attempts,--wrap=memory_increment_failed_unlock_attempts,--wrap=securechip_kdf"
   gestures
   ""
   random
   "-Wl,--wrap=rand,--wrap=wally_sha256"
   apps_common_bip32
   ""
   app_btc
   "-Wl,--wrap=keystore_get_xpub,--wrap=btc_common_is_valid_keypath_xpub,--wrap=btc_common_is_valid_keypath_address_simple,--wrap=btc_common_encode_xpub,--wrap=btc_common_outputhash_from_pubkeyhash"
   app_btc_multisig
   "-Wl,--wrap=memory_multisig_get_by_hash,--wrap=apps_btc_confirm_multisig"
   app_btc_common
   ""
   app_btc_confirm_locktime_rbf
   "-Wl,--wrap=workflow_confirm,--wrap=workflow_status_create"
   sd
   ""
   ui_components
   ""
   ui_util
   ""
   ui_component_gestures
   ""
   btc_sign
   "-Wl,--wrap=workflow_verify_recipient,--wrap=workflow_verify_total,--wrap=apps_btc_confirm_locktime_rbf,--wrap=btc_common_format_amount,--wrap=btc_common_is_valid_keypath_address_simple"
   app_btc_sign_multisig
   "-Wl,--wrap=workflow_verify_recipient,--wrap=workflow_verify_total,--wrap=apps_btc_confirm_locktime_rbf,--wrap=memory_multisig_get_by_hash,--wrap=apps_btc_confirm_multisig"
   memory
   "-Wl,--wrap=memory_read_chunk_mock,--wrap=memory_write_chunk_mock,--wrap=bb_noise_generate_static_private_key,--wrap=memory_read_shared_bootdata_mock,--wrap=memory_write_to_address_mock"
   memory_functional
   "-Wl,--wrap=memory_write_chunk_mock,--wrap=memory_read_chunk_mock"
   salt
   "-Wl,--wrap=memory_get_salt_root"
   backup
   "-Wl,--wrap=keystore_copy_seed,--wrap=memory_get_seed_birthdate,--wrap=sd_write_bin,--wrap=sd_load_bin,--wrap=sd_list_subdir,--wrap=sd_erase_file_in_subdir,--wrap=sd_file_rename,--wrap=memory_get_device_name"
   restore
   "-Wl,--wrap=keystore_copy_seed,--wrap=keystore_encrypt_and_store_seed,--wrap=memory_get_seed_birthdate,--wrap=sd_write_bin,--wrap=sd_load_bin,--wrap=sd_list_subdir,--wrap=sd_list,--wrap=sd_erase_file_in_subdir,--wrap=sd_file_rename,--wrap=memory_get_device_name,--wrap=memory_set_device_name"
   cipher
   "-Wl,--wrap=random_32_bytes"
   sha3
   ""
   app_eth
   "-Wl,--wrap=keystore_secp256k1_pubkey,--wrap=eth_common_is_valid_keypath_address"
   app_eth_common
   ""
   app_eth_sighash
   ""
   app_eth_sign
   "-Wl,--wrap=app_eth_verify_standard_transaction,--wrap=app_eth_verify_erc20_transaction,--wrap=keystore_secp256k1_sign,--wrap=eth_common_is_valid_keypath_address"
   app_eth_sign_msg
   "-Wl,--wrap=keystore_secp256k1_sign,--wrap=keystore_secp256k1_pubkey,--wrap=eth_common_is_valid_keypath_address,--wrap=workflow_confirm"
   app_eth_verify
   "-Wl,--wrap=workflow_verify_recipient,--wrap=workflow_verify_total,--wrap=app_eth_erc20_params_get"
   usart
   "-Wl,--wrap=usb_processing_enqueue"
   util
   ""
   util_string
   ""
   commander_set_device_name
   "-Wl,--wrap=workflow_confirm,--wrap=memory_set_device_name"
   commander_set_mnemonic_passphrase_enabled
   "-Wl,--wrap=workflow_confirm,--wrap=memory_set_mnemonic_passphrase_enabled"
   workflow_blocking
   "-Wl,--wrap=screen_process"
   workflow_status
   "-Wl,--wrap=ui_screen_stack_push,--wrap=ui_screen_stack_pop,--wrap=status_create,--wrap=workflow_blocking_block,--wrap=workflow_blocking_unblock"
   workflow_cancel
   "-Wl,--wrap=ui_screen_stack_push,--wrap=ui_screen_stack_pop,--wrap=workflow_blocking_unblock,--wrap=workflow_blocking_block,--wrap=workflow_confirm,--wrap=workflow_status_create"
   ugui
   ""
)

find_package(CMocka REQUIRED)

list(LENGTH TEST_LIST TEST_LIST_LEN)
math(EXPR TEST_LIST_LEN ${TEST_LIST_LEN}-1)
foreach(I RANGE 0 ${TEST_LIST_LEN} 2)
  math(EXPR I2 ${I}+1)
  list(GET TEST_LIST ${I} TEST_NAME)
  list(GET TEST_LIST ${I2} TEST_LINK_ARGS)
  set(EXE test_${TEST_NAME})
  add_executable(${EXE} test_${TEST_NAME}.c)
  # asan must be first library in linking order
  target_link_libraries(${EXE} PRIVATE
    $<$<BOOL:SANITIZE_ADDRESS>:asan>
    $<$<BOOL:SANITIZE_UNDEFINED>:-fsanitize=undefined>
    bitbox
    ${CMOCKA_LIBRARIES}
    ${TEST_LINK_ARGS}
  )
  add_test(NAME test_${TEST_NAME} COMMAND ${EXE})
endforeach()


# These unit tests for U2F are special because they don't call any bitbox functions directly, instead they go through hid_read/write.
# They are copied from https://github.com/google/u2f-ref-code/tree/master/u2f-tests/HID
set(U2F_TESTS
   u2f_standard
   "-Wl,--wrap=workflow_unlock"
   u2f_hid
   "-Wl,--wrap=workflow_status_create"
)
list(LENGTH U2F_TESTS U2F_TESTS_LEN)
math(EXPR U2F_TESTS_LEN ${U2F_TESTS_LEN}-1)
foreach(I RANGE 0 ${U2F_TESTS_LEN} 2)
  math(EXPR I2 ${I}+1)
  list(GET U2F_TESTS ${I} TEST_NAME)
  list(GET U2F_TESTS ${I2} TEST_LINK_ARGS)
  set(EXE test_${TEST_NAME})

  # This tests link to our code
  add_executable(${EXE} test_${TEST_NAME}.c framework/mock_hidapi.c)
  target_link_libraries(${EXE} PRIVATE
    $<$<BOOL:SANITIZE_ADDRESS>:asan>
    $<$<BOOL:SANITIZE_UNDEFINED>:-fsanitize=undefined>
    bitbox
    u2f-util
    ${CMOCKA_LIBRARIES}
    ${TEST_LINK_ARGS}
  )
  target_compile_definitions(${EXE} PRIVATE "TESTING")
  add_test(NAME test_${TEST_NAME} COMMAND ${EXE})

  # Running these two tests require a hardware device connected and they link to the real libhidapi.
  set(EXE test_${TEST_NAME}_with_hardware)
  add_executable(${EXE} test_${TEST_NAME}.c)
  # asan must be first library in linking order
  target_link_libraries(${EXE} PRIVATE
    $<$<BOOL:SANITIZE_ADDRESS>:asan>
    $<$<BOOL:SANITIZE_UNDEFINED>:-fsanitize=undefined>
    u2f-util
    hidapi-hidraw
    ${CMOCKA_LIBRARIES}
  )
  target_compile_definitions(${EXE} PRIVATE "TESTING" "WITH_HARDWARE")
endforeach()
