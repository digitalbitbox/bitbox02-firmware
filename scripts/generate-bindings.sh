#!/usr/bin/env bash

# ./generate-bindings.sh TARGET SOURCE [CLANG_FLAG [CLANG_FLAG]]
#
# TARGET is a rust file that should be generated
# SOURCE is a c header file
# CLANG_FLAG are flags to pass to libclang (i.e. include directories)
#
# bindgen version can be overridden with the BINDGEN env variable

TARGET=$1; shift
SOURCE=$1; shift
read -ra FLAGS <<< "$*"

BINDGEN=${BINDGEN:-bindgen}

${BINDGEN} \
	--output "${TARGET}" \
	--use-core \
	--with-derive-default \
	--ctypes-prefix util::c_types \
	--rustified-enum backup_error_t \
	--rustified-enum restore_error_t \
	--whitelist-function wally_free_string \
	--whitelist-function backup_check \
	--whitelist-function backup_create \
	--whitelist-function mock_memory_factoryreset \
	--whitelist-function memory_setup \
	--whitelist-function restore_from_directory \
	--whitelist-function memory_is_initialized \
	--whitelist-function memory_set_initialized \
	--whitelist-function memory_is_mnemonic_passphrase_enabled \
	--whitelist-function memory_get_attestation_pubkey_and_certificate \
	--whitelist-function memory_bootloader_hash \
	--whitelist-function memory_get_noise_static_private_key \
	--whitelist-function memory_check_noise_remote_static_pubkey \
	--whitelist-function memory_add_noise_remote_static_pubkey \
	--whitelist-function memory_get_device_name \
	--whitelist-function memory_set_device_name \
	--whitelist-function memory_set_mnemonic_passphrase_enabled \
	--whitelist-function memory_set_seed_birthdate \
	--whitelist-function memory_get_seed_birthdate \
	--whitelist-var MEMORY_DEVICE_NAME_MAX_LEN \
	--whitelist-function securechip_attestation_sign \
	--whitelist-function securechip_monotonic_increments_remaining \
	--whitelist-function securechip_u2f_counter_set \
	--whitelist-function securechip_model \
	--rustified-enum securechip_model_t \
	--whitelist-var KEYSTORE_MAX_SEED_LENGTH \
	--whitelist-function keystore_is_locked \
	--whitelist-function keystore_unlock \
	--whitelist-function keystore_unlock_bip39 \
	--whitelist-function keystore_lock \
	--whitelist-function keystore_create_and_store_seed \
	--whitelist-function keystore_get_bip39_mnemonic \
	--whitelist-function keystore_get_bip39_word \
	--whitelist-function keystore_get_ed25519_seed \
	--whitelist-function keystore_secp256k1_pubkey_uncompressed \
	--whitelist-function keystore_secp256k1_nonce_commit \
	--whitelist-function keystore_secp256k1_sign \
	--whitelist-function keystore_bip39_mnemonic_to_seed \
	--whitelist-function keystore_get_root_fingerprint \
	--whitelist-function mock_state \
	--whitelist-var EC_PUBLIC_KEY_UNCOMPRESSED_LEN \
	--whitelist-var EC_PUBLIC_KEY_LEN \
	--whitelist-function keystore_encode_xpub_at_keypath \
	--whitelist-function keystore_encrypt_and_store_seed \
	--rustified-enum xpub_type_t \
	--whitelist-var XPUB_ENCODED_LEN \
	--whitelist-function lock_animation_start \
	--whitelist-function lock_animation_stop \
	--whitelist-function delay_us \
	--rustified-enum keystore_error_t \
	--rustified-enum keystore_secp256k1_pubkey_format \
	--whitelist-function util_format_datetime \
	--whitelist-function util_version_short \
	--whitelist-function delay_ms \
	--whitelist-function UG_PutString \
	--whitelist-function UG_FontSelect \
	--whitelist-function UG_ClearBuffer \
	--whitelist-function UG_SendBuffer \
	--whitelist-function screen_print_debug \
	--whitelist-function ui_screen_stack_push \
	--whitelist-function ui_screen_stack_pop \
	--whitelist-function ui_screen_stack_pop_all \
	--whitelist-function screen_process \
	--whitelist-function label_create \
	--whitelist-function confirm_create \
	--whitelist-function status_create \
	--whitelist-function sdcard_create \
	--whitelist-function menu_create \
	--whitelist-function trinary_choice_create \
	--rustified-enum trinary_choice_t \
	--whitelist-function wally_sha256 \
	--whitelist-function random_32_bytes_mcu \
	--whitelist-type component_t \
	--whitelist-type confirm_params_t \
	--whitelist-type commander_error_t \
	--rustified-enum commander_error_t \
	--whitelist-function commander \
	--whitelist-function commander_states_can_call \
	--whitelist-function commander_states_clear_force_next \
	--whitelist-var ".*_tag" \
	--whitelist-var MAX_LABEL_SIZE \
	--whitelist-var font_font_a_9X9 \
	--whitelist-var font_font_a_11X10 \
	--whitelist-var font_monogram_5X9 \
	--whitelist-var font_password_11X12 \
	--whitelist-var WALLY_OK \
	--whitelist-type trinary_input_string_params_t \
	--whitelist-var INPUT_STRING_MAX_SIZE \
	--whitelist-function trinary_input_string_create \
	--whitelist-function trinary_input_string_set_input \
	--whitelist-function confirm_transaction_address_create \
	--whitelist-function confirm_transaction_fee_create \
	--whitelist-function reset_reset \
	--whitelist-function sd_card_inserted \
	--whitelist-function sd_format \
	--whitelist-function sd_list_subdir \
	--whitelist-function sd_free_list \
	--whitelist-var BIP39_WORDLIST_LEN \
	--whitelist-function app_eth_params_get \
	--whitelist-function app_eth_erc20_params_get \
	--whitelist-function app_eth_sighash \
	--whitelist-function app_btc_address_simple \
	--whitelist-function reboot \
	"${SOURCE}" \
	-- \
	-DPB_NO_PACKED_STRUCTS=1 -DPB_FIELD_16BIT=1 -fshort-enums \
	"${FLAGS[@]}"
