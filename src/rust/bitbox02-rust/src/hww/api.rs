// Copyright 2020 Shift Crypto AG
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::pb;

pub(super) mod error;

#[cfg(feature = "app-ethereum")]
mod ethereum;

#[cfg(any(feature = "app-bitcoin", feature = "app-litecoin"))]
pub mod bitcoin;

#[cfg(feature = "app-cardano")]
mod cardano;

mod backup;
mod device_info;
mod electrum;
mod reset;
mod restore;
mod rootfingerprint;
mod sdcard;
mod set_device_name;
mod set_mnemonic_passphrase_enabled;
mod set_password;
mod show_mnemonic;
mod system;

use alloc::vec::Vec;

use error::{make_error, Error};
use pb::request::Request;
use pb::response::Response;
use prost::Message;

/// Encodes a protobuf Response message.
pub fn encode(response: Response) -> Vec<u8> {
    let response = pb::Response {
        response: Some(response),
    };
    response.encode_to_vec()
}

/// Decodes a protofbuf Request message.
pub fn decode(input: &[u8]) -> Result<Request, Error> {
    match pb::Request::decode(input) {
        Ok(pb::Request {
            request: Some(request),
        }) => Ok(request),
        _ => Err(Error::InvalidInput),
    }
}

/// Returns the field tag number of the request as defined in the .proto file.  This is needed for
/// compatibility with commander_states.c.
fn request_tag(request: &Request) -> u32 {
    use Request::*;
    match request {
        DeviceName(_) => bitbox02::Request_device_name_tag,
        DeviceLanguage(_) => bitbox02::Request_device_language_tag,
        DeviceInfo(_) => bitbox02::Request_device_info_tag,
        SetPassword(_) => bitbox02::Request_set_password_tag,
        CreateBackup(_) => bitbox02::Request_create_backup_tag,
        ShowMnemonic(_) => bitbox02::Request_show_mnemonic_tag,
        BtcPub(_) => bitbox02::Request_btc_pub_tag,
        BtcSignInit(_) => bitbox02::Request_btc_sign_init_tag,
        BtcSignInput(_) => bitbox02::Request_btc_sign_input_tag,
        BtcSignOutput(_) => bitbox02::Request_btc_sign_output_tag,
        InsertRemoveSdcard(_) => bitbox02::Request_insert_remove_sdcard_tag,
        CheckSdcard(_) => bitbox02::Request_check_sdcard_tag,
        SetMnemonicPassphraseEnabled(_) => bitbox02::Request_set_mnemonic_passphrase_enabled_tag,
        ListBackups(_) => bitbox02::Request_list_backups_tag,
        RestoreBackup(_) => bitbox02::Request_restore_backup_tag,
        PerformAttestation(_) => bitbox02::Request_perform_attestation_tag,
        Reboot(_) => bitbox02::Request_reboot_tag,
        CheckBackup(_) => bitbox02::Request_check_backup_tag,
        Eth(_) => bitbox02::Request_eth_tag,
        Reset(_) => bitbox02::Request_reset_tag,
        RestoreFromMnemonic(_) => bitbox02::Request_restore_from_mnemonic_tag,
        Fingerprint(_) => bitbox02::Request_fingerprint_tag,
        Btc(_) => bitbox02::Request_btc_tag,
        ElectrumEncryptionKey(_) => bitbox02::Request_electrum_encryption_key_tag,
        Cardano(_) => bitbox02::Request_cardano_tag,
    }
}

#[cfg(any(feature = "app-bitcoin", feature = "app-litecoin"))]
async fn process_api_btc(request: &Request) -> Option<Result<Response, Error>> {
    match request {
        Request::BtcPub(ref request) => bitcoin::process_pub(request).await,
        Request::BtcSignInit(ref request) => Some(bitcoin::signtx::process(request).await),
        // These are streamed asynchronously using the `next_request()` primitive in
        // bitcoin/signtx.rs and are not handled directly.
        Request::BtcSignInput(_) | Request::BtcSignOutput(_) => Some(Err(Error::InvalidState)),
        Request::Btc(pb::BtcRequest {
            request: Some(request),
        }) => bitcoin::process_api(request)
            .await
            .map(|r| r.map(|r| Response::Btc(pb::BtcResponse { response: Some(r) }))),
        _ => None,
    }
}

#[cfg(not(any(feature = "app-bitcoin", feature = "app-litecoin")))]
async fn process_api_btc(_request: &Request) -> Option<Result<Response, Error>> {
    Some(Err(Error::Disabled))
}

/// Handle a protobuf api call.
///
/// Returns `None` if the call was not handled by Rust, in which case it should be handled by
/// the C commander.
async fn process_api(request: &Request) -> Option<Result<Response, Error>> {
    match request {
        Request::Reboot(ref request) => Some(system::reboot(request).await),
        Request::DeviceInfo(_) => Some(device_info::process()),
        Request::DeviceName(ref request) => Some(set_device_name::process(request).await),
        Request::SetPassword(ref request) => Some(set_password::process(request).await),
        Request::Reset(_) => Some(reset::process().await),
        Request::SetMnemonicPassphraseEnabled(ref request) => {
            Some(set_mnemonic_passphrase_enabled::process(request).await)
        }
        Request::InsertRemoveSdcard(ref request) => Some(sdcard::process(request).await),
        Request::ListBackups(_) => Some(backup::list()),
        Request::CheckSdcard(_) => Some(Ok(Response::CheckSdcard(pb::CheckSdCardResponse {
            inserted: bitbox02::sdcard_inserted(),
        }))),
        Request::CheckBackup(ref request) => Some(backup::check(request).await),
        Request::CreateBackup(ref request) => Some(backup::create(request).await),
        Request::RestoreBackup(ref request) => Some(restore::from_file(request).await),
        Request::ShowMnemonic(_) => Some(show_mnemonic::process().await),
        Request::RestoreFromMnemonic(ref request) => Some(restore::from_mnemonic(request).await),
        Request::ElectrumEncryptionKey(ref request) => Some(electrum::process(request).await),

        #[cfg(feature = "app-ethereum")]
        Request::Eth(pb::EthRequest {
            request: Some(ref request),
        }) => ethereum::process_api(request)
            .await
            .map(|r| r.map(|r| Response::Eth(pb::EthResponse { response: Some(r) }))),
        #[cfg(not(feature = "app-ethereum"))]
        Request::Eth(_) => Some(Err(Error::Disabled)),

        Request::Fingerprint(ref request) => Some(rootfingerprint::process(request).await),
        request @ Request::BtcPub(_)
        | request @ Request::Btc(_)
        | request @ Request::BtcSignInit(_) => process_api_btc(request).await,

        #[cfg(feature = "app-cardano")]
        Request::Cardano(pb::CardanoRequest {
            request: Some(ref request),
        }) => Some(
            cardano::process_api(request)
                .await
                .map(|r| Response::Cardano(pb::CardanoResponse { response: Some(r) })),
        ),
        #[cfg(not(feature = "app-cardano"))]
        Request::Cardano(_) => Some(Err(Error::Disabled)),
        _ => None,
    }
}

/// Handle a protobuf api call.  API calls not handled by Rust are
/// handled by the C commander, which allows us to use Rust for new
/// api calls and port the old calls step by step.
///
/// `input` is a hww.proto Request message, protobuf encoded.
/// Returns a protobuf encoded hww.proto Response message.
pub async fn process(input: Vec<u8>) -> Vec<u8> {
    let request = match decode(&input[..]) {
        Ok(request) => request,
        Err(err) => return encode(make_error(err)),
    };
    if !bitbox02::commander::states_can_call(request_tag(&request) as u16) {
        return encode(make_error(Error::InvalidState));
    }

    match process_api(&request).await {
        Some(Ok(response)) => encode(response),
        Some(Err(error)) => encode(make_error(error)),
        // Api call not handled in Rust -> handle it in C.
        None => bitbox02::commander::commander(input),
    }
}
