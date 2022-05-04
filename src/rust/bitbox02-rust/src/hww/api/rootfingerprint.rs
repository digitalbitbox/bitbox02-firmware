// Copyright 2021 Shift Crypto AG
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

use super::pb;
use super::Error;

use pb::response::Response;

use bitbox02::keystore;

use crate::workflow::confirm;

/// Returns the keystore's root fingerprint, which is the first 32
/// bits of the hash160 of the pubkey at the keypath m/.
/// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#key-identifiers
pub async fn process(request: &pb::RootFingerprintRequest) -> Result<Response, Error> {
    let fingerprint = keystore::root_fingerprint()?;
    if request.display {
        confirm::confirm(&confirm::Params {
            body: &format!("Root fingerprint:\n{}", &hex::encode(&fingerprint[..])),
            accept_only: true,
            ..Default::default()
        })
        .await?;
    }
    Ok(Response::Fingerprint(pb::RootFingerprintResponse {
        fingerprint: fingerprint.to_vec(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::bb02_async::block_on;
    use alloc::boxed::Box;
    use bitbox02::keystore::lock;
    use bitbox02::testing::{mock, mock_unlocked_using_mnemonic, Data};

    #[test]
    fn test_process() {
        lock();
        assert_eq!(
            block_on(process(&pb::RootFingerprintRequest { display: false })),
            Err(Error::Generic)
        );

        mock_unlocked_using_mnemonic(
            "purity concert above invest pigeon category peace tuition hazard vivid latin since legal speak nation session onion library travel spell region blast estate stay"
        );
        assert_eq!(
            block_on(process(&pb::RootFingerprintRequest { display: false })),
            Ok(Response::Fingerprint(pb::RootFingerprintResponse {
                fingerprint: vec![0x02, 0x40, 0xe9, 0x2a],
            }))
        );

        static mut CONFIRM_COUNTER: u32 = 0;
        mock(Data {
            ui_confirm_create: Some(Box::new(|params| {
                match unsafe {
                    CONFIRM_COUNTER += 1;
                    CONFIRM_COUNTER
                } {
                    1 => {
                        assert_eq!(params.title, "");
                        assert_eq!(params.body, "Root fingerprint:\nf40b469a");
                        true
                    }
                    _ => panic!("too many user confirmations"),
                }
            })),
            ..Default::default()
        });
        mock_unlocked_using_mnemonic(
            "small agent wife animal marine cloth exit thank stool idea steel frame",
        );
        assert_eq!(
            block_on(process(&pb::RootFingerprintRequest { display: true })),
            Ok(Response::Fingerprint(pb::RootFingerprintResponse {
                fingerprint: vec![0xf4, 0x0b, 0x46, 0x9a],
            }))
        );
        assert_eq!(unsafe { CONFIRM_COUNTER }, 1);
    }
}
