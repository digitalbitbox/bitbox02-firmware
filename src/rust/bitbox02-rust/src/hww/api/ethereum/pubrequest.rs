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

use super::pb;
use super::Error;

use pb::eth_pub_request::OutputType;
use pb::eth_response::Response;

use crate::workflow::confirm;
use bitbox02::keystore;

extern crate alloc;
use core::convert::TryInto;

fn coin_title(coin: pb::EthCoin) -> &'static str {
    match coin {
        pb::EthCoin::Eth => "Ethereum",
        pb::EthCoin::RopstenEth => "Ropsten",
        pb::EthCoin::RinkebyEth => "Rinkeby",
        pb::EthCoin::Etc => "Ethereum Classic",
        pb::EthCoin::KottiEtc => "Kotti",
        pb::EthCoin::MordorEtc => "Mordor",
    }
}

async fn process_address(request: &pb::EthPubRequest) -> Result<Response, Error> {
    let coin = pb::EthCoin::from_i32(request.coin).ok_or(Error::InvalidInput)?;
    let params = bitbox02::app_eth::params_get(request.coin as _).ok_or(Error::InvalidInput)?;
    // If a contract_address is provided, it has to be a supported ERC20-token.
    let erc20_params: Option<bitbox02::app_eth::ERC20Params> =
        if request.contract_address.is_empty() {
            None
        } else {
            let address: [u8; 20] = request
                .contract_address
                .as_slice()
                .try_into()
                .or(Err(Error::InvalidInput))?;
            Some(
                bitbox02::app_eth::erc20_params_get(request.coin as _, address)
                    .ok_or(Error::InvalidInput)?,
            )
        };

    if !ethereum::keypath::is_valid_keypath_address(&request.keypath, params.bip44_coin) {
        return Err(Error::InvalidInput);
    }
    let pubkey = bitbox02::keystore::secp256k1_pubkey_uncompressed(&request.keypath)
        .or(Err(Error::InvalidInput))?;
    let address = ethereum::address::from_pubkey(&pubkey);

    if request.display {
        let title = match erc20_params {
            Some(erc20_params) => erc20_params.name,
            None => coin_title(coin),
        };
        let params = confirm::Params {
            title,
            title_autowrap: true,
            body: &address,
            scrollable: true,
            ..Default::default()
        };
        confirm::confirm(&params).await?;
    }

    Ok(Response::Pub(pb::PubResponse { r#pub: address }))
}

fn process_xpub(request: &pb::EthPubRequest) -> Result<Response, Error> {
    if request.display {
        // No xpub user verification for now.
        return Err(Error::InvalidInput);
    }

    let params = bitbox02::app_eth::params_get(request.coin as _).ok_or(Error::InvalidInput)?;
    if !ethereum::keypath::is_valid_keypath_xpub(&request.keypath, params.bip44_coin) {
        return Err(Error::InvalidInput);
    }
    let xpub = keystore::encode_xpub_at_keypath(&request.keypath, keystore::xpub_type_t::XPUB)
        .or(Err(Error::InvalidInput))?;

    Ok(Response::Pub(pb::PubResponse { r#pub: xpub }))
}

pub async fn process(request: &pb::EthPubRequest) -> Result<Response, Error> {
    let output_type = OutputType::from_i32(request.output_type).ok_or(Error::InvalidInput)?;
    match output_type {
        OutputType::Address => process_address(request).await,
        OutputType::Xpub => process_xpub(request),
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    use crate::bb02_async::block_on;
    use bitbox02::testing::{mock, mock_unlocked, Data, MUTEX};
    use std::boxed::Box;
    use util::bip32::HARDENED;

    #[test]
    pub fn test_process_xpub() {
        let _guard = MUTEX.lock().unwrap();

        const EXPECTED_XPUB: &str = "xpub";
        let request = pb::EthPubRequest {
            output_type: OutputType::Xpub as _,
            keypath: [44 + HARDENED, 60 + HARDENED, 0 + HARDENED, 0].to_vec(),
            coin: pb::EthCoin::Eth as _,
            display: false,
            contract_address: b"".to_vec(),
        };

        // All good.
        mock(Data {
            keystore_encode_xpub_at_keypath: Some(Box::new(|_, xpub_type| {
                assert_eq!(xpub_type, keystore::xpub_type_t::XPUB);
                Ok(EXPECTED_XPUB.into())
            })),
            ..Default::default()
        });
        assert_eq!(
            block_on(process(&request)),
            Ok(Response::Pub(pb::PubResponse {
                r#pub: EXPECTED_XPUB.into()
            }))
        );

        // Params not found.
        let mut invalid_request = request.clone();
        invalid_request.coin = 100;
        mock(Data {
            ..Default::default()
        });
        assert_eq!(
            block_on(process(&invalid_request)),
            Err(Error::InvalidInput)
        );

        // Wrong keypath (wrong expected coin)
        let mut invalid_request = request.clone();
        invalid_request.keypath[1] = 61 + HARDENED;
        mock(Data {
            ..Default::default()
        });
        assert_eq!(
            block_on(process(&invalid_request)),
            Err(Error::InvalidInput)
        );

        // xpub fetching/encoding failed.
        mock(Data {
            keystore_encode_xpub_at_keypath: Some(Box::new(|_, _| Err(()))),
            ..Default::default()
        });
        assert_eq!(block_on(process(&request)), Err(Error::InvalidInput));
    }

    #[test]
    pub fn test_process_address() {
        let _guard = MUTEX.lock().unwrap();

        const ADDRESS: &str = "0x773A77b9D32589be03f9132AF759e294f7851be9";

        let request = &pb::EthPubRequest {
            output_type: OutputType::Address as _,
            keypath: [44 + HARDENED, 60 + HARDENED, 0 + HARDENED, 0, 0].to_vec(),
            coin: pb::EthCoin::Eth as _,
            display: false,
            contract_address: b"".to_vec(),
        };

        // All good.
        mock(Data {
            ..Default::default()
        });
        mock_unlocked();
        assert_eq!(
            block_on(process(&request)),
            Ok(Response::Pub(pb::PubResponse {
                r#pub: ADDRESS.into()
            }))
        );

        // All good, with display.
        mock(Data {
            ui_confirm_create: Some(Box::new(|params| {
                assert_eq!(params.title, "Ethereum");
                assert_eq!(params.body, ADDRESS);
                true
            })),
            ..Default::default()
        });
        mock_unlocked();
        assert_eq!(
            block_on(process(&pb::EthPubRequest {
                output_type: OutputType::Address as _,
                keypath: [44 + HARDENED, 60 + HARDENED, 0 + HARDENED, 0, 0].to_vec(),
                coin: pb::EthCoin::Eth as _,
                display: true,
                contract_address: b"".to_vec(),
            })),
            Ok(Response::Pub(pb::PubResponse {
                r#pub: ADDRESS.into()
            }))
        );

        // Keystore locked.
        mock(Data {
            ui_confirm_create: Some(Box::new(|_| true)),
            ..Default::default()
        });
        assert_eq!(
            block_on(process(&pb::EthPubRequest {
                output_type: OutputType::Address as _,
                keypath: [44 + HARDENED, 60 + HARDENED, 0 + HARDENED, 0, 0].to_vec(),
                coin: pb::EthCoin::Eth as _,
                display: true,
                contract_address: b"".to_vec(),
            })),
            Err(Error::InvalidInput)
        );

        // Params not found.
        let mut invalid_request = request.clone();
        invalid_request.coin = 100;
        mock(Data {
            ..Default::default()
        });
        assert_eq!(
            block_on(process(&invalid_request)),
            Err(Error::InvalidInput)
        );

        // Wrong keypath (wrong expected coin)
        let mut invalid_request = request.clone();
        invalid_request.keypath[1] = 61 + HARDENED;
        mock(Data {
            ..Default::default()
        });
        assert_eq!(
            block_on(process(&invalid_request)),
            Err(Error::InvalidInput)
        );

        // Wrong keypath (account too high)
        mock(Data {
            ..Default::default()
        });
        assert_eq!(
            block_on(process(&pb::EthPubRequest {
                output_type: OutputType::Address as _,
                keypath: [44 + HARDENED, 60 + HARDENED, 0 + HARDENED, 0, 100].to_vec(),
                coin: pb::EthCoin::Eth as _,
                display: false,
                contract_address: b"".to_vec(),
            })),
            Err(Error::InvalidInput)
        );
    }

    #[test]
    pub fn test_process_erc20_address() {
        let _guard = MUTEX.lock().unwrap();

        const ADDRESS: &str = "0x773A77b9D32589be03f9132AF759e294f7851be9";
        const CONTRACT_ADDRESS: [u8; 20] =
            *b"\xda\xc1\x7f\x95\x8d\x2e\xe5\x23\xa2\x20\x62\x06\x99\x45\x97\xc1\x3d\x83\x1e\xc7";

        let request = &pb::EthPubRequest {
            output_type: OutputType::Address as _,
            keypath: [44 + HARDENED, 60 + HARDENED, 0 + HARDENED, 0, 0].to_vec(),
            coin: pb::EthCoin::Eth as _,
            display: false,
            contract_address: CONTRACT_ADDRESS.to_vec(),
        };

        // All good.
        mock(Data {
            ..Default::default()
        });
        mock_unlocked();
        assert_eq!(
            block_on(process(&request)),
            Ok(Response::Pub(pb::PubResponse {
                r#pub: ADDRESS.into()
            }))
        );

        // All good, with display.
        mock(Data {
            ui_confirm_create: Some(Box::new(|params| {
                assert_eq!(params.title, "Tether USD");
                assert_eq!(params.body, ADDRESS);
                true
            })),
            ..Default::default()
        });
        mock_unlocked();
        assert_eq!(
            block_on(process(&pb::EthPubRequest {
                output_type: OutputType::Address as _,
                keypath: [44 + HARDENED, 60 + HARDENED, 0 + HARDENED, 0, 0].to_vec(),
                coin: pb::EthCoin::Eth as _,
                display: true,
                contract_address: CONTRACT_ADDRESS.to_vec(),
            })),
            Ok(Response::Pub(pb::PubResponse {
                r#pub: ADDRESS.into()
            }))
        );

        // ERC20 params not found / invalid contract address.
        mock(Data {
            ..Default::default()
        });
        assert_eq!(
            block_on(process(&pb::EthPubRequest {
                output_type: OutputType::Address as _,
                keypath: [44 + HARDENED, 60 + HARDENED, 0 + HARDENED, 0, 0].to_vec(),
                coin: pb::EthCoin::Eth as _,
                display: false,
                contract_address: b"aaaaaaaaaaaaaaaaaaaa".to_vec(),
            })),
            Err(Error::InvalidInput)
        );
    }
}
