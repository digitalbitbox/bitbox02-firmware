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

#[cfg(not(feature = "app-bitcoin"))]
compile_error!("Bitcoin code is being compiled even though the app-bitcoin feature is not enabled");

mod bip143;
mod bip341;
pub mod common;
pub mod keypath;
mod multisig;
pub mod params;
mod payment_request;
mod policies;
mod registration;
mod script;
mod script_configs;
pub mod signmsg;
pub mod signtx;

use super::pb;
use super::Error;

use crate::workflow::confirm;

use util::bip32::HARDENED;

use crate::keystore;

use pb::btc_pub_request::{Output, XPubType};
use pb::btc_request::Request;
use pb::btc_script_config::{Config, SimpleType};
use pb::btc_script_config::{Multisig, Policy};
use pb::response::Response;
use pb::BtcCoin;
use pb::BtcScriptConfig;

use alloc::string::String;

/// Like `hww::next_request`, but for Bitcoin requests/responses.
pub async fn next_request(response: pb::btc_response::Response) -> Result<Request, Error> {
    let request = crate::hww::next_request(pb::response::Response::Btc(pb::BtcResponse {
        response: Some(response),
    }))
    .await?;
    match request {
        pb::request::Request::Btc(pb::BtcRequest {
            request: Some(request),
        }) => Ok(request),
        _ => Err(Error::InvalidState),
    }
}

/// Sends the `signer_nonce_commitment` to the host and waits for the next request, which has to be a
/// `AntiKleptoSignatureRequest` message containing the host nonce.
pub async fn antiklepto_get_host_nonce(
    signer_nonce_commitment: [u8; 33],
) -> Result<[u8; 32], Error> {
    let request = next_request(pb::btc_response::Response::AntikleptoSignerCommitment(
        pb::AntiKleptoSignerCommitment {
            commitment: signer_nonce_commitment.to_vec(),
        },
    ))
    .await?;
    match request {
        Request::AntikleptoSignature(pb::AntiKleptoSignatureRequest { host_nonce }) => {
            Ok(host_nonce
                .as_slice()
                .try_into()
                .or(Err(Error::InvalidInput))?)
        }
        _ => Err(Error::InvalidState),
    }
}

/// Returns `Ok(())` if the coin is enabled in this edition of the firmware.
fn coin_enabled(coin: pb::BtcCoin) -> Result<(), Error> {
    use pb::BtcCoin::*;
    #[cfg(feature = "app-bitcoin")]
    if let Btc | Tbtc = coin {
        return Ok(());
    }
    #[cfg(feature = "app-litecoin")]
    if let Ltc | Tltc = coin {
        return Ok(());
    }
    Err(Error::Disabled)
}

/// Processes an xpub api call.
async fn xpub(
    coin: BtcCoin,
    xpub_type: XPubType,
    keypath: &[u32],
    display: bool,
) -> Result<Response, Error> {
    let params = params::get(coin);
    let is_unusual =
        keypath::validate_xpub(keypath, params.bip44_coin, params.taproot_support).is_err();
    if is_unusual {
        // For unusual keypaths, we allow export after a confirmation.
        confirm::confirm(&confirm::Params {
            title: if display { "xpub" } else { "Export xpub" },
            body: &format!(
                "Warning: unusual keypath {}. Proceed only if you know what you are doing.",
                util::bip32::to_string(keypath)
            ),
            scrollable: true,
            longtouch: true,
            ..Default::default()
        })
        .await?
    }
    let xpub = keystore::get_xpub(keypath)
        .or(Err(Error::InvalidInput))?
        .serialize_str(xpub_type)?;
    if display {
        let title = if is_unusual {
            "".into()
        } else if keypath == [45 + HARDENED] {
            format!("{}\nat\n{}", params.name, util::bip32::to_string(keypath))
        } else {
            format!("{}\naccount #{}", params.name, keypath[2] - HARDENED + 1)
        };

        let confirm_params = confirm::Params {
            title: &title,
            body: &xpub,
            scrollable: true,
            ..Default::default()
        };
        confirm::confirm(&confirm_params).await?;
    }
    Ok(Response::Pub(pb::PubResponse { r#pub: xpub }))
}

pub fn derive_address_simple(
    coin: BtcCoin,
    simple_type: SimpleType,
    keypath: &[u32],
) -> Result<String, Error> {
    let coin_params = params::get(coin);
    keypath::validate_address_simple(
        keypath,
        coin_params.bip44_coin,
        simple_type,
        coin_params.taproot_support,
        keypath::ReceiveSpend::Receive,
    )
    .or(Err(Error::InvalidInput))?;
    Ok(common::Payload::from_simple(
        &mut crate::xpubcache::XpubCache::new(),
        coin_params,
        simple_type,
        keypath,
    )?
    .address(coin_params)?)
}

/// Processes a SimpleType (single-sig) address api call.
async fn address_simple(
    coin: BtcCoin,
    simple_type: SimpleType,
    keypath: &[u32],
    display: bool,
) -> Result<Response, Error> {
    let address = derive_address_simple(coin, simple_type, keypath)?;
    if display {
        let confirm_params = confirm::Params {
            title: params::get(coin).name,
            body: &address,
            scrollable: true,
            ..Default::default()
        };
        confirm::confirm(&confirm_params).await?;
    }
    Ok(Response::Pub(pb::PubResponse { r#pub: address }))
}

/// Processes a multisig address api call.
pub async fn address_multisig(
    coin: BtcCoin,
    multisig: &Multisig,
    keypath: &[u32],
    display: bool,
) -> Result<Response, Error> {
    let coin_params = params::get(coin);
    keypath::validate_address_policy(keypath, keypath::ReceiveSpend::Receive)
        .or(Err(Error::InvalidInput))?;
    let account_keypath = &keypath[..keypath.len() - 2];
    multisig::validate(multisig, account_keypath)?;
    let name = match multisig::get_name(coin, multisig, account_keypath)? {
        Some(name) => name,
        None => return Err(Error::InvalidInput),
    };
    let title = "Receive to";
    if display {
        multisig::confirm(title, coin_params, &name, multisig).await?;
    }
    let address = common::Payload::from_multisig(
        coin_params,
        multisig,
        keypath[keypath.len() - 2],
        keypath[keypath.len() - 1],
    )?
    .address(coin_params)?;
    if display {
        confirm::confirm(&confirm::Params {
            title,
            body: &address,
            scrollable: true,
            ..Default::default()
        })
        .await?;
    }
    Ok(Response::Pub(pb::PubResponse { r#pub: address }))
}

/// Processes a policy address api call.
async fn address_policy(
    coin: BtcCoin,
    policy: &Policy,
    keypath: &[u32],
    display: bool,
) -> Result<Response, Error> {
    let coin_params = params::get(coin);

    keypath::validate_address_policy(keypath, keypath::ReceiveSpend::Receive)
        .or(Err(Error::InvalidInput))?;

    let parsed = policies::parse(policy, coin)?;

    let name = match policies::get_name(coin, policy)? {
        Some(name) => name,
        None => return Err(Error::InvalidInput),
    };

    let title = "Receive to";

    if display {
        parsed
            .confirm(title, coin_params, &name, policies::Mode::Basic)
            .await?;
    }

    let address =
        common::Payload::from_policy(coin_params, &parsed, keypath)?.address(coin_params)?;
    if display {
        confirm::confirm(&confirm::Params {
            title,
            body: &address,
            scrollable: true,
            ..Default::default()
        })
        .await?;
    }
    Ok(Response::Pub(pb::PubResponse { r#pub: address }))
}

/// Handle a Bitcoin xpub/address protobuf api call.
pub async fn process_pub(request: &pb::BtcPubRequest) -> Result<Response, Error> {
    let coin = BtcCoin::try_from(request.coin)?;
    coin_enabled(coin)?;
    match request.output {
        None => Err(Error::InvalidInput),
        Some(Output::XpubType(xpub_type)) => {
            let xpub_type = XPubType::try_from(xpub_type)?;
            xpub(coin, xpub_type, &request.keypath, request.display).await
        }
        Some(Output::ScriptConfig(BtcScriptConfig {
            config: Some(Config::SimpleType(simple_type)),
        })) => {
            let simple_type = SimpleType::try_from(simple_type)?;
            address_simple(coin, simple_type, &request.keypath, request.display).await
        }
        Some(Output::ScriptConfig(BtcScriptConfig {
            config: Some(Config::Multisig(ref multisig)),
        })) => address_multisig(coin, multisig, &request.keypath, request.display).await,
        Some(Output::ScriptConfig(BtcScriptConfig {
            config: Some(Config::Policy(ref policy)),
        })) => address_policy(coin, policy, &request.keypath, request.display).await,
        _ => Err(Error::InvalidInput),
    }
}

/// Handle a nexted Bitcoin protobuf api call.
pub async fn process_api(request: &Request) -> Result<pb::btc_response::Response, Error> {
    match request {
        Request::IsScriptConfigRegistered(ref request) => {
            registration::process_is_script_config_registered(request)
        }
        Request::RegisterScriptConfig(ref request) => {
            registration::process_register_script_config(request).await
        }
        Request::SignMessage(ref request) => signmsg::process(request).await,
        // These are streamed asynchronously using the `next_request()` primitive in
        // bitcoin/signtx.rs and are not handled directly.
        Request::PrevtxInit(_)
        | Request::PrevtxInput(_)
        | Request::PrevtxOutput(_)
        | Request::AntikleptoSignature(_)
        | Request::PaymentRequest(_) => Err(Error::InvalidState),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::bb02_async::block_on;
    use crate::bip32::parse_xpub;
    use alloc::boxed::Box;
    use alloc::vec::Vec;
    use bitbox02::testing::{
        mock, mock_memory, mock_unlocked, mock_unlocked_using_mnemonic, Data, TEST_MNEMONIC,
    };
    use pb::btc_script_config::multisig::ScriptType as MultisigScriptType;
    use util::bip32::HARDENED;

    #[test]
    pub fn test_xpub() {
        struct Test<'a> {
            mnemonic: &'a str,
            coin: BtcCoin,
            keypath: &'a [u32],
            xpub_type: XPubType,
            expected_xpub: &'a str,
            expected_display_title: &'a str,
        }

        for test in vec![
            // BTC P2WPKH-P2SH
            Test {
                mnemonic: TEST_MNEMONIC,
                coin: BtcCoin::Btc,
                keypath: &[49 + HARDENED, 0 + HARDENED, 0 + HARDENED],
                xpub_type: XPubType::Xpub,
                expected_xpub: "xpub6Bj8T8R98MTKGDcMpJnoKeHR54EF1JJohA2HLs2WeNiaZ9UdNVvAbYpPnVd3Mcymabx7fYDKx4ubku1DTPRoDzpziD4qK3vxN9FEiF25Hgx",
                expected_display_title: "Bitcoin\naccount #1",
            },
            Test {
                mnemonic: TEST_MNEMONIC,
                coin: BtcCoin::Btc,
                keypath: &[49 + HARDENED, 0 + HARDENED, 0 + HARDENED],
                xpub_type: XPubType::Ypub,
                expected_xpub: "ypub6WZPko64H2zo7WoUefaRXjNvF2NgwvJJcGYW8FvQ2P6TcFHrdA5jDcUXohadMXdgzF4vR1otQjG9eBcnB5qp2EWbaYmFtxkSdsJt6svswWd",
                expected_display_title: "Bitcoin\naccount #1",
            },
            Test {
                mnemonic: TEST_MNEMONIC,
                coin: BtcCoin::Btc,
                keypath: &[49 + HARDENED, 0 + HARDENED, 0 + HARDENED],
                xpub_type: XPubType::Zpub,
                expected_xpub: "zpub6qPf4TkyRiYGxozbV2N3jpURQzX8tYHoXP4iuepHQPULfM75spFHqg8fpuYDMSHcPtBjAVQSsPchXUELtnFppUCCStTgUsZvubNXVPGWjcc",
                expected_display_title: "Bitcoin\naccount #1",
            },
            Test {
                mnemonic: TEST_MNEMONIC,
                coin: BtcCoin::Btc,
                keypath: &[84 + HARDENED, 0 + HARDENED, 1 + HARDENED],
                xpub_type: XPubType::Xpub,
                expected_xpub: "xpub6Bh4PT7iTyf6EHrFhc2ZaRYQxiLexYJQ7DtnNSNipD19JRV5jUW4gVHV9ouWvRY6DbbfyQhjP9E7LQ9QuR1SkPMnMi8NP3o2WtnWZim6Dqd",
                expected_display_title: "Bitcoin\naccount #2",
            },
            // BTC P2WPKH
            Test {
                mnemonic: TEST_MNEMONIC,
                coin: BtcCoin::Btc,
                keypath: &[84 + HARDENED, 0 + HARDENED, 1 + HARDENED],
                xpub_type: XPubType::Zpub,
                expected_xpub: "zpub6qMaznTYmLk3vtEVNKbozbjRJedYqnHPwSwDwEAVaDkuQd7YEnqBvcbmCDpgvEqw2sqHUMtrJTwD6yNYLoqULriz6PXDYsS14LuoLr3KxUC",
                expected_display_title: "Bitcoin\naccount #2",
            },
            // BTC m/45', no warning
            Test {
                mnemonic: TEST_MNEMONIC,
                coin: BtcCoin::Btc,
                keypath: &[45 + HARDENED],
                xpub_type: XPubType::Xpub,
                expected_xpub: "xpub67uTYzYstMMVao9Z7sseYh5m9N51ft82f6Wo3Lp773Qxe1JxFFDyP71C3xvo3jZ3p1Cg3xZQ8eqsFBHYEVFZt9iqoTBEcCigcmxF1xgqBPm",
                expected_display_title: "Bitcoin\nat\nm/45'",
            },
            // BTC P2TR
            Test {
                // Test vector from https://github.com/bitcoin/bips/blob/edffe529056f6dfd33d8f716fb871467c3c09263/bip-0086.mediawiki#test-vectors
                mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
                coin: BtcCoin::Btc,
                keypath: &[86 + HARDENED, 0 + HARDENED, 0 + HARDENED],
                xpub_type: XPubType::Xpub,
                expected_xpub: "xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ",
                expected_display_title: "Bitcoin\naccount #1",
            },
            // TBTC P2WPKH-P2SH
            Test {
                mnemonic: TEST_MNEMONIC,
                coin: BtcCoin::Tbtc,
                keypath: &[49 + HARDENED, 1 + HARDENED, 0 + HARDENED],
                xpub_type: XPubType::Xpub,
                expected_xpub: "xpub6BmN7k2vQY7D5jQpmKErAMNRqgtDMz9ePjR83SRAR6GAiWr63z7QLBPvsEQ2ghgT8hm1BoeApuS3paSmGmax2u3ggETCfWJvCEu6jCZDneX",
                expected_display_title: "BTC Testnet\naccount #1",
            },
            Test {
                mnemonic: TEST_MNEMONIC,
                coin: BtcCoin::Tbtc,
                keypath: &[49 + HARDENED, 1 + HARDENED, 0 + HARDENED],
                xpub_type: XPubType::Tpub,
                expected_xpub: "tpubDC8zdyrc7p4fMXbgDWDwNGhoAoysMNehwN1RPzUJm124ToWo8CxVUd4m7GUpDCdgvcHuoPA3N1G6WkwNfdSBvLVyjqCWM2y9nCVWVGLFiLh",
                expected_display_title: "BTC Testnet\naccount #1",
            },
            // TBTC P2WPKH
            Test {
                mnemonic: TEST_MNEMONIC,
                coin: BtcCoin::Tbtc,
                keypath: &[84 + HARDENED, 1 + HARDENED, 0 + HARDENED],
                xpub_type: XPubType::Xpub,
                expected_xpub: "xpub6Bs9jH3KF6w5ibrAdLAvY4759RnU74dnmUZ42m5FMqoFQoW9xL6co535xiGzaZMXrYn3nqk94ruLVfArx7sxvUvoXeF3FvXLX9T2dgTLGgc",
                expected_display_title: "BTC Testnet\naccount #1",
            },
            Test {
                mnemonic: TEST_MNEMONIC,
                coin: BtcCoin::Tbtc,
                keypath: &[84 + HARDENED, 1 + HARDENED, 0 + HARDENED],
                xpub_type: XPubType::Tpub,
                expected_xpub: "tpubDCEnFWrzxNtXzQ325XA1jySSUYt86T8rK79MPK8PhkZ9A6As2YwhwWhvCkMn74JmeTJxQRG1bxjPBqfULyjCovP6bEzLwTBa773SPehtXCt",
                expected_display_title: "BTC Testnet\naccount #1",
            },
            // TBTC P2TR
            Test {
                mnemonic: TEST_MNEMONIC,
                coin: BtcCoin::Tbtc,
                keypath: &[86 + HARDENED, 1 + HARDENED, 0 + HARDENED],
                xpub_type: XPubType::Xpub,
                expected_xpub: "xpub6CQ45XSCvP42pyFcnL1pm2xsCwvNbqFUN8BZwRdzFz4ZrMAuJHLjQt4KP9c2pSMfp5GVy64kUkpytwnRiandtuy8KAX7o9iuhFsN8KPj8Fw",
                expected_display_title: "BTC Testnet\naccount #1",
            },
            // LTC P2WPKH-P2SH
            Test {
                mnemonic: TEST_MNEMONIC,
                coin: BtcCoin::Ltc,
                keypath: &[49 + HARDENED, 2 + HARDENED, 0 + HARDENED],
                xpub_type: XPubType::Xpub,
                expected_xpub: "xpub6CC3f5yryzDqxUWHSFz69BcjP1yB7dX3d4MNoyCrc77Z3iAmDdfSmsTR2wCH4WnAhPcmRyAn4tnQsxBD9E1A3DiZ4PA81FUGCYXkJ5hUmEu",
                expected_display_title: "Litecoin\naccount #1",
            },
            // LTC P2WPKH
            Test {
                mnemonic: TEST_MNEMONIC,
                coin: BtcCoin::Ltc,
                keypath: &[84 + HARDENED, 2 + HARDENED, 0 + HARDENED],
                xpub_type: XPubType::Xpub,
                expected_xpub: "xpub6CJNSECzxso6VQF15vTqSMUCLDfYytpKgbCEtuMTs6Sbjd3CGUoXynTvQYWDBThN337scHJnjqnQrL31ttZFa9CicdB3pRodqWxyEQwnrqm",
                expected_display_title: "Litecoin\naccount #1",
            },
        ] {
            mock_unlocked_using_mnemonic(test.mnemonic, "");

            // Without display.
            let mut req = pb::BtcPubRequest {
                coin: test.coin as _,
                keypath: test.keypath.to_vec(),
                display: false,
                output: Some(Output::XpubType(test.xpub_type as _)),
            };

            assert_eq!(
                block_on(process_pub(&req)),
                Ok(Response::Pub(pb::PubResponse {
                    r#pub: test.expected_xpub.into(),
                })),
            );

            // With display.
            req.display = true;
            let expected_display_title = test.expected_display_title;
            let expected_xpub = test.expected_xpub;
            mock(Data {
                ui_confirm_create: Some(Box::new(move |params| {
                    assert_eq!(params.title, expected_display_title);
                    assert_eq!(params.body, expected_xpub);
                    assert!(params.scrollable);
                    true
                })),
                ..Default::default()
            });
            mock_unlocked_using_mnemonic(test.mnemonic, "");
            assert_eq!(
                block_on(process_pub(&req)),
                Ok(Response::Pub(pb::PubResponse {
                    r#pub: test.expected_xpub.into(),
                })),
            );
        }

        {
            // --- Unusual keypath, no display (still forces confirmation of unusual keypath)
            mock(Data {
                ui_confirm_create: Some(Box::new(move |params| {
                    assert_eq!(params.title, "Export xpub");
                    assert_eq!(params.body, "Warning: unusual keypath m/1'/2'/3'/4. Proceed only if you know what you are doing.");
                    assert!(params.scrollable);
                    assert!(params.longtouch);
                    true
                })),
                ..Default::default()
            });
            mock_unlocked();
            assert_eq!(
                block_on(process_pub(&pb::BtcPubRequest {
                    coin: BtcCoin::Btc as _,
                    keypath: [1 + HARDENED, 2 + HARDENED, 3 + HARDENED, 4].to_vec(),
                    display: false,
                    output: Some(Output::XpubType(XPubType::Xpub as _)),
                })),
                Ok(Response::Pub(pb::PubResponse {
                    r#pub: "xpub6DdW7n2P4Ht8m9DNumbzVKPU4yXoBMR9mm39q6tGp8PHGgNTJWL3fBdoUS4E8tP9XmyK4F85ApxLEBTB6f3fJf3Ujk5PaqssRuTLsRVTn6E".into(),
                }))
            );
        }

        {
            // --- Unusual keypath, with display
            static mut UI_COUNTER: u32 = 0;
            mock(Data {
                ui_confirm_create: Some(Box::new(move |params| {
                    match unsafe {
                        UI_COUNTER += 1;
                        UI_COUNTER
                    } {
                        1 => {
                            assert_eq!(params.title, "xpub");
                            assert_eq!(params.body, "Warning: unusual keypath m/1'/2'/3'/4. Proceed only if you know what you are doing.");
                            assert!(params.scrollable);
                            assert!(params.longtouch);
                        }
                        2 => {
                            assert_eq!(params.title, "");
                            assert_eq!(params.body, "xpub6DdW7n2P4Ht8m9DNumbzVKPU4yXoBMR9mm39q6tGp8PHGgNTJWL3fBdoUS4E8tP9XmyK4F85ApxLEBTB6f3fJf3Ujk5PaqssRuTLsRVTn6E");
                            assert!(params.scrollable);
                        }
                        _ => panic!("too many dialogs"),
                    }
                    true
                })),
                ..Default::default()
            });
            mock_unlocked();
            assert_eq!(
                block_on(process_pub(&pb::BtcPubRequest {
                    coin: BtcCoin::Btc as _,
                    keypath: [1 + HARDENED, 2 + HARDENED, 3 + HARDENED, 4].to_vec(),
                    display: true,
                    output: Some(Output::XpubType(XPubType::Xpub as _)),
                })),
                Ok(Response::Pub(pb::PubResponse {
                    r#pub: "xpub6DdW7n2P4Ht8m9DNumbzVKPU4yXoBMR9mm39q6tGp8PHGgNTJWL3fBdoUS4E8tP9XmyK4F85ApxLEBTB6f3fJf3Ujk5PaqssRuTLsRVTn6E".into(),
                }))
            );
        }

        let req = pb::BtcPubRequest {
            coin: BtcCoin::Btc as _,
            keypath: [49 + HARDENED, 0 + HARDENED, 0 + HARDENED].to_vec(),
            display: false,
            output: Some(Output::XpubType(XPubType::Xpub as _)),
        };

        // -- Wrong coin: MIN-1
        let mut req_invalid = req.clone();
        req_invalid.coin = BtcCoin::Btc as i32 - 1;
        assert!(block_on(process_pub(&req_invalid)).is_err());
        // -- Wrong coin: MAX + 1
        let mut req_invalid = req.clone();
        req_invalid.coin = BtcCoin::Tltc as i32 + 1;
        assert!(block_on(process_pub(&req_invalid)).is_err());
    }

    #[test]
    pub fn test_address_simple() {
        struct Test<'a> {
            mnemonic: &'a str,
            coin: BtcCoin,
            keypath: &'a [u32],
            simple_type: SimpleType,
            expected_address: &'a str,
            expected_display_title: &'a str,
        }

        for test in vec![
            // BTC P2WPKH-P2SH
            Test {
                mnemonic: TEST_MNEMONIC,
                coin: BtcCoin::Btc,
                keypath: &[49 + HARDENED, 0 + HARDENED, 0 + HARDENED, 0, 0],
                simple_type: SimpleType::P2wpkhP2sh,
                expected_address: "3BaL6XecvLAidPToUDhXo1zxD99ZUrErpd",
                expected_display_title: "Bitcoin",
            },
            Test {
                mnemonic: TEST_MNEMONIC,
                coin: BtcCoin::Btc,
                keypath: &[49 + HARDENED, 0 + HARDENED, 0 + HARDENED, 0, 1],
                simple_type: SimpleType::P2wpkhP2sh,
                expected_address: "3QRfCGEJVzvR1HN13kxB7xkuUtdEvG2orZ",
                expected_display_title: "Bitcoin",
            },
            Test {
                mnemonic: TEST_MNEMONIC,
                coin: BtcCoin::Btc,
                keypath: &[49 + HARDENED, 0 + HARDENED, 1 + HARDENED, 1, 100],
                simple_type: SimpleType::P2wpkhP2sh,
                expected_address: "39r7CFVo1wpb3mxQfkG6yYyxMAfqAmZMhA",
                expected_display_title: "Bitcoin",
            },
            // BTC P2WPKH
            Test {
                mnemonic: TEST_MNEMONIC,
                coin: BtcCoin::Btc,
                keypath: &[84 + HARDENED, 0 + HARDENED, 0 + HARDENED, 0, 0],
                simple_type: SimpleType::P2wpkh,
                expected_address: "bc1qk5f9em9qc8yfpks8ngfg3h8h02n2e3yeqdyhpt",
                expected_display_title: "Bitcoin",
            },
            Test {
                mnemonic: TEST_MNEMONIC,
                coin: BtcCoin::Btc,
                keypath: &[84 + HARDENED, 0 + HARDENED, 0 + HARDENED, 0, 1],
                simple_type: SimpleType::P2wpkh,
                expected_address: "bc1qtn7feuj7juxkzf48zfxtngrcyqyns9f4ska7hg",
                expected_display_title: "Bitcoin",
            },
            Test {
                mnemonic: TEST_MNEMONIC,
                coin: BtcCoin::Btc,
                keypath: &[84 + HARDENED, 0 + HARDENED, 1 + HARDENED, 1, 100],
                simple_type: SimpleType::P2wpkh,
                expected_address: "bc1qarhxx6daqetewkjwz9p6y78a28ygxm2vndhdas",
                expected_display_title: "Bitcoin",
            },
            // BTC P2TR
            // Test vectors from https://github.com/bitcoin/bips/blob/edffe529056f6dfd33d8f716fb871467c3c09263/bip-0086.mediawiki#test-vectors.
            Test {
                mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
                coin: BtcCoin::Btc,
                keypath: &[86 + HARDENED, 0 + HARDENED, 0 + HARDENED, 0, 0],
                simple_type: SimpleType::P2tr,
                expected_address: "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
                expected_display_title: "Bitcoin",
            },
            Test {
                mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
                coin: BtcCoin::Btc,
                keypath: &[86 + HARDENED, 0 + HARDENED, 0 + HARDENED, 0, 1],
                simple_type: SimpleType::P2tr,
                expected_address: "bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh",
                expected_display_title: "Bitcoin",
            },
            Test {
                mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
                coin: BtcCoin::Btc,
                keypath: &[86 + HARDENED, 0 + HARDENED, 0 + HARDENED, 1, 0],
                simple_type: SimpleType::P2tr,
                expected_address: "bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7",
                expected_display_title: "Bitcoin",
            },
            // TBTC P2WPKH-P2SH
            Test {
                mnemonic: TEST_MNEMONIC,
                coin: BtcCoin::Tbtc,
                keypath: &[49 + HARDENED, 1 + HARDENED, 0 + HARDENED, 0, 0],
                simple_type: SimpleType::P2wpkhP2sh,
                expected_address: "2N5Tjwx5Htk7gLbv7nWqXUgpg5K2Uf4TacQ",
                expected_display_title: "BTC Testnet",
            },
            // TBTC P2WPKH
            Test {
                mnemonic: TEST_MNEMONIC,
                coin: BtcCoin::Tbtc,
                keypath: &[84 + HARDENED, 1 + HARDENED, 0 + HARDENED, 0, 0],
                simple_type: SimpleType::P2wpkh,
                expected_address: "tb1qnlyrq9pshg0v0lsuudjgga4nvmjxhcvketqwdg",
                expected_display_title: "BTC Testnet",
            },
            // LTC P2WPKH-P2SH
            Test {
                mnemonic: TEST_MNEMONIC,
                coin: BtcCoin::Ltc,
                keypath: &[49 + HARDENED, 2 + HARDENED, 0 + HARDENED, 0, 0],
                simple_type: SimpleType::P2wpkhP2sh,
                expected_address: "MMmYgSH7fbTPnfdi1vTejMJyY7rKY4j9qv",
                expected_display_title: "Litecoin",
            },
            Test {
                mnemonic: TEST_MNEMONIC,
                coin: BtcCoin::Ltc,
                keypath: &[49 + HARDENED, 2 + HARDENED, 0 + HARDENED, 0, 1],
                simple_type: SimpleType::P2wpkhP2sh,
                expected_address: "M7wA8gBLL4SBiwQ1muQeKcG6naYqWcaUHg",
                expected_display_title: "Litecoin",
            },
            Test {
                mnemonic: TEST_MNEMONIC,
                coin: BtcCoin::Ltc,
                keypath: &[49 + HARDENED, 2 + HARDENED, 1 + HARDENED, 1, 100],
                simple_type: SimpleType::P2wpkhP2sh,
                expected_address: "MPBnihMP2JYjPtBnLxGydqvaALBsc5ALTG",
                expected_display_title: "Litecoin",
            },
            // LTC P2WPKH
            Test {
                mnemonic: TEST_MNEMONIC,
                coin: BtcCoin::Ltc,
                keypath: &[84 + HARDENED, 2 + HARDENED, 0 + HARDENED, 0, 0],
                simple_type: SimpleType::P2wpkh,
                expected_address: "ltc1q7598y6mzud5fka043vs4vkx7zktvppxffsf7e3",
                expected_display_title: "Litecoin",
            },
            Test {
                mnemonic: TEST_MNEMONIC,
                coin: BtcCoin::Ltc,
                keypath: &[84 + HARDENED, 2 + HARDENED, 0 + HARDENED, 0, 1],
                simple_type: SimpleType::P2wpkh,
                expected_address: "ltc1qtgjfu2ltg4slmksv27awmh6h2pccvsth4mw2w9",
                expected_display_title: "Litecoin",
            },
            Test {
                mnemonic: TEST_MNEMONIC,
                coin: BtcCoin::Ltc,
                keypath: &[84 + HARDENED, 2 + HARDENED, 1 + HARDENED, 1, 100],
                simple_type: SimpleType::P2wpkh,
                expected_address: "ltc1qwsz89auhpezjfllq9y9qegpfgdwpw5vesppsz0",
                expected_display_title: "Litecoin",
            },
            // TLTC P2WPKH-P2SH
            Test {
                mnemonic: TEST_MNEMONIC,
                coin: BtcCoin::Tltc,
                keypath: &[49 + HARDENED, 1 + HARDENED, 0 + HARDENED, 0, 0],
                simple_type: SimpleType::P2wpkhP2sh,
                expected_address: "2N5Tjwx5Htk7gLbv7nWqXUgpg5K2Uf4TacQ",
                expected_display_title: "LTC Testnet",
            },
            // TLTC P2WPKH
            Test {
                mnemonic: TEST_MNEMONIC,
                coin: BtcCoin::Tltc,
                keypath: &[84 + HARDENED, 1 + HARDENED, 0 + HARDENED, 0, 0],
                simple_type: SimpleType::P2wpkh,
                expected_address: "tltc1qnlyrq9pshg0v0lsuudjgga4nvmjxhcvkqrzsap",
                expected_display_title: "LTC Testnet",
            },
        ] {
            let mut req = pb::BtcPubRequest {
                coin: test.coin as _,
                keypath: test.keypath.to_vec(),
                display: false,
                output: Some(Output::ScriptConfig(BtcScriptConfig {
                    config: Some(Config::SimpleType(test.simple_type as _)),
                })),
            };

            // Without display.
            mock_unlocked_using_mnemonic(test.mnemonic, "");
            assert_eq!(
                block_on(process_pub(&req)),
                Ok(Response::Pub(pb::PubResponse {
                    r#pub: test.expected_address.into(),
                })),
            );

            // With display.
            req.display = true;
            let expected_display_title = test.expected_display_title;
            let expected_address = test.expected_address;
            mock(Data {
                ui_confirm_create: Some(Box::new(move |params| {
                    assert_eq!(params.title, expected_display_title);
                    assert_eq!(params.body, expected_address);
                    assert!(params.scrollable);
                    true
                })),
                ..Default::default()
            });
            mock_unlocked_using_mnemonic(test.mnemonic, "");
            assert_eq!(
                block_on(process_pub(&req)),
                Ok(Response::Pub(pb::PubResponse {
                    r#pub: test.expected_address.into()
                })),
            );
        }

        // --- Negative tests
        mock_unlocked();
        // First check a valid request:
        let req = pb::BtcPubRequest {
            coin: BtcCoin::Btc as _,
            keypath: [49 + HARDENED, 0 + HARDENED, 1 + HARDENED, 1, 100].to_vec(),
            display: false,
            output: Some(Output::ScriptConfig(BtcScriptConfig {
                config: Some(Config::SimpleType(SimpleType::P2wpkhP2sh as _)),
            })),
        };
        assert!(block_on(process_pub(&req)).is_ok());
        // -- Wrong coin: MIN-1
        let mut req_invalid = req.clone();
        req_invalid.coin = BtcCoin::Btc as i32 - 1;
        assert!(block_on(process_pub(&req_invalid)).is_err());
        // -- Wrong coin: MAX + 1
        let mut req_invalid = req.clone();
        req_invalid.coin = BtcCoin::Tltc as i32 + 1;
        assert!(block_on(process_pub(&req_invalid)).is_err());
        // -- Wrong keypath
        let mut req_invalid = req.clone();
        req_invalid.keypath = [49 + HARDENED, 0 + HARDENED, 1 + HARDENED, 1, 10000].to_vec();
        assert!(block_on(process_pub(&req_invalid)).is_err());
        // -- No taproot in Litecoin
        assert!(block_on(process_pub(&pb::BtcPubRequest {
            coin: BtcCoin::Ltc as _,
            keypath: [86 + HARDENED, 0 + HARDENED, 0 + HARDENED, 0, 0].to_vec(),
            display: false,
            output: Some(Output::ScriptConfig(BtcScriptConfig {
                config: Some(Config::SimpleType(SimpleType::P2tr as _)),
            })),
        }))
        .is_err());
    }

    #[test]
    pub fn test_address_multisig() {
        static mut UI_COUNTER: u32 = 0;
        struct Test<'a> {
            coin: BtcCoin,
            xpubs: &'a [&'a str],
            threshold: u32,
            expected_info: &'a str,
            our_xpub_index: u32,
            keypath: &'a [u32],
            script_type: MultisigScriptType,
            expected_address: &'a str,
        }
        let tests = &[
            /* P2WSH */
            Test {
                coin: BtcCoin::Btc,
                threshold: 1,
                xpubs: &[
                    "xpub6FEZ9Bv73h1vnE4TJG4QFj2RPXJhhsPbnXgFyH3ErLvpcZrDcynY65bhWga8PazWHLSLi23PoBhGcLcYW6JRiJ12zXZ9Aop4LbAqsS3gtcy",
                    "xpub6EGAio99SxruuNxoBtG4fbYx3xM8fs7wjYJLRNcUg7UQin3LTANQiUYyb3RLjZ2EAyLsQBrtbNENUGh3oWzjHtgfQ3mtjPNFgNMronzTTVR",
                ],
                expected_info: "1-of-2\nBitcoin multisig",
                our_xpub_index: 1,
                keypath: &[
                    48 + HARDENED,
                    0 + HARDENED,
                    0 + HARDENED,
                    2 + HARDENED,
                    1,
                    2,
                ],
                script_type: MultisigScriptType::P2wsh,
                expected_address: "bc1q2fhgukymf0caaqrhfxrdju4wm94wwrch2ukntl5fuc0faz8zm49q0h6ss8",
            },
            Test {
                coin: BtcCoin::Tbtc,
                threshold: 1,
                xpubs: &[
                    "xpub6EMfjyGVUvwhpc3WKN1zXhMFGKJGMaSBPqbja4tbGoYvRBSXeTBCaqrRDjcuGTcaY95JrrAnQvDG3pdQPdtnYUCugjeksHSbyZT7rq38VQF",
                    "xpub6ERxBysTYfQyY4USv6c6J1HNVv9hpZFN9LHVPu47Ac4rK8fLy6NnAeeAHyEsMvG4G66ay5aFZii2VM7wT3KxLKX8Q8keZPd67kRGmrD1WJj",
                ],
                expected_info: "1-of-2\nBTC Testnet multisig",
                our_xpub_index: 0,
                keypath: &[
                    48 + HARDENED,
                    1 + HARDENED,
                    0 + HARDENED,
                    2 + HARDENED,
                    1,
                    2,
                ],
                script_type: MultisigScriptType::P2wsh,
                expected_address: "tb1qw2scxk3zq0znr4ug9xkf3n7nfjsc8ldvemrm9dxjpl847zyu6afsfjjy28",
            },
            Test {
                coin: BtcCoin::Tbtc,
                threshold: 7,
                xpubs: &[
                    "xpub6Eu7xJRyXRCi4eLYhJPnfZVjgAQtM7qFaEZwUhvgxGf4enEZMxevGzWvZTawCj9USP2MFTEhKQAwnqHwoaPHetTLqGuvq5r5uaLKyGx5QDZ",
                    "xpub6EQcxF2jFkYGn89AwoQJEEJkYMbRjED9AZgt7bkxQA5BLhZEoaQpUHcADbB5GxcMrTdDSGmjP7M3u462Q9otyE2PPam66P5KFLWitPVfYz9",
                    "xpub6EP4EycVS5dq1PN7ZqsxBtptkYhfLvLGokZjnB3fvPshMiAohh6E5TaJjAafZWoPRjo6uiZxhtDXLgCuk81ooQgwrsnEdfSWSfa4VUtX8nu",
                    "xpub6Eszd4BGGmHShcGtys5gbvV2zrBtW1gaorKf9YuvV4L3bePw7XePyyb2DKswZ5AhFfkcQwjQsiJEUTKhfRstRdHZUjQnJ2RJoQqL8g7FS4b",
                    "xpub6Df3nbvH6P3FTvjgKaZcSuydyEofK545U4Bb15JY8R9MtFkKrhYrc3bpEF6fHtNM7xQ1qHwsVpS56TJWUjbKcmRwPkQr17ovV2RaVSJaBq3",
                    "xpub6FQQ62gUYzS9wnHWHMPLWrpVnzS8xAf8XvfW1xzXEXTkTCtBrfbeww2zNeCgm3PbueMoq8opQvQDzp5Yf9EtiqVd7d1ASDoWSC1m7g1KHza",
                    "xpub6EQNZUUAzJAoFAVVetYUrFVrf7mLyYsnHiQihkA3KPhoRHx7m6SgKBYV4z5Rd9CvUc11ACN8Ap5Wxigt6GYRPUqXGFfm3833ezJpjAmvJKt",
                    "xpub6EGZy7cizYn2zUf9NT4qJ3Kr1ZrxdzPRcv2CwAnB1BTGWw7n9ZgDYvwmzzJXM6V7AgZ6CL3DrARZk5DzM9o8tz2RVTeC7QoHh9SxbW3b7Pw",
                    "xpub6DaV7oCAkm4HJQMoProrrKYq1RvcgpStgYUCzLRaaeJSBSy9WBRFMNnQyAWJUYy9myUFRTvogq1C2f7x4A2yhtYgr7gL6eZXv2eJvzU12pe",
                    "xpub6FFVRbdHt5DgHqR69KuWXRVDp93e1xKxv8rRLwhhCGnWaoF1ecnfdxpg2Nf1pvJTgT1UYg28CVt7YbUXFJL86vi9FaPN9QGtWLeCmf9dA24",
                    "xpub6FNywxebMjvSSginZrk7DfNmAHvPJAy3j6pJ9FmUQCoh4FKPzNymdHnkA1z77Ke4GK7g5GkdrBhpyXfWTbZkH6Yo1t4v524wDwF8SAKny9J",
                    "xpub6F1V9y6gXejomurTy2hN1UDCJidYahVkqtQJSZLYmcPcPDWkxGgWTrrLnCrCkGESSUSq6GpVVQx9kejPV97BEa9F85utABNL9r6xyPZFiDm",
                    "xpub6ECHc4kmTC2tQg2ZoAoazwyag9C4V6yFsZEhjwMJixdVNsUibot6uEvsZY38ZLVqWCtyc9gbzFEwHQLHCT8EiDDKSNNsFAB8NQYRgkiAQwu",
                    "xpub6F7CaxXzBCtvXwpRi61KYyhBRkgT1856ujHV5AbJK6ySCUYoDruBH6Pnsi6eHkDiuKuAJ2tSc9x3emP7aax9Dc3u7nP7RCQXEjLKihQu6w1",
                    "xpub6EMfjyGVUvwhpc3WKN1zXhMFGKJGMaSBPqbja4tbGoYvRBSXeTBCaqrRDjcuGTcaY95JrrAnQvDG3pdQPdtnYUCugjeksHSbyZT7rq38VQF",
                ],
                expected_info: "7-of-15\nBTC Testnet multisig",
                our_xpub_index: 14,
                keypath: &[
                    48 + HARDENED,
                    1 + HARDENED,
                    0 + HARDENED,
                    2 + HARDENED,
                    1,
                    2,
                ],
                script_type: MultisigScriptType::P2wsh,
                expected_address: "tb1qndz49j0arp8g6jc8vcrgf9ugrsw96a0j5d7vqcun6jev6rlv47jsv99y5m",
            },
            // An arbitrary "non-standard" keypath
            Test {
                coin: BtcCoin::Btc,
                threshold: 1,
                xpubs: &[
                    "xpub6FEZ9Bv73h1vnE4TJG4QFj2RPXJhhsPbnXgFyH3ErLvpcZrDcynY65bhWga8PazWHLSLi23PoBhGcLcYW6JRiJ12zXZ9Aop4LbAqsS3gtcy",
                    "xpub68yJakxtRe3azab9rb8DJqxDeCG7oBY3zhsNnvZybjTE9qc9Hgw4bCqdLjVGykZrwD6CC6r6xHrnuep5Dmb9uq2R4emCm8YzBuddFyhgvAD",
                ],
                expected_info: "1-of-2\nBitcoin multisig",
                our_xpub_index: 1,
                keypath: &[
                    45 + HARDENED,
                    1,
                    2
                ],
                script_type: MultisigScriptType::P2wsh,
                expected_address: "bc1qtsvlhzltl05etjjeqh00urwttu6ep4xn3c0ccndz77unttut9h0qvrcs04",
            },
            /* P2WSH-P2SH */
            Test {
                coin: BtcCoin::Btc,
                threshold: 2,
                xpubs: &[
                    "xpub6FEZ9Bv73h1vnE4TJG4QFj2RPXJhhsPbnXgFyH3ErLvpcZrDcynY65bhWga8PazWHLSLi23PoBhGcLcYW6JRiJ12zXZ9Aop4LbAqsS3gtcy",
                    "xpub6EGAio99SxrurYgGH5BEzSiM4ZNedDX68RTGTSzGt5gk4STbs8B35ASC3RMdysGhJ7dJfffQcQEzFAkLxvMTyDsdrvMmsd45gr8pDmtTzEX",
                ],
                expected_info: "2-of-2\nBitcoin multisig",
                our_xpub_index: 1,
                keypath: &[
                    48 + HARDENED,
                    0 + HARDENED,
                    0 + HARDENED,
                    1 + HARDENED,
                    1,
                    0,
                ],
                script_type: MultisigScriptType::P2wshP2sh,
                expected_address: "3BKdK5c2kcFrNmmJbMAeWuveaoYDB4BYvu",
            },
            /* P2WSH-P2SH Nunchuk keypath */
            Test {
                coin: BtcCoin::Btc,
                threshold: 2,
                xpubs: &[
                    "xpub6FEZ9Bv73h1vnE4TJG4QFj2RPXJhhsPbnXgFyH3ErLvpcZrDcynY65bhWga8PazWHLSLi23PoBhGcLcYW6JRiJ12zXZ9Aop4LbAqsS3gtcy",
                    "xpub6C2Btqv4ZLgC3f2kjqEvsWUsJosEYVzrMTS8JHjZHrQpuVRyjtXcGfwR5dtueTQaTPAEyiiAknU6V5GUyR4ryT2y2tv3VRnCNf57GWqocgd",
                ],
                expected_info: "2-of-2\nBitcoin multisig",
                our_xpub_index: 1,
                keypath: &[
                    48 + HARDENED,
                    0 + HARDENED,
                    0 + HARDENED,
                    1,
                    0,
                ],
                script_type: MultisigScriptType::P2wshP2sh,
                expected_address: "341hw7cuzpf2AtSuXupX5Pu3tkkXv24bvo",
            },
        ];
        for test in tests.iter() {
            mock_memory();
            unsafe { UI_COUNTER = 0 };
            let name = "some name";
            let expected_info = test.expected_info;
            let expected_address = test.expected_address;
            mock(Data {
                ui_confirm_create: Some(Box::new(move |params| {
                    match unsafe {
                        UI_COUNTER += 1;
                        UI_COUNTER
                    } {
                        1 => {
                            assert_eq!(params.title, "Receive to");
                            assert_eq!(params.body, expected_info);
                            true
                        }
                        2 => {
                            assert_eq!(params.title, "Receive to");
                            assert_eq!(params.body, name);
                            true
                        }
                        3 => {
                            assert_eq!(params.title, "Receive to");
                            assert_eq!(params.body, expected_address);
                            true
                        }
                        _ => panic!("too many dialogs"),
                    }
                })),
                ..Default::default()
            });
            mock_unlocked_using_mnemonic(
                "sudden tenant fault inject concert weather maid people chunk youth stumble grit",
                "",
            );

            let multisig = Multisig {
                threshold: test.threshold,
                xpubs: test.xpubs.iter().map(|s| parse_xpub(s).unwrap()).collect(),
                our_xpub_index: test.our_xpub_index,
                script_type: test.script_type as _,
            };
            bitbox02::memory::multisig_set_by_hash(
                &multisig::get_hash(
                    test.coin,
                    &multisig,
                    multisig::SortXpubs::Yes,
                    &test.keypath[..test.keypath.len() - 2],
                )
                .unwrap(),
                name,
            )
            .unwrap();
            let req = pb::BtcPubRequest {
                coin: test.coin as _,
                keypath: test.keypath.to_vec(),
                display: true,
                output: Some(Output::ScriptConfig(BtcScriptConfig {
                    config: Some(Config::Multisig(multisig)),
                })),
            };
            assert_eq!(
                block_on(process_pub(&req)),
                Ok(Response::Pub(pb::PubResponse {
                    r#pub: test.expected_address.into(),
                })),
            );
            assert_eq!(unsafe { UI_COUNTER }, 3);
        }
    }

    #[test]
    fn test_address_policy() {
        mock_unlocked_using_mnemonic(
            "sudden tenant fault inject concert weather maid people chunk youth stumble grit",
            "",
        );

        const SOME_XPUB: &str = "tpubDFj9SBQssRHA5EB1ox58mcgF9sB61br9RGz6UrBukcNKmFe4fPgskZ4wigxQ1jSUzLdjnvvDHL8Z6L3ey5Ev5FNNqrDrePxwXsNHiLZhBTc";
        const KEYPATH_ACCOUNT_TESTNET: &[u32] =
            &[48 + HARDENED, 1 + HARDENED, 0 + HARDENED, 3 + HARDENED];
        const KEYPATH_ACCOUNT_MAINNET: &[u32] =
            &[48 + HARDENED, 0 + HARDENED, 0 + HARDENED, 3 + HARDENED];

        let our_key_testnet = pb::KeyOriginInfo {
            root_fingerprint: keystore::root_fingerprint().unwrap(),
            keypath: KEYPATH_ACCOUNT_TESTNET.to_vec(),
            xpub: Some(
                crate::keystore::get_xpub(KEYPATH_ACCOUNT_TESTNET)
                    .unwrap()
                    .into(),
            ),
        };
        let our_key_mainnet = pb::KeyOriginInfo {
            root_fingerprint: keystore::root_fingerprint().unwrap(),
            keypath: KEYPATH_ACCOUNT_MAINNET.to_vec(),
            xpub: Some(
                crate::keystore::get_xpub(KEYPATH_ACCOUNT_MAINNET)
                    .unwrap()
                    .into(),
            ),
        };
        let some_key = pb::KeyOriginInfo {
            root_fingerprint: vec![],
            keypath: vec![],
            xpub: Some(parse_xpub(SOME_XPUB).unwrap()),
        };

        struct Test<'a> {
            coin: BtcCoin,
            policy: &'a str,
            keys: &'a [pb::KeyOriginInfo],
            keypath: &'a [u32],
            expected_address: &'a str,
        }
        let tests = &[
            Test {
                coin: BtcCoin::Btc,
                policy: "wsh(multi(2,@0/**,@1/**))",
                keys: &[our_key_mainnet.clone(), some_key.clone()],
                keypath: &[
                    48 + HARDENED,
                    0 + HARDENED,
                    0 + HARDENED,
                    3 + HARDENED,
                    0,
                    0,
                ],
                expected_address: "bc1q9n0nxanmarawjpj2xz0echuhk4a2qga99xpn0nrpgfv2vv9279vsvrh6rj",
            },
            Test {
                coin: BtcCoin::Tbtc,
                policy: "wsh(multi(2,@0/**,@1/**))",
                keys: &[our_key_testnet.clone(), some_key.clone()],
                keypath: &[
                    48 + HARDENED,
                    1 + HARDENED,
                    0 + HARDENED,
                    3 + HARDENED,
                    0,
                    0,
                ],
                expected_address: "tb1qvq2793p7nyuxzqn5ts3kgqywxn9kj277skyvtz895gf7urfdxenqvq39sp",
            },
            Test {
                coin: BtcCoin::Tbtc,
                policy: "wsh(andor(pk(@0/**),older(12960),pk(@1/**)))",
                keys: &[our_key_testnet.clone(), some_key.clone()],
                keypath: &[
                    48 + HARDENED,
                    1 + HARDENED,
                    0 + HARDENED,
                    3 + HARDENED,
                    0,
                    0,
                ],
                expected_address: "tb1qeah5dqvya674w60ce6d3gk2xy7n8n0g4weztlywdd6zhu0csdv7s8yynr3",
            },
            Test {
                coin: BtcCoin::Tbtc,
                policy: "wsh(or_b(pk(@0/<10;11>/*),s:pk(@1/**)))",
                keys: &[our_key_testnet.clone(), some_key.clone()],
                keypath: &[
                    48 + HARDENED,
                    1 + HARDENED,
                    0 + HARDENED,
                    3 + HARDENED,
                    10,
                    0,
                ],
                expected_address: "tb1qeyetg3vgjvrgax0c5z70yuev3egdtxvv870jvzn235agtqe0l3gqytjrmc",
            },
            Test {
                coin: BtcCoin::Tbtc,
                policy: "wsh(or_b(pk(@0/<10;11>/*),s:pk(@1/**)))",
                keys: &[our_key_testnet.clone(), some_key.clone()],
                keypath: &[
                    48 + HARDENED,
                    1 + HARDENED,
                    0 + HARDENED,
                    3 + HARDENED,
                    11,
                    5,
                ],
                expected_address: "tb1qkfpeqx87pwjruet9c2xt88n6k47mz9q9m5jt77906780qrv4sl4sr5m72q",
            },
        ];
        for test in tests {
            let policy = pb::btc_script_config::Policy {
                policy: test.policy.into(),
                keys: test.keys.to_vec(),
            };

            // Register policy.
            mock_memory();
            let name = "some name";
            bitbox02::memory::multisig_set_by_hash(
                &policies::get_hash(test.coin, &policy).unwrap(),
                name,
            )
            .unwrap();

            let req = pb::BtcPubRequest {
                coin: test.coin as _,
                keypath: test.keypath.to_vec(),
                display: false,
                output: Some(Output::ScriptConfig(BtcScriptConfig {
                    config: Some(Config::Policy(policy)),
                })),
            };
            assert_eq!(
                block_on(process_pub(&req)),
                Ok(Response::Pub(pb::PubResponse {
                    r#pub: test.expected_address.into(),
                })),
            );
        }
    }
}
