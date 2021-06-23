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

use super::amount::Amount;
use super::pb;
use super::Error;

use bitbox02::keystore;

use crate::workflow::{confirm, transaction};
use bitbox02::app_eth::{params_get, sighash_eth, sighash_etc, Params, SighashParams};

use alloc::vec::Vec;
use core::convert::TryInto;
use pb::eth_response::Response;

use core::ops::{Add, Mul};
use num_bigint::BigUint;

// 1 ETH = 1e18 wei.
const WEI_DECIMALS: usize = 18;

/// Converts `recipient` to an array of 20 chars. If `recipient` is
/// not exactly 20 elements, `InvalidInput` is returned.
fn parse_recipient(recipient: &[u8]) -> Result<[u8; 20], Error> {
    recipient.try_into().or(Err(Error::InvalidInput))
}

/// Checks if the transaction is an ERC20 transaction.
/// An ERC20 transaction transacts 0 ETH, but contains an ERC20 transfer method call in the data.
/// The data field must look like:
/// `<0xa9059cbb><32 bytes recipient><32 bytes value>`
/// where recipient 20 bytes (zero padded to 32 bytes), and value is zero padded big endian number.
/// On success, the 20 byte recipient and transaction value are returned.
fn parse_erc20(request: &pb::EthSignRequest) -> Option<([u8; 20], BigUint)> {
    if !request.value.is_empty() || request.data.len() != 68 {
        return None;
    }
    let (method, recipient, value) = (
        &request.data[..4],
        &request.data[4..36],
        &request.data[36..68],
    );
    if method != [0xa9, 0x05, 0x9c, 0xbb] {
        return None;
    }
    // Recipient must be zero padded.
    if recipient[..12] != [0u8; 12] {
        return None;
    }
    // Transacted value can't be zero.
    if value == [0u8; 32] {
        return None;
    }
    Some((
        recipient[12..].try_into().unwrap(),
        BigUint::from_bytes_be(value),
    ))
}

// fee: gas limit * gas price:
fn parse_fee<'a>(request: &pb::EthSignRequest, params: &'a Params) -> Amount<'a> {
    let gas_price = BigUint::from_bytes_be(&request.gas_price);
    let gas_limit = BigUint::from_bytes_be(&request.gas_limit);
    Amount {
        unit: params.unit,
        decimals: WEI_DECIMALS,
        value: gas_price.mul(gas_limit),
    }
}

/// Verifies an ERC20 transfer.
///
/// If the ERC20 contract is known (stored in our list of supported ERC20 tokens), the token name,
/// amount, recipient, total and fee are shown for confirmation.
///
/// If the ERC20 token is unknown, only the recipient and fee can be shown. The token name and
/// amount are displayed as "unknown". The amount is not known because we don't know the number of
/// decimal places (specified in the ERC20 contract).
async fn verify_erc20_transaction(
    request: &pb::EthSignRequest,
    params: &Params,
    erc20_recipient: [u8; 20],
    erc20_value: BigUint,
) -> Result<(), Error> {
    let erc20_params = bitbox02::app_eth::erc20_params_get(
        request.coin as _,
        parse_recipient(&request.recipient)?,
    );
    let formatted_fee = parse_fee(request, params).format();
    let recipient_address = ethereum::address::from_pubkey_hash(&erc20_recipient);
    let (formatted_value, formatted_total) = match erc20_params {
        Some(erc20_params) => {
            let value = Amount {
                unit: erc20_params.unit,
                decimals: erc20_params.decimals as _,
                value: erc20_value,
            }
            .format();

            // ERC20 token: fee has a different unit (ETH), so the total is just the value again.
            (value.clone(), value.clone())
        }
        None => ("Unknown token".into(), "Unknown amount".into()),
    };
    transaction::verify_recipient(&recipient_address, &formatted_value).await?;
    transaction::verify_total_fee(&formatted_total, &formatted_fee).await?;
    Ok(())
}

/// Verifies a standard ETH transaction, meaning that the data field is empty or has unknown
/// contents.
///
/// If the data field is not empty, it will be shown for confirmation as a hex string. This is for
/// experts that know the expected encoding of a smart contract invocation.
///
/// The transacted value, recipient address, total and fee are confirmed.
async fn verify_standard_transaction(
    request: &pb::EthSignRequest,
    params: &Params,
) -> Result<(), Error> {
    if request.data.is_empty() && request.value.is_empty() {
        // Must transfer non-zero value, unless there is data (contract invocation).
        return Err(Error::InvalidInput);
    }

    let recipient = parse_recipient(&request.recipient)?;

    if !request.data.is_empty() {
        confirm::confirm(&confirm::Params {
            title: "Unknown\ncontract",
            body: "You will be shown\nthe raw\ntransaction data.",
            accept_is_nextarrow: true,
            ..Default::default()
        })
        .await?;
        confirm::confirm(&confirm::Params {
            title: "Unknown\ncontract",
            body: "Only proceed if you\nunderstand exactly\nwhat the data means.",
            accept_is_nextarrow: true,
            ..Default::default()
        })
        .await?;

        confirm::confirm(&confirm::Params {
            title: "Transaction\ndata",
            body: &hex::encode(&request.data),
            scrollable: true,
            display_size: request.data.len(),
            accept_is_nextarrow: true,
            ..Default::default()
        })
        .await?;
    }

    let address = ethereum::address::from_pubkey_hash(&recipient);
    let amount = Amount {
        unit: params.unit,
        decimals: WEI_DECIMALS,
        value: BigUint::from_bytes_be(&request.value),
    };
    transaction::verify_recipient(&address, &amount.format()).await?;

    let fee = parse_fee(request, params);
    let total = Amount {
        unit: params.unit,
        decimals: WEI_DECIMALS,
        value: amount.value.add(&fee.value),
    };
    transaction::verify_total_fee(&total.format(), &fee.format()).await?;
    Ok(())
}

/// Verify and sign an Ethereum transaction.
pub async fn process(request: &pb::EthSignRequest) -> Result<Response, Error> {
    let params = params_get(request.coin as _).ok_or(Error::InvalidInput)?;

    if !ethereum::keypath::is_valid_keypath_address(&request.keypath, params.bip44_coin) {
        confirm::confirm(&confirm::Params {
            title: "Unusual\nbip32 path",
            body: "Only proceed if you\nunderstand exactly\nwhat the path means.",
            accept_is_nextarrow: true,
            ..Default::default()
        }).await?;

        confirm::confirm(&confirm::Params {
            title: "Unusual\nbip32 path",
            body: &util::bip32::to_string(&request.keypath),
            accept_is_nextarrow: true,
            ..Default::default()
        }).await?;
    }

    // Size limits.
    if request.nonce.len() > 16
        || request.gas_price.len() > 16
        || request.gas_limit.len() > 16
        || request.value.len() > 32
        || request.data.len() > 1024
    {
        return Err(Error::InvalidInput);
    }

    // No zero prefix in the big endian numbers.
    if let [0, ..] = &request.nonce[..] {
        return Err(Error::InvalidInput);
    }
    if let [0, ..] = &request.gas_price[..] {
        return Err(Error::InvalidInput);
    }
    if let [0, ..] = &request.gas_limit[..] {
        return Err(Error::InvalidInput);
    }
    if let [0, ..] = &request.value[..] {
        return Err(Error::InvalidInput);
    }

    let recipient = parse_recipient(&request.recipient)?;
    if recipient == [0; 20] {
        // Reserved for contract creation.
        return Err(Error::InvalidInput);
    }

    if let Some((erc20_recipient, erc20_value)) = parse_erc20(request) {
        verify_erc20_transaction(request, &params, erc20_recipient, erc20_value).await?;
    } else {
        verify_standard_transaction(request, &params).await?;
    }

    let hash = if false {
        // Call sighash_etc
        todo!()
    } else {
        sighash_eth(SighashParams {
            nonce: &request.nonce,
            gas_price: &request.gas_price,
            gas_limit: &request.gas_limit,
            recipient: &recipient,
            value: &request.value,
            data: &request.data,
            chain_id: params.chain_id,
        })
        .or(Err(Error::InvalidInput))?
    };

    let host_nonce = match request.host_nonce_commitment {
        // Engage in the anti-klepto protocol if the host sends a host nonce commitment.
        Some(pb::AntiKleptoHostNonceCommitment { ref commitment }) => {
            let signer_commitment = keystore::secp256k1_nonce_commit(
                &request.keypath,
                &hash,
                commitment
                    .as_slice()
                    .try_into()
                    .or(Err(Error::InvalidInput))?,
            )?;

            // Send signer commitment to host and wait for the host nonce from the host.
            super::antiklepto_get_host_nonce(signer_commitment).await?
        }

        // Return signature directly without the anti-klepto protocol, for backwards compatibility.
        None => [0; 32],
    };
    let sign_result = keystore::secp256k1_sign(&request.keypath, &hash, &host_nonce)?;

    let mut signature: Vec<u8> = sign_result.signature.to_vec();
    signature.push(sign_result.recid);

    Ok(Response::Sign(pb::EthSignResponse { signature }))
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
    pub fn test_parse_recipient() {
        assert_eq!(
            parse_recipient(b"01234567890123456789"),
            Ok(*b"01234567890123456789"),
        );

        assert_eq!(
            parse_recipient(b"0123456789012345678"),
            Err(Error::InvalidInput),
        );
        assert_eq!(
            parse_recipient(b"012345678901234567890"),
            Err(Error::InvalidInput),
        );
    }

    #[test]
    pub fn test_parse_erc20() {
        let valid_data =
            b"\xa9\x05\x9c\xbb\0\0\0\0\0\0\0\0\0\0\0\0abcdefghijklmnopqrst\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x55\0\0\0\xff";
        assert_eq!(
            parse_erc20(&pb::EthSignRequest {
                data: valid_data.to_vec(),
                ..Default::default()
            }),
            Some((*b"abcdefghijklmnopqrst", 365072220415u64.into()))
        );

        // ETH value must be 0 when transacting ERC20.
        assert!(parse_erc20(&pb::EthSignRequest {
            value: vec![0],
            data: valid_data.to_vec(),
            ..Default::default()
        })
        .is_none());

        // Invalid method (first byte)
        let invalid_data = b"\xa8\x05\x9c\xbb\0\0\0\0\0\0\0\0\0\0\0\0abcdefghijklmnopqrst\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xff";
        assert!(parse_erc20(&pb::EthSignRequest {
            data: invalid_data.to_vec(),
            ..Default::default()
        })
        .is_none());

        // Recipient too long (not zero padded)
        let invalid_data = b"\xa9\x05\x9c\xbb\0\0\0\0\0\0\0\0\0\0\0babcdefghijklmnopqrst\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xff";
        assert!(parse_erc20(&pb::EthSignRequest {
            data: invalid_data.to_vec(),
            ..Default::default()
        })
        .is_none());

        // Value can't be zero
        let invalid_data = b"\xa9\x05\x9c\xbb\0\0\0\0\0\0\0\0\0\0\0\0abcdefghijklmnopqrst\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x00";
        assert!(parse_erc20(&pb::EthSignRequest {
            data: invalid_data.to_vec(),
            ..Default::default()
        })
        .is_none());
    }

    /// Standard ETH transaction with no data field.
    #[test]
    pub fn test_process_standard_transaction() {
        let _guard = MUTEX.lock().unwrap();

        const KEYPATH: &[u32] = &[44 + HARDENED, 60 + HARDENED, 0 + HARDENED, 0, 0];

        mock(Data {
            ui_transaction_address_create: Some(Box::new(|amount, address| {
                assert_eq!(amount, "0.530564 ETH");
                assert_eq!(address, "0x04F264Cf34440313B4A0192A352814FBe927b885");
                true
            })),
            ui_transaction_fee_create: Some(Box::new(|total, fee| {
                assert_eq!(total, "0.53069 ETH");
                assert_eq!(fee, "0.000126 ETH");
                true
            })),
            ..Default::default()
        });
        mock_unlocked();
        assert_eq!(
            block_on(process(&pb::EthSignRequest {
                coin: pb::EthCoin::Eth as _,
                keypath: KEYPATH.to_vec(),
                nonce: b"\x1f\xdc".to_vec(),
                gas_price: b"\x01\x65\xa0\xbc\x00".to_vec(),
                gas_limit: b"\x52\x08".to_vec(),
                recipient: b"\x04\xf2\x64\xcf\x34\x44\x03\x13\xb4\xa0\x19\x2a\x35\x28\x14\xfb\xe9\x27\xb8\x85".to_vec(),
                value: b"\x07\x5c\xf1\x25\x9e\x9c\x40\x00".to_vec(),
                data: b"".to_vec(),
                host_nonce_commitment: None,
            })),
            Ok(Response::Sign(pb::EthSignResponse {
                signature: b"\xc3\xae\x24\xc1\x67\xe2\x16\xcf\xb7\x5c\x72\xb5\xe0\x3e\xf9\x7a\xcc\x2b\x60\x7f\x3a\xcf\x63\x86\x5f\x80\x96\x0f\x76\xf6\x56\x47\x0f\x8e\x23\xf1\xd2\x78\x8f\xb0\x07\x0e\x28\xc2\xa5\xc8\xaa\xf1\x5b\x5d\xbf\x30\xb4\x09\x07\xff\x6c\x50\x68\xfd\xcb\xc1\x1a\x2d\x00"
                    .to_vec()
            }))
        );
    }

    /// Standard ETH transaction with an unknown data field.
    #[test]
    pub fn test_process_standard_transaction_with_data() {
        let _guard = MUTEX.lock().unwrap();

        const KEYPATH: &[u32] = &[44 + HARDENED, 60 + HARDENED, 0 + HARDENED, 0, 0];
        static mut CONFIRM_COUNTER: u32 = 0;
        mock(Data {
            ui_confirm_create: Some(Box::new(|params| {
                match unsafe { CONFIRM_COUNTER } {
                    0 | 1 => assert_eq!(params.title, "Unknown\ncontract"),
                    2 => {
                        assert_eq!(params.title, "Transaction\ndata");
                        assert_eq!(params.body, "666f6f20626172"); // "foo bar" in hex.
                        assert!(params.scrollable);
                        assert_eq!(params.display_size, 7); // length of "foo bar"
                        assert!(params.accept_is_nextarrow);
                    }
                    _ => panic!("too many user confirmations"),
                }
                unsafe { CONFIRM_COUNTER += 1 }
                true
            })),
            ui_transaction_address_create: Some(Box::new(|amount, address| {
                assert_eq!(amount, "0.530564 ETH");
                assert_eq!(address, "0x04F264Cf34440313B4A0192A352814FBe927b885");
                true
            })),
            ui_transaction_fee_create: Some(Box::new(|total, fee| {
                assert_eq!(total, "0.53069 ETH");
                assert_eq!(fee, "0.000126 ETH");
                true
            })),
            ..Default::default()
        });
        mock_unlocked();
        assert_eq!(
            block_on(process(&pb::EthSignRequest {
                coin: pb::EthCoin::Eth as _,
                keypath: KEYPATH.to_vec(),
                nonce: b"\x1f\xdc".to_vec(),
                gas_price: b"\x01\x65\xa0\xbc\x00".to_vec(),
                gas_limit: b"\x52\x08".to_vec(),
                recipient: b"\x04\xf2\x64\xcf\x34\x44\x03\x13\xb4\xa0\x19\x2a\x35\x28\x14\xfb\xe9\x27\xb8\x85".to_vec(),
                value: b"\x07\x5c\xf1\x25\x9e\x9c\x40\x00".to_vec(),
                data: b"foo bar".to_vec(),
                host_nonce_commitment: None,
            })),
            Ok(Response::Sign(pb::EthSignResponse {
                signature: b"\x7d\x3f\x37\x13\xe3\xcf\x10\x82\x79\x1d\x5c\x0f\xc6\x8e\xc2\x9e\xaf\xf5\xe1\xee\x84\x67\xa8\xec\x54\x7d\xc7\x96\xe8\x5a\x79\x04\x2b\x7c\x01\x69\x2f\xb7\x2f\x55\x76\xab\x50\xdc\xaa\x62\x1a\xd1\xee\xab\xd9\x97\x59\x73\xb8\x62\x56\xf4\x0c\x6f\x85\x50\xef\x44\x00"
                    .to_vec()
            }))
        );
    }

    /// ERC20 transaction: recipient is an ERC20 contract address, and
    /// the data field contains an ERC20 transfer method invocation.
    #[test]
    pub fn test_process_standard_erc20_transaction() {
        let _guard = MUTEX.lock().unwrap();

        const KEYPATH: &[u32] = &[44 + HARDENED, 60 + HARDENED, 0 + HARDENED, 0, 0];

        mock(Data {
            ui_transaction_address_create: Some(Box::new(|amount, address| {
                assert_eq!(amount, "57 USDT");
                assert_eq!(address, "0xE6CE0a092A99700CD4ccCcBb1fEDc39Cf53E6330");
                true
            })),
            ui_transaction_fee_create: Some(Box::new(|total, fee| {
                assert_eq!(total, "57 USDT");
                assert_eq!(fee, "0.0012658164 ETH");
                true
            })),
            ..Default::default()
        });
        mock_unlocked();
        assert_eq!(
            block_on(process(&pb::EthSignRequest {
                coin: pb::EthCoin::Eth as _,
                keypath: KEYPATH.to_vec(),
                nonce: b"\x23\x67".to_vec(),
                gas_price: b"\x02\x7a\xca\x1a\x80".to_vec(),
                gas_limit: b"\x01\xd0\x48".to_vec(),
                recipient: b"\xda\xc1\x7f\x95\x8d\x2e\xe5\x23\xa2\x20\x62\x06\x99\x45\x97\xc1\x3d\x83\x1e\xc7".to_vec(),
                value: b"".to_vec(),
                data: b"\xa9\x05\x9c\xbb\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xe6\xce\x0a\x09\x2a\x99\x70\x0c\xd4\xcc\xcc\xbb\x1f\xed\xc3\x9c\xf5\x3e\x63\x30\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x65\xc0\x40".to_vec(),
                host_nonce_commitment: None,
            })),
            Ok(Response::Sign(pb::EthSignResponse {
                signature: b"\x67\x4e\x9a\x01\x70\xee\xe0\xca\x8c\x40\x6e\xc9\xa7\xdf\x2e\x3a\x6b\xdd\x17\x9c\xf6\x93\x85\x80\x0e\x1f\xd3\x78\xe7\xcf\xb1\x9c\x4d\x55\x16\x2c\x54\x7b\x04\xd1\x81\x8e\x43\x90\x16\x91\xae\xc9\x88\xef\x75\xcd\x67\xd9\xbb\x30\x1d\x14\x90\x2f\xd6\xe6\x92\x92\x01"
                    .to_vec()
            }))
        );
    }

    /// An ERC20 transaction which is not in our list of supported ERC20 tokens.
    #[test]
    pub fn test_process_standard_unknown_erc20_transaction() {
        let _guard = MUTEX.lock().unwrap();

        const KEYPATH: &[u32] = &[44 + HARDENED, 60 + HARDENED, 0 + HARDENED, 0, 0];

        mock(Data {
            ui_transaction_address_create: Some(Box::new(|amount, address| {
                assert_eq!(amount, "Unknown token");
                assert_eq!(address, "0x857B3D969eAcB775a9f79cabc62Ec4bB1D1cd60e");
                true
            })),
            ui_transaction_fee_create: Some(Box::new(|total, fee| {
                assert_eq!(total, "Unknown amount");
                assert_eq!(fee, "0.000067973 ETH");
                true
            })),
            ..Default::default()
        });
        mock_unlocked();
        assert_eq!(
            block_on(process(&pb::EthSignRequest {
                coin: pb::EthCoin::Eth as _,
                keypath: KEYPATH.to_vec(),
                nonce: b"\xb9".to_vec(),
                gas_price: b"\x3b\x9a\xca\x00".to_vec(),
                gas_limit: b"\x01\x09\x85".to_vec(),
                recipient: b"\x9c\x23\xd6\x7a\xea\x7b\x95\xd8\x09\x42\xe3\x83\x6b\xcd\xf7\xe7\x08\xa7\x47\xc1".to_vec(),
                value: b"".to_vec(),
                data: b"\xa9\x05\x9c\xbb\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x85\x7b\x3d\x96\x9e\xac\xb7\x75\xa9\xf7\x9c\xab\xc6\x2e\xc4\xbb\x1d\x1c\xd6\x0e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x98\xa6\x3c\xbe\xb8\x59\xd0\x27\xb0".to_vec(),
                host_nonce_commitment: None,
            })),
            Ok(Response::Sign(pb::EthSignResponse {
                signature: b"\xec\x6e\x53\x0c\x8e\xe2\x54\x34\xfc\x44\x0e\x9a\xc0\xf8\x88\xe9\xc6\x3c\xf0\x7e\xbc\xf1\xc2\xf8\xa8\x3e\x2e\x8c\x39\x83\x2c\x55\x15\x12\x71\x6f\x6e\x1a\x8b\x66\xce\x38\x11\xa7\x26\xbc\xb2\x44\x66\x4e\xf2\x6f\x98\xee\x35\xc0\xc9\xdb\x4c\xaa\xb0\x73\x98\x56\x00"
                    .to_vec()
            }))
        );
    }

    #[test]
    pub fn test_process_unhappy() {
        let _guard = MUTEX.lock().unwrap();

        let valid_request = pb::EthSignRequest {
            coin: pb::EthCoin::Eth as _,
            keypath: vec![44 + HARDENED, 60 + HARDENED, 0 + HARDENED, 0, 0],
            nonce: b"\x1f\xdc".to_vec(),
            gas_price: b"\x01\x65\xa0\xbc\x00".to_vec(),
            gas_limit: b"\x52\x08".to_vec(),
            recipient:
                b"\x04\xf2\x64\xcf\x34\x44\x03\x13\xb4\xa0\x19\x2a\x35\x28\x14\xfb\xe9\x27\xb8\x85"
                    .to_vec(),
            value: b"\x07\x5c\xf1\x25\x9e\x9c\x40\x00".to_vec(),
            data: b"".to_vec(),
            host_nonce_commitment: None,
        };

        {
            // invalid coin
            let mut invalid_request = valid_request.clone();
            invalid_request.coin = 100;
            assert_eq!(
                block_on(process(&invalid_request)),
                Err(Error::InvalidInput)
            );
        }

        {
            // invalid keypath (wrong coin part).
            let mut invalid_request = valid_request.clone();
            invalid_request.keypath = vec![44 + HARDENED, 0 + HARDENED, 0 + HARDENED, 0, 0];
            assert_eq!(
                block_on(process(&invalid_request)),
                Err(Error::InvalidInput)
            );
        }

        {
            // invalid keypath (account too high).
            let mut invalid_request = valid_request.clone();
            invalid_request.keypath = vec![44 + HARDENED, 60 + HARDENED, 0 + HARDENED, 0, 100];
            assert_eq!(
                block_on(process(&invalid_request)),
                Err(Error::InvalidInput)
            );
        }

        {
            // data too long
            let mut invalid_request = valid_request.clone();
            invalid_request.data = vec![0; 1025];
            assert_eq!(
                block_on(process(&invalid_request)),
                Err(Error::InvalidInput)
            );
        }

        {
            // recipient too long
            let mut invalid_request = valid_request.clone();
            invalid_request.recipient = vec![b'a'; 21];
            assert_eq!(
                block_on(process(&invalid_request)),
                Err(Error::InvalidInput)
            );
        }

        {
            // recipient has the right size, but is all zeroes
            let mut invalid_request = valid_request.clone();
            invalid_request.recipient = vec![0; 20];
            assert_eq!(
                block_on(process(&invalid_request)),
                Err(Error::InvalidInput)
            );
        }

        {
            // User rejects recipient/value.
            mock(Data {
                ui_transaction_address_create: Some(Box::new(|amount, address| {
                    assert_eq!(amount, "0.530564 ETH");
                    assert_eq!(address, "0x04F264Cf34440313B4A0192A352814FBe927b885");
                    false
                })),
                ..Default::default()
            });
            assert_eq!(block_on(process(&valid_request)), Err(Error::UserAbort));
        }
        {
            // User rejects total/fee.
            mock(Data {
                ui_transaction_address_create: Some(Box::new(|amount, address| {
                    assert_eq!(amount, "0.530564 ETH");
                    assert_eq!(address, "0x04F264Cf34440313B4A0192A352814FBe927b885");
                    true
                })),
                ui_transaction_fee_create: Some(Box::new(|total, fee| {
                    assert_eq!(total, "0.53069 ETH");
                    assert_eq!(fee, "0.000126 ETH");
                    false
                })),
                ..Default::default()
            });
            assert_eq!(block_on(process(&valid_request)), Err(Error::UserAbort));
        }
        {
            // Keystore locked.
            mock(Data {
                ui_transaction_address_create: Some(Box::new(|_, _| true)),
                ui_transaction_fee_create: Some(Box::new(|_, _| true)),
                ..Default::default()
            });
            assert_eq!(block_on(process(&valid_request)), Err(Error::Generic));
        }
    }
}
