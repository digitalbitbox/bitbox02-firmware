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

use super::amount::{calculate_percentage, Amount};
use super::params::Params;
use super::pb;
use super::Error;

use bitbox02::keystore;

use crate::workflow::{confirm, status, transaction};

use alloc::string::String;
use alloc::vec::Vec;
use core::convert::TryFrom;
use core::convert::TryInto;
use pb::eth_response::Response;

use core::ops::{Add, Mul};
use num_bigint::BigUint;

// 1 ETH = 1e18 wei.
const WEI_DECIMALS: usize = 18;

pub enum Transaction<'a> {
    Legacy(&'a pb::EthSignRequest),
    Eip1559(&'a pb::EthSignEip1559Request),
}

impl<'a> Transaction<'a> {
    fn nonce(&self) -> &[u8] {
        match self {
            Transaction::Legacy(legacy) => &legacy.nonce,
            Transaction::Eip1559(eip1559) => &eip1559.nonce,
        }
    }
    fn gas_limit(&self) -> &[u8] {
        match self {
            Transaction::Legacy(legacy) => &legacy.gas_limit,
            Transaction::Eip1559(eip1559) => &eip1559.gas_limit,
        }
    }
    fn recipient(&self) -> &[u8] {
        match self {
            Transaction::Legacy(legacy) => &legacy.recipient,
            Transaction::Eip1559(eip1559) => &eip1559.recipient,
        }
    }
    fn value(&self) -> &[u8] {
        match self {
            Transaction::Legacy(legacy) => &legacy.value,
            Transaction::Eip1559(eip1559) => &eip1559.value,
        }
    }
    fn data(&self) -> &[u8] {
        match self {
            Transaction::Legacy(legacy) => &legacy.data,
            Transaction::Eip1559(eip1559) => &eip1559.data,
        }
    }
    fn chain_id(&self) -> u64 {
        match self {
            Transaction::Legacy(legacy) => legacy.chain_id,
            Transaction::Eip1559(eip1559) => eip1559.chain_id,
        }
    }
    fn keypath(&self) -> &[u32] {
        match self {
            Transaction::Legacy(legacy) => &legacy.keypath,
            Transaction::Eip1559(eip1559) => &eip1559.keypath,
        }
    }
    fn host_nonce_commitment(&self) -> Option<&pb::AntiKleptoHostNonceCommitment> {
        match self {
            Transaction::Legacy(legacy) => legacy.host_nonce_commitment.as_ref(),
            Transaction::Eip1559(eip1559) => eip1559.host_nonce_commitment.as_ref(),
        }
    }
    fn coin(&self) -> Result<Option<pb::EthCoin>, Error> {
        match self {
            Transaction::Legacy(legacy) => Ok(Some(pb::EthCoin::try_from(legacy.coin)?)),
            Transaction::Eip1559(_) => Ok(None),
        }
    }
    fn address(&self) -> String {
        match self {
            Transaction::Legacy(legacy) => legacy.address.clone(),
            Transaction::Eip1559(eip1559) => eip1559.address.clone(),
        }
    }
}

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
fn parse_erc20(request: &Transaction<'_>) -> Option<([u8; 20], BigUint)> {
    if !request.value().is_empty() || request.data().len() != 68 {
        return None;
    }
    let (method, recipient, value) = (
        &request.data()[..4],
        &request.data()[4..36],
        &request.data()[36..68],
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

// For legacy transactions: `fee = gas limit * gas price`
// For 1559 transactions: `fee = gas limit * max fee per gas` where max fee per gas is composed of the base fee + priority fee
// In both instances we show the user the max possible fee, but the actual fee paid at execution might be lower
// That is because:
// 1) actual gas used will often be lower than gas limit (in the case of contract interactions, not simple ETH transfers)
// 2) in the case of 1559 base fee at execution time might also be lower so that `base fee + priority fee < max fee per gas`
fn parse_fee<'a>(request: &Transaction<'_>, params: &'a Params) -> Amount<'a> {
    let gas_limit = BigUint::from_bytes_be(request.gas_limit());
    match request {
        Transaction::Legacy(legacy) => {
            let gas_price = BigUint::from_bytes_be(&legacy.gas_price);
            Amount {
                unit: params.unit,
                decimals: WEI_DECIMALS,
                value: gas_price.mul(gas_limit),
            }
        }
        Transaction::Eip1559(eip1559) => {
            let max_fee_per_gas = BigUint::from_bytes_be(&eip1559.max_fee_per_gas);
            Amount {
                unit: params.unit,
                decimals: WEI_DECIMALS,
                value: max_fee_per_gas.mul(gas_limit),
            }
        }
    }
}

fn hash_legacy(chain_id: u64, request: &pb::EthSignRequest) -> Result<[u8; 32], Error> {
    let hash = super::sighash::compute_legacy(&super::sighash::ParamsLegacy {
        nonce: &request.nonce,
        gas_price: &request.gas_price,
        gas_limit: &request.gas_limit,
        recipient: &request.recipient,
        value: &request.value,
        data: &request.data,
        chain_id,
    })
    .map_err(|_| Error::InvalidInput)?;
    Ok(hash)
}

fn hash_eip1559(request: &pb::EthSignEip1559Request) -> Result<[u8; 32], Error> {
    let hash = super::sighash::compute_eip1559(&super::sighash::ParamsEIP1559 {
        chain_id: request.chain_id,
        nonce: &request.nonce,
        max_priority_fee_per_gas: &request.max_priority_fee_per_gas,
        max_fee_per_gas: &request.max_fee_per_gas,
        gas_limit: &request.gas_limit,
        recipient: &request.recipient,
        value: &request.value,
        data: &request.data,
    })
    .map_err(|_| Error::InvalidInput)?;
    Ok(hash)
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
    request: &Transaction<'_>,
    params: &Params,
    erc20_recipient: [u8; 20],
    erc20_value: BigUint,
) -> Result<(), Error> {
    let erc20_params =
        bitbox02::app_eth::erc20_params_get(params.chain_id, parse_recipient(request.recipient())?);
    let formatted_fee = parse_fee(request, params).format();
    let recipient_address_verify = super::address::from_pubkey_hash(&erc20_recipient);
    let recipient_address = format!("0x{}", hex::encode(&erc20_recipient));
    if recipient_address.to_lowercase() != recipient_address_verify.to_lowercase() {
        return Err(Error::InvalidInput);
    }

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
    transaction::verify_total_fee(&formatted_total, &formatted_fee, None).await?;
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
    request: &Transaction<'_>,
    params: &Params,
) -> Result<(), Error> {
    let recipient = parse_recipient(request.recipient())?;

    if !request.data().is_empty() {
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
            body: &hex::encode(request.data()),
            scrollable: true,
            display_size: request.data().len(),
            accept_is_nextarrow: true,
            ..Default::default()
        })
        .await?;
    }

    let address_verify = super::address::from_pubkey_hash(&recipient);
    let address = format!("0x{}", request.address());
    if address.to_lowercase() != address_verify.to_lowercase() {
        return Err(Error::InvalidInput);
    }
    let amount = Amount {
        unit: params.unit,
        decimals: WEI_DECIMALS,
        value: BigUint::from_bytes_be(request.value()),
    };
    transaction::verify_recipient(&address, &amount.format()).await?;

    let fee = parse_fee(request, params);
    let total = Amount {
        unit: params.unit,
        decimals: WEI_DECIMALS,
        value: (&amount.value).add(&fee.value),
    };
    let percentage = calculate_percentage(&fee.value, &amount.value);
    transaction::verify_total_fee(&total.format(), &fee.format(), percentage).await?;
    Ok(())
}

/// Verify and sign an Ethereum transaction.
pub async fn process(request: &Transaction<'_>) -> Result<Response, Error> {
    let params = super::params::get_and_warn_unknown(request.coin()?, request.chain_id()).await?;

    if !super::keypath::is_valid_keypath_address(request.keypath()) {
        return Err(Error::InvalidInput);
    }
    super::keypath::warn_unusual_keypath(&params, params.name, request.keypath()).await?;

    // Size limits.
    if request.nonce().len() > 16
        || request.gas_limit().len() > 16
        || request.value().len() > 32
        || request.data().len() > 6144
    {
        return Err(Error::InvalidInput);
    }

    // No zero prefix in the big endian numbers.
    if let [0, ..] = request.nonce()[..] {
        return Err(Error::InvalidInput);
    }
    if let [0, ..] = request.gas_limit()[..] {
        return Err(Error::InvalidInput);
    }
    if let [0, ..] = request.value()[..] {
        return Err(Error::InvalidInput);
    }

    // size and zero prefix checks for legacy and eip1559 transactions
    match request {
        Transaction::Legacy(legacy) => {
            if let [0, ..] = &legacy.gas_price[..] {
                return Err(Error::InvalidInput);
            }
            if legacy.gas_price.len() > 16 {
                return Err(Error::InvalidInput);
            }
        }
        Transaction::Eip1559(eip1559) => {
            if let [0, ..] = &eip1559.max_priority_fee_per_gas[..] {
                return Err(Error::InvalidInput);
            }
            if let [0, ..] = &eip1559.gas_limit[..] {
                return Err(Error::InvalidInput);
            }
            if eip1559.max_priority_fee_per_gas.len() > 16 || eip1559.max_fee_per_gas.len() > 16 {
                return Err(Error::InvalidInput);
            }
        }
    }

    let recipient = parse_recipient(request.recipient())?;
    if recipient == [0; 20] {
        // Reserved for contract creation.
        return Err(Error::InvalidInput);
    }

    let verification_result = if let Some((erc20_recipient, erc20_value)) = parse_erc20(request) {
        verify_erc20_transaction(request, &params, erc20_recipient, erc20_value).await
    } else {
        verify_standard_transaction(request, &params).await
    };
    match verification_result {
        Ok(()) => status::status("Transaction\nconfirmed", true).await,
        Err(err) => {
            if err == Error::UserAbort {
                status::status("Transaction\ncanceled", false).await;
            }
            return Err(err);
        }
    }

    let hash: [u8; 32] = match request {
        Transaction::Legacy(legacy) => hash_legacy(params.chain_id, legacy)?,
        Transaction::Eip1559(eip1559) => hash_eip1559(eip1559)?,
    };

    let host_nonce = match request.host_nonce_commitment() {
        // Engage in the anti-klepto protocol if the host sends a host nonce commitment.
        Some(pb::AntiKleptoHostNonceCommitment { ref commitment }) => {
            let signer_commitment = keystore::secp256k1_nonce_commit(
                request.keypath(),
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
    let sign_result = keystore::secp256k1_sign(request.keypath(), &hash, &host_nonce)?;

    let mut signature: Vec<u8> = sign_result.signature.to_vec();
    signature.push(sign_result.recid);

    Ok(Response::Sign(pb::EthSignResponse { signature }))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::bb02_async::block_on;
    use alloc::boxed::Box;
    use bitbox02::testing::{mock, mock_unlocked, Data};
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
            parse_erc20(&Transaction::Legacy(&pb::EthSignRequest {
                data: valid_data.to_vec(),
                ..Default::default()
            })),
            Some((*b"abcdefghijklmnopqrst", 365072220415u64.into()))
        );

        // ETH value must be 0 when transacting ERC20.
        assert!(parse_erc20(&Transaction::Legacy(&pb::EthSignRequest {
            value: vec![0],
            data: valid_data.to_vec(),
            ..Default::default()
        }))
        .is_none());

        // Invalid method (first byte)
        let invalid_data = b"\xa8\x05\x9c\xbb\0\0\0\0\0\0\0\0\0\0\0\0abcdefghijklmnopqrst\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xff";
        assert!(parse_erc20(&Transaction::Legacy(&pb::EthSignRequest {
            data: invalid_data.to_vec(),
            ..Default::default()
        }))
        .is_none());

        // Recipient too long (not zero padded)
        let invalid_data = b"\xa9\x05\x9c\xbb\0\0\0\0\0\0\0\0\0\0\0babcdefghijklmnopqrst\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xff";
        assert!(parse_erc20(&Transaction::Legacy(&pb::EthSignRequest {
            data: invalid_data.to_vec(),
            ..Default::default()
        }))
        .is_none());

        // Value can't be zero
        let invalid_data = b"\xa9\x05\x9c\xbb\0\0\0\0\0\0\0\0\0\0\0\0abcdefghijklmnopqrst\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x00";
        assert!(parse_erc20(&Transaction::Legacy(&pb::EthSignRequest {
            data: invalid_data.to_vec(),
            ..Default::default()
        }))
        .is_none());
    }

    /// Standard ETH transaction with no data field.
    #[test]
    pub fn test_process_standard_transaction() {
        const KEYPATH: &[u32] = &[44 + HARDENED, 60 + HARDENED, 0 + HARDENED, 0, 0];

        mock(Data {
            ui_transaction_address_create: Some(Box::new(|amount, address| {
                assert_eq!(amount, "0.530564 ETH");
                assert_eq!(address, "0x04F264Cf34440313B4A0192A352814FBe927b885");
                true
            })),
            ui_transaction_fee_create: Some(Box::new(|total, fee, longtouch| {
                assert_eq!(total, "0.53069 ETH");
                assert_eq!(fee, "0.000126 ETH");
                assert!(longtouch);
                true
            })),
            ..Default::default()
        });
        mock_unlocked();
        assert_eq!(
            block_on(process(&Transaction::Legacy(&pb::EthSignRequest {
                coin: pb::EthCoin::Eth as _,
                keypath: KEYPATH.to_vec(),
                nonce: b"\x1f\xdc".to_vec(),
                gas_price: b"\x01\x65\xa0\xbc\x00".to_vec(),
                gas_limit: b"\x52\x08".to_vec(),
                recipient: b"\x04\xf2\x64\xcf\x34\x44\x03\x13\xb4\xa0\x19\x2a\x35\x28\x14\xfb\xe9\x27\xb8\x85".to_vec(),
                value: b"\x07\x5c\xf1\x25\x9e\x9c\x40\x00".to_vec(),
                data: b"".to_vec(),
                host_nonce_commitment: None,
                chain_id: 0,
                address: String::from("04F264Cf34440313B4A0192A352814FBe927b885")
            }))),
            Ok(Response::Sign(pb::EthSignResponse {
                signature: b"\xc3\xae\x24\xc1\x67\xe2\x16\xcf\xb7\x5c\x72\xb5\xe0\x3e\xf9\x7a\xcc\x2b\x60\x7f\x3a\xcf\x63\x86\x5f\x80\x96\x0f\x76\xf6\x56\x47\x0f\x8e\x23\xf1\xd2\x78\x8f\xb0\x07\x0e\x28\xc2\xa5\xc8\xaa\xf1\x5b\x5d\xbf\x30\xb4\x09\x07\xff\x6c\x50\x68\xfd\xcb\xc1\x1a\x2d\x00"
                    .to_vec()
            }))
        );
        assert_eq!(
            block_on(process(&Transaction::Eip1559(&pb::EthSignEip1559Request {
                keypath: KEYPATH.to_vec(),
                nonce: b"\x1f\xdc".to_vec(),
                max_priority_fee_per_gas: b"".to_vec(),
                max_fee_per_gas: b"\x01\x65\xa0\xbc\x00".to_vec(),
                gas_limit: b"\x52\x08".to_vec(),
                recipient: b"\x04\xf2\x64\xcf\x34\x44\x03\x13\xb4\xa0\x19\x2a\x35\x28\x14\xfb\xe9\x27\xb8\x85".to_vec(),
                value: b"\x07\x5c\xf1\x25\x9e\x9c\x40\x00".to_vec(),
                data: b"".to_vec(),
                host_nonce_commitment: None,
                chain_id: 1,
                address: hex::encode(b"\x04\xf2\x64\xcf\x34\x44\x03\x13\xb4\xa0\x19\x2a\x35\x28\x14\xfb\xe9\x27\xb8\x85".to_vec()),
            }))),
            Ok(Response::Sign(pb::EthSignResponse {
                signature: b"\x28\x91\x11\x77\x0d\xc0\x67\x89\x57\x80\xde\x3e\x9b\x30\x45\x4e\x33\x1b\xa6\x66\x1f\x04\x6e\x9e\x26\x43\x15\x76\xd7\xf0\x8a\x49\x6f\xfe\x6d\xef\xfb\x07\xdd\x8d\x47\x13\xd8\xc5\x23\xb6\xc3\x3b\x53\xdd\x6e\xf2\xdc\x9c\x39\x4d\x6e\x21\xf6\x43\x07\xd2\xbc\xf0\x01"
                    .to_vec()
            }))
        );
    }

    /// Test a transaction with an unusually high fee.
    #[test]
    fn test_high_fee_warning() {
        const KEYPATH: &[u32] = &[44 + HARDENED, 60 + HARDENED, 0 + HARDENED, 0, 0];

        static mut UI_COUNTER: u32 = 0;
        mock(Data {
            ui_transaction_address_create: Some(Box::new(|_amount, _address| true)),
            ui_transaction_fee_create: Some(Box::new(|total, fee, longtouch| {
                assert_eq!(total, "0.59427728 ETH");
                assert_eq!(fee, "0.06371328 ETH");
                assert!(!longtouch);
                true
            })),
            ui_confirm_create: Some(Box::new(move |params| {
                match unsafe {
                    UI_COUNTER += 1;
                    UI_COUNTER
                } {
                    1 => {
                        assert_eq!(params.title, "High fee");
                        assert_eq!(params.body, "The fee is 12.0%\nthe send amount.\nProceed?");
                        assert!(params.longtouch);
                        true
                    }
                    _ => panic!("too many user confirmations"),
                }
            })),
            ..Default::default()
        });
        mock_unlocked();
        assert!(block_on(process(&Transaction::Legacy(&pb::EthSignRequest {
            coin: pb::EthCoin::Eth as _,
            keypath: KEYPATH.to_vec(),
            nonce: b"\x1f\xdc".to_vec(),
            // fee=gas_price*gas_limit=63713280000000000
            gas_price: b"\x01\x65\xa0\xbc\x00\x00".to_vec(),
            gas_limit: b"\xa2\x08".to_vec(),
            recipient:
                b"\x04\xf2\x64\xcf\x34\x44\x03\x13\xb4\xa0\x19\x2a\x35\x28\x14\xfb\xe9\x27\xb8\x85"
                    .to_vec(),
            // 530564000000000000
            value: b"\x07\x5c\xf1\x25\x9e\x9c\x40\x00".to_vec(),
            data: b"".to_vec(),
            host_nonce_commitment: None,
            chain_id: 0,
            address: hex::encode(
                b"\x04\xf2\x64\xcf\x34\x44\x03\x13\xb4\xa0\x19\x2a\x35\x28\x14\xfb\xe9\x27\xb8\x85"
                    .to_vec()
            ),
        })))
        .is_ok());
        assert_eq!(unsafe { UI_COUNTER }, 1);
    }

    /// Test an EIP-1559 transaction with an unusually high fee.
    #[test]
    fn test_high_fee_warning_eip1559() {
        const KEYPATH: &[u32] = &[44 + HARDENED, 60 + HARDENED, 0 + HARDENED, 0, 0];

        static mut UI_COUNTER: u32 = 0;
        mock(Data {
            ui_transaction_address_create: Some(Box::new(|_amount, _address| true)),
            ui_transaction_fee_create: Some(Box::new(|total, fee, longtouch| {
                assert_eq!(total, "0.59427728 ETH");
                assert_eq!(fee, "0.06371328 ETH");
                assert!(!longtouch);
                true
            })),
            ui_confirm_create: Some(Box::new(move |params| {
                match unsafe {
                    UI_COUNTER += 1;
                    UI_COUNTER
                } {
                    1 => {
                        assert_eq!(params.title, "High fee");
                        assert_eq!(params.body, "The fee is 12.0%\nthe send amount.\nProceed?");
                        assert!(params.longtouch);
                        true
                    }
                    _ => panic!("too many user confirmations"),
                }
            })),
            ..Default::default()
        });
        mock_unlocked();
        assert!(block_on(process(&Transaction::Eip1559(&pb::EthSignEip1559Request {
            keypath: KEYPATH.to_vec(),
            nonce: b"\x1f\xdc".to_vec(),
            // fee=max_fee_per_gas*gas_limit=63713280000000000
            max_priority_fee_per_gas: b"".to_vec(),
            max_fee_per_gas: b"\x01\x65\xa0\xbc\x00\x00".to_vec(),
            gas_limit: b"\xa2\x08".to_vec(),
            recipient:
                b"\x04\xf2\x64\xcf\x34\x44\x03\x13\xb4\xa0\x19\x2a\x35\x28\x14\xfb\xe9\x27\xb8\x85"
                    .to_vec(),
            // 530564000000000000
            value: b"\x07\x5c\xf1\x25\x9e\x9c\x40\x00".to_vec(),
            data: b"".to_vec(),
            host_nonce_commitment: None,
            chain_id: 1,
            address: hex::encode(b"\x04\xf2\x64\xcf\x34\x44\x03\x13\xb4\xa0\x19\x2a\x35\x28\x14\xfb\xe9\x27\xb8\x85".to_vec()),
        })))
        .is_ok());
        assert_eq!(unsafe { UI_COUNTER }, 1);
    }

    /// Standard ETH transaction on an unusual keypath (Goerli on mainnet keypath)
    #[test]
    pub fn test_process_warn_unusual_keypath() {
        const KEYPATH: &[u32] = &[44 + HARDENED, 60 + HARDENED, 0 + HARDENED, 0, 0];

        static mut CONFIRM_COUNTER: u32 = 0;
        mock(Data {
            ui_confirm_create: Some(Box::new(|params| {
                match unsafe {
                    CONFIRM_COUNTER += 1;
                    CONFIRM_COUNTER
                } {
                    1 => {
                        assert_eq!(params.title, "Goerli");
                        assert_eq!(params.body, "Warning: unusual keypath m/44'/60'/0'/0/0. Proceed only if you know what you are doing.");
                        true
                    }
                    _ => panic!("too many user confirmations"),
                }
            })),
            ui_transaction_address_create: Some(Box::new(|amount, address| {
                assert_eq!(amount, "0.530564 GOETH");
                assert_eq!(address, "0x04F264Cf34440313B4A0192A352814FBe927b885");
                true
            })),
            ui_transaction_fee_create: Some(Box::new(|total, fee, longtouch| {
                assert_eq!(total, "0.53069 GOETH");
                assert_eq!(fee, "0.000126 GOETH");
                assert!(longtouch);
                true
            })),
            ..Default::default()
        });
        mock_unlocked();

        block_on(process(&Transaction::Legacy(&pb::EthSignRequest {
            coin: pb::EthCoin::Eth as _,
            keypath: KEYPATH.to_vec(),
            nonce: b"\x1f\xdc".to_vec(),
            gas_price: b"\x01\x65\xa0\xbc\x00".to_vec(),
            gas_limit: b"\x52\x08".to_vec(),
            recipient:
                b"\x04\xf2\x64\xcf\x34\x44\x03\x13\xb4\xa0\x19\x2a\x35\x28\x14\xfb\xe9\x27\xb8\x85"
                    .to_vec(),
            value: b"\x07\x5c\xf1\x25\x9e\x9c\x40\x00".to_vec(),
            data: b"".to_vec(),
            host_nonce_commitment: None,
            chain_id: 5,
            address: String::from("04F264Cf34440313B4A0192A352814FBe927b885"),
        })))
        .unwrap();
        assert_eq!(unsafe { CONFIRM_COUNTER }, 1);
    }

    /// Standard ETH transaction with an unknown data field.
    #[test]
    pub fn test_process_standard_transaction_with_data() {
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
            ui_transaction_fee_create: Some(Box::new(|total, fee, longtouch| {
                assert_eq!(total, "0.53069 ETH");
                assert_eq!(fee, "0.000126 ETH");
                assert!(longtouch);
                true
            })),
            ..Default::default()
        });
        mock_unlocked();
        assert_eq!(
            block_on(process(&Transaction::Legacy(&pb::EthSignRequest {
                coin: pb::EthCoin::Eth as _,
                keypath: KEYPATH.to_vec(),
                nonce: b"\x1f\xdc".to_vec(),
                gas_price: b"\x01\x65\xa0\xbc\x00".to_vec(),
                gas_limit: b"\x52\x08".to_vec(),
                recipient: b"\x04\xf2\x64\xcf\x34\x44\x03\x13\xb4\xa0\x19\x2a\x35\x28\x14\xfb\xe9\x27\xb8\x85".to_vec(),
                value: b"\x07\x5c\xf1\x25\x9e\x9c\x40\x00".to_vec(),
                data: b"foo bar".to_vec(),
                host_nonce_commitment: None,
                chain_id: 0,
                address: String::from("04F264Cf34440313B4A0192A352814FBe927b885")
            }))),
            Ok(Response::Sign(pb::EthSignResponse {
                signature: b"\x7d\x3f\x37\x13\xe3\xcf\x10\x82\x79\x1d\x5c\x0f\xc6\x8e\xc2\x9e\xaf\xf5\xe1\xee\x84\x67\xa8\xec\x54\x7d\xc7\x96\xe8\x5a\x79\x04\x2b\x7c\x01\x69\x2f\xb7\x2f\x55\x76\xab\x50\xdc\xaa\x62\x1a\xd1\xee\xab\xd9\x97\x59\x73\xb8\x62\x56\xf4\x0c\x6f\x85\x50\xef\x44\x00"
                    .to_vec()
            }))
        );
    }

    /// EIP-1559 ETH transaction with an unknown data field.
    #[test]
    pub fn test_process_eip1559_transaction_with_data() {
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
            ui_transaction_fee_create: Some(Box::new(|total, fee, longtouch| {
                assert_eq!(total, "0.53069 ETH");
                assert_eq!(fee, "0.000126 ETH");
                assert!(longtouch);
                true
            })),
            ..Default::default()
        });
        mock_unlocked();
        assert_eq!(
            block_on(process(&Transaction::Eip1559(&pb::EthSignEip1559Request {
                keypath: KEYPATH.to_vec(),
                nonce: b"\x1f\xdc".to_vec(),
                max_priority_fee_per_gas: b"\x3b\x9a\xca\x00".to_vec(),
                max_fee_per_gas: b"\x01\x65\xa0\xbc\x00".to_vec(),
                gas_limit: b"\x52\x08".to_vec(),
                recipient: b"\x04\xf2\x64\xcf\x34\x44\x03\x13\xb4\xa0\x19\x2a\x35\x28\x14\xfb\xe9\x27\xb8\x85".to_vec(),
                value: b"\x07\x5c\xf1\x25\x9e\x9c\x40\x00".to_vec(),
                data: b"foo bar".to_vec(),
                host_nonce_commitment: None,
                chain_id: 1,
                address: String::from("04F264Cf34440313B4A0192A352814FBe927b885"),
            }))),
            Ok(Response::Sign(pb::EthSignResponse {
                signature: b"\xc5\xd9\x63\x9a\x77\x8a\x34\x15\xf6\x3a\x11\xc0\x3a\x58\xbe\xde\x6b\x3c\xaf\xff\x4f\x2c\xe6\xea\x16\x41\x1e\x76\xfb\xa9\x46\xf7\x21\x66\xf0\x9e\x31\x3c\x07\xe7\x8b\x7b\x1f\xff\x87\x45\x0c\x43\x21\x17\x0c\x02\xdf\x2d\x36\xc4\x4c\x3a\x02\x1a\xbf\x20\x54\x60\x01"
                    .to_vec()
            }))
        );
    }

    /// ERC20 transaction: recipient is an ERC20 contract address, and
    /// the data field contains an ERC20 transfer method invocation.
    #[test]
    pub fn test_process_standard_erc20_transaction() {
        const KEYPATH: &[u32] = &[44 + HARDENED, 60 + HARDENED, 0 + HARDENED, 0, 0];

        mock(Data {
            ui_transaction_address_create: Some(Box::new(|amount, address| {
                assert_eq!(amount, "57 USDT");
                assert_eq!(address, "0xE6CE0a092A99700CD4ccCcBb1fEDc39Cf53E6330");
                true
            })),
            ui_transaction_fee_create: Some(Box::new(|total, fee, longtouch| {
                assert_eq!(total, "57 USDT");
                assert_eq!(fee, "0.0012658164 ETH");
                assert!(longtouch);
                true
            })),
            ..Default::default()
        });
        mock_unlocked();
        assert_eq!(
            block_on(process(&Transaction::Legacy(&pb::EthSignRequest {
                coin: pb::EthCoin::RopstenEth as _, // ignored because chain_id > 0
                keypath: KEYPATH.to_vec(),
                nonce: b"\x23\x67".to_vec(),
                gas_price: b"\x02\x7a\xca\x1a\x80".to_vec(),
                gas_limit: b"\x01\xd0\x48".to_vec(),
                recipient: b"\xda\xc1\x7f\x95\x8d\x2e\xe5\x23\xa2\x20\x62\x06\x99\x45\x97\xc1\x3d\x83\x1e\xc7".to_vec(),
                value: b"".to_vec(),
                data: b"\xa9\x05\x9c\xbb\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xe6\xce\x0a\x09\x2a\x99\x70\x0c\xd4\xcc\xcc\xbb\x1f\xed\xc3\x9c\xf5\x3e\x63\x30\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x65\xc0\x40".to_vec(),
                host_nonce_commitment: None,
                chain_id: 1,
                address: String::from("E6CE0a092A99700CD4ccCcBb1fEDc39Cf53E6330")
            }))),
            Ok(Response::Sign(pb::EthSignResponse {
                signature: b"\x67\x4e\x9a\x01\x70\xee\xe0\xca\x8c\x40\x6e\xc9\xa7\xdf\x2e\x3a\x6b\xdd\x17\x9c\xf6\x93\x85\x80\x0e\x1f\xd3\x78\xe7\xcf\xb1\x9c\x4d\x55\x16\x2c\x54\x7b\x04\xd1\x81\x8e\x43\x90\x16\x91\xae\xc9\x88\xef\x75\xcd\x67\xd9\xbb\x30\x1d\x14\x90\x2f\xd6\xe6\x92\x92\x01"
                    .to_vec()
            }))
        );
        assert_eq!(
            block_on(process(&Transaction::Eip1559(&pb::EthSignEip1559Request {
                keypath: KEYPATH.to_vec(),
                nonce: b"\x23\x67".to_vec(),
                max_priority_fee_per_gas: b"\x3b\x9a\xca\x00".to_vec(),
                max_fee_per_gas: b"\x02\x7a\xca\x1a\x80".to_vec(),
                gas_limit: b"\x01\xd0\x48".to_vec(),
                recipient: b"\xda\xc1\x7f\x95\x8d\x2e\xe5\x23\xa2\x20\x62\x06\x99\x45\x97\xc1\x3d\x83\x1e\xc7".to_vec(),
                value: b"".to_vec(),
                data: b"\xa9\x05\x9c\xbb\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xe6\xce\x0a\x09\x2a\x99\x70\x0c\xd4\xcc\xcc\xbb\x1f\xed\xc3\x9c\xf5\x3e\x63\x30\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x65\xc0\x40".to_vec(),
                host_nonce_commitment: None,
                chain_id: 1,
                address: hex::encode(b"\xda\xc1\x7f\x95\x8d\x2e\xe5\x23\xa2\x20\x62\x06\x99\x45\x97\xc1\x3d\x83\x1e\xc7".to_vec()),
            }))),
            Ok(Response::Sign(pb::EthSignResponse {
                signature: b"\x31\x62\x48\x78\x80\xab\xde\xa1\xf3\x52\xd9\xa4\xe3\xd5\x60\x66\xf1\x22\xf0\x4f\xf1\x12\x11\x7c\x8c\xa3\xcd\x22\x0f\x16\x66\x30\x2d\xac\xd5\xe5\xe8\xda\x4c\xd3\x97\x04\xe3\x34\x43\xa9\xa7\xf3\x26\x02\xd3\x32\xbb\x52\x56\x7c\x2e\x34\xaa\xfe\x9e\xd4\x8f\xeb\x01"
                    .to_vec()
            }))
        );
    }

    /// An ERC20 transaction which is not in our list of supported ERC20 tokens.
    #[test]
    pub fn test_process_standard_unknown_erc20_transaction() {
        const KEYPATH: &[u32] = &[44 + HARDENED, 60 + HARDENED, 0 + HARDENED, 0, 0];

        mock(Data {
            ui_transaction_address_create: Some(Box::new(|amount, address| {
                assert_eq!(amount, "Unknown token");
                assert_eq!(address, "0x857B3D969eAcB775a9f79cabc62Ec4bB1D1cd60e");
                true
            })),
            ui_transaction_fee_create: Some(Box::new(|total, fee, longtouch| {
                assert_eq!(total, "Unknown amount");
                assert_eq!(fee, "0.000067973 ETH");
                assert!(longtouch);
                true
            })),
            ..Default::default()
        });
        mock_unlocked();
        assert_eq!(
            block_on(process(&Transaction::Legacy(&pb::EthSignRequest {
                coin: pb::EthCoin::Eth as _,
                keypath: KEYPATH.to_vec(),
                nonce: b"\xb9".to_vec(),
                gas_price: b"\x3b\x9a\xca\x00".to_vec(),
                gas_limit: b"\x01\x09\x85".to_vec(),
                recipient: b"\x9c\x23\xd6\x7a\xea\x7b\x95\xd8\x09\x42\xe3\x83\x6b\xcd\xf7\xe7\x08\xa7\x47\xc1".to_vec(),
                value: b"".to_vec(),
                data: b"\xa9\x05\x9c\xbb\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x85\x7b\x3d\x96\x9e\xac\xb7\x75\xa9\xf7\x9c\xab\xc6\x2e\xc4\xbb\x1d\x1c\xd6\x0e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x98\xa6\x3c\xbe\xb8\x59\xd0\x27\xb0".to_vec(),
                host_nonce_commitment: None,
                chain_id: 0,
                address: String::from("857B3D969eAcB775a9f79cabc62Ec4bB1D1cd60e")
            }))),
            Ok(Response::Sign(pb::EthSignResponse {
                signature: b"\xec\x6e\x53\x0c\x8e\xe2\x54\x34\xfc\x44\x0e\x9a\xc0\xf8\x88\xe9\xc6\x3c\xf0\x7e\xbc\xf1\xc2\xf8\xa8\x3e\x2e\x8c\x39\x83\x2c\x55\x15\x12\x71\x6f\x6e\x1a\x8b\x66\xce\x38\x11\xa7\x26\xbc\xb2\x44\x66\x4e\xf2\x6f\x98\xee\x35\xc0\xc9\xdb\x4c\xaa\xb0\x73\x98\x56\x00"
                    .to_vec()
            }))
        );
        assert_eq!(
            block_on(process(&Transaction::Eip1559(&pb::EthSignEip1559Request {
                keypath: KEYPATH.to_vec(),
                nonce: b"\xb9".to_vec(),
                max_priority_fee_per_gas: b"".to_vec(),
                max_fee_per_gas: b"\x3b\x9a\xca\x00".to_vec(),
                gas_limit: b"\x01\x09\x85".to_vec(),
                recipient: b"\x9c\x23\xd6\x7a\xea\x7b\x95\xd8\x09\x42\xe3\x83\x6b\xcd\xf7\xe7\x08\xa7\x47\xc1".to_vec(),
                value: b"".to_vec(),
                data: b"\xa9\x05\x9c\xbb\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x85\x7b\x3d\x96\x9e\xac\xb7\x75\xa9\xf7\x9c\xab\xc6\x2e\xc4\xbb\x1d\x1c\xd6\x0e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x98\xa6\x3c\xbe\xb8\x59\xd0\x27\xb0".to_vec(),
                host_nonce_commitment: None,
                chain_id: 1,
                address: hex::encode(b"\x9c\x23\xd6\x7a\xea\x7b\x95\xd8\x09\x42\xe3\x83\x6b\xcd\xf7\xe7\x08\xa7\x47\xc1".to_vec()),
            }))),
            Ok(Response::Sign(pb::EthSignResponse {
                signature: b"\x82\x03\xd8\x0b\x60\x0d\xce\x8e\x77\xcd\xcb\x11\x9d\x45\xdb\x7f\x60\xd7\xca\x34\xe7\x36\x91\x40\xe9\x2d\x93\x91\x92\x21\xf8\x5a\x0a\x11\x9d\x24\x64\xdf\xab\x65\x83\x30\x95\xc1\x27\x63\xfe\xd3\x7c\x07\x2f\xeb\x29\x61\x0e\x14\x37\xf3\x88\x95\x8d\x77\x56\x28\x01"
                    .to_vec()
            }))
        );
    }

    #[test]
    pub fn test_process_unhappy() {
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
            chain_id: 0,
            address: hex::encode(
                b"\x04\xf2\x64\xcf\x34\x44\x03\x13\xb4\xa0\x19\x2a\x35\x28\x14\xfb\xe9\x27\xb8\x85"
                    .to_vec(),
            ),
        };

        {
            // Check that the above is valid before making invalid variants.
            mock(Data {
                ui_transaction_address_create: Some(Box::new(|_, _| true)),
                ui_transaction_fee_create: Some(Box::new(|_, _, _| true)),
                ..Default::default()
            });
            mock_unlocked();
            assert!(block_on(process(&Transaction::Legacy(&valid_request))).is_ok());
        }

        {
            // invalid coin
            let mut invalid_request = valid_request.clone();
            invalid_request.coin = 100;
            assert_eq!(
                block_on(process(&Transaction::Legacy(&invalid_request))),
                Err(Error::InvalidInput)
            );
        }

        {
            // invalid keypath (wrong coin part).
            let mut invalid_request = valid_request.clone();
            invalid_request.keypath = vec![44 + HARDENED, 0 + HARDENED, 0 + HARDENED, 0, 0];
            assert_eq!(
                block_on(process(&Transaction::Legacy(&invalid_request))),
                Err(Error::InvalidInput)
            );
        }

        {
            // invalid keypath (account too high).
            let mut invalid_request = valid_request.clone();
            invalid_request.keypath = vec![44 + HARDENED, 60 + HARDENED, 0 + HARDENED, 0, 100];
            assert_eq!(
                block_on(process(&Transaction::Legacy(&invalid_request))),
                Err(Error::InvalidInput)
            );
        }

        {
            // data too long
            let mut invalid_request = valid_request.clone();
            invalid_request.data = vec![0; 6145];
            assert_eq!(
                block_on(process(&Transaction::Legacy(&invalid_request))),
                Err(Error::InvalidInput)
            );
        }

        {
            // recipient too long
            let mut invalid_request = valid_request.clone();
            invalid_request.recipient = vec![b'a'; 21];
            assert_eq!(
                block_on(process(&Transaction::Legacy(&invalid_request))),
                Err(Error::InvalidInput)
            );
        }

        {
            // recipient has the right size, but is all zeroes
            let mut invalid_request = valid_request.clone();
            invalid_request.recipient = vec![0; 20];
            assert_eq!(
                block_on(process(&Transaction::Legacy(&invalid_request))),
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
            assert_eq!(
                block_on(process(&Transaction::Legacy(&valid_request))),
                Err(Error::UserAbort)
            );
        }
        {
            // User rejects total/fee.
            mock(Data {
                ui_transaction_address_create: Some(Box::new(|amount, address| {
                    assert_eq!(amount, "0.530564 ETH");
                    assert_eq!(address, "0x04F264Cf34440313B4A0192A352814FBe927b885");
                    true
                })),
                ui_transaction_fee_create: Some(Box::new(|total, fee, longtouch| {
                    assert_eq!(total, "0.53069 ETH");
                    assert_eq!(fee, "0.000126 ETH");
                    assert!(longtouch);
                    false
                })),
                ..Default::default()
            });
            assert_eq!(
                block_on(process(&Transaction::Legacy(&valid_request))),
                Err(Error::UserAbort)
            );
        }
        {
            // Keystore locked.
            mock(Data {
                ui_transaction_address_create: Some(Box::new(|_, _| true)),
                ui_transaction_fee_create: Some(Box::new(|_, _, _| true)),
                ..Default::default()
            });
            assert_eq!(
                block_on(process(&Transaction::Legacy(&valid_request))),
                Err(Error::Generic)
            );
        }
    }

    #[test]
    pub fn test_process_unhappy_eip1559() {
        let valid_request = pb::EthSignEip1559Request {
            keypath: vec![44 + HARDENED, 60 + HARDENED, 0 + HARDENED, 0, 0],
            nonce: b"\x1f\xdc".to_vec(),
            max_priority_fee_per_gas: b"".to_vec(),
            max_fee_per_gas: b"\x01\x65\xa0\xbc\x00".to_vec(),
            gas_limit: b"\x52\x08".to_vec(),
            recipient:
                b"\x04\xf2\x64\xcf\x34\x44\x03\x13\xb4\xa0\x19\x2a\x35\x28\x14\xfb\xe9\x27\xb8\x85"
                    .to_vec(),
            value: b"\x07\x5c\xf1\x25\x9e\x9c\x40\x00".to_vec(),
            data: b"".to_vec(),
            host_nonce_commitment: None,
            chain_id: 1,
            address: hex::encode(
                b"\x04\xf2\x64\xcf\x34\x44\x03\x13\xb4\xa0\x19\x2a\x35\x28\x14\xfb\xe9\x27\xb8\x85"
                    .to_vec(),
            ),
        };

        {
            // Check that the above is valid before making invalid variants.
            mock(Data {
                ui_transaction_address_create: Some(Box::new(|_, _| true)),
                ui_transaction_fee_create: Some(Box::new(|_, _, _| true)),
                ..Default::default()
            });
            mock_unlocked();
            assert!(block_on(process(&Transaction::Eip1559(&valid_request))).is_ok());
        }

        {
            // invalid chain ID
            let mut invalid_request = valid_request.clone();
            invalid_request.chain_id = 0;
            assert_eq!(
                block_on(process(&Transaction::Eip1559(&invalid_request))),
                Err(Error::InvalidInput)
            );
        }
    }

    /// Unknown chain ID (network params not hardcoded in in the firmware).
    #[test]
    pub fn test_process_unknown_network() {
        const KEYPATH: &[u32] = &[44 + HARDENED, 60 + HARDENED, 0 + HARDENED, 0, 0];

        static mut CONFIRM_COUNTER: u32 = 0;

        mock(Data {
            ui_confirm_create: Some(Box::new(|params| {
                match unsafe {
                    CONFIRM_COUNTER += 1;
                    CONFIRM_COUNTER
                } {
                    1 => {
                        assert_eq!(params.title, "Warning");
                        assert_eq!(params.body, "Unknown network\nwith chain ID:\n12345");
                        true
                    }
                    2 => {
                        assert_eq!(params.title, "Warning");
                        assert_eq!(
                            params.body,
                            "Only proceed if\nyou recognize\nthis chain ID."
                        );
                        true
                    }
                    _ => panic!("unexpected user confirmation"),
                }
            })),
            ui_transaction_address_create: Some(Box::new(|amount, address| {
                match unsafe {
                    CONFIRM_COUNTER += 1;
                    CONFIRM_COUNTER
                } {
                    3 => {
                        assert_eq!(amount, "0.530564 ");
                        assert_eq!(address, "0x04F264Cf34440313B4A0192A352814FBe927b885");
                        true
                    }
                    _ => panic!("unexpected user confirmation"),
                }
            })),
            ui_transaction_fee_create: Some(Box::new(|total, fee, longtouch| {
                match unsafe {
                    CONFIRM_COUNTER += 1;
                    CONFIRM_COUNTER
                } {
                    4 => {
                        assert_eq!(total, "0.53069 ");
                        assert_eq!(fee, "0.000126 ");
                        assert!(longtouch);
                        true
                    }
                    _ => panic!("unexpected user confirmation"),
                }
            })),
            ..Default::default()
        });
        mock_unlocked();
        assert_eq!(
            block_on(process(&Transaction::Legacy(&pb::EthSignRequest {
                coin: pb::EthCoin::Eth as _,
                keypath: KEYPATH.to_vec(),
                nonce: b"\x1f\xdc".to_vec(),
                gas_price: b"\x01\x65\xa0\xbc\x00".to_vec(),
                gas_limit: b"\x52\x08".to_vec(),
                recipient: b"\x04\xf2\x64\xcf\x34\x44\x03\x13\xb4\xa0\x19\x2a\x35\x28\x14\xfb\xe9\x27\xb8\x85".to_vec(),
                value: b"\x07\x5c\xf1\x25\x9e\x9c\x40\x00".to_vec(),
                data: b"".to_vec(),
                host_nonce_commitment: None,
                chain_id: 12345,
                address: String::from("04F264Cf34440313B4A0192A352814FBe927b885")
            }))),
            Ok(Response::Sign(pb::EthSignResponse {
                signature: b"\xb1\xb6\xb3\x4e\x15\xa0\x30\x9d\xdc\x26\x03\xdf\x4c\x40\x38\xea\x86\x65\xed\x85\xd3\xf2\xc8\x1e\x7f\x1a\xa0\x25\x4b\x21\x38\x72\x0d\x60\x1f\x42\x19\xfb\x29\xab\x3d\x5f\xf7\x76\xea\xe1\xbe\x15\x26\xb4\x67\xe2\xb0\xe6\x30\xe8\xe6\x34\xa4\xda\x4a\x82\x2e\x39\x00".to_vec()
            }))
        );
        assert_eq!(unsafe { CONFIRM_COUNTER }, 4);
    }
}
