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

use bitbox02_sys::in_buffer_t;

pub struct Params {
    pub bip44_coin: u32,
    pub chain_id: u8,
    pub unit: &'static str,
}

pub fn params_get(coin: bitbox02_sys::ETHCoin) -> Option<Params> {
    let params = unsafe { bitbox02_sys::app_eth_params_get(coin).as_ref()? };
    Some(Params {
        bip44_coin: params.bip44_coin,
        chain_id: params.chain_id,
        unit: {
            let s = unsafe {
                let len = crate::util::strlen_ptr(params.unit);
                core::slice::from_raw_parts(params.unit, len as _)
            };
            core::str::from_utf8(s).unwrap()
        },
    })
}

pub struct ERC20Params {
    pub unit: &'static str,
    pub name: &'static str,
    pub contract_address: [u8; 20],
    pub decimals: u8,
}

pub fn erc20_params_get(
    coin: bitbox02_sys::ETHCoin,
    contract_address: [u8; 20],
) -> Option<ERC20Params> {
    let params = unsafe {
        bitbox02_sys::app_eth_erc20_params_get(coin, contract_address.as_ptr()).as_ref()?
    };
    Some(ERC20Params {
        unit: {
            let s = unsafe {
                let len = crate::util::strlen_ptr(params.unit);
                core::slice::from_raw_parts(params.unit, len as _)
            };
            core::str::from_utf8(s).unwrap()
        },
        name: {
            let s = unsafe {
                let len = crate::util::strlen_ptr(params.name);
                core::slice::from_raw_parts(params.name, len as _)
            };
            core::str::from_utf8(s).unwrap()
        },
        contract_address: params.contract_address,
        decimals: params.decimals,
    })
}

pub struct SighashParams<'a> {
    pub nonce: &'a [u8],
    pub gas_price: &'a [u8],
    pub gas_limit: &'a [u8],
    pub recipient: &'a [u8; 20],
    pub value: &'a [u8],
    pub data: &'a [u8],
    pub chain_id: u8,
}

pub fn sighash_eth(params: SighashParams) -> Result<[u8; 32], ()> {
    let mut sighash_out = [0u8; 32];
    let params = sighash_prepare(params);
    let result = unsafe { bitbox02_sys::app_eth_sighash(params, sighash_out.as_mut_ptr())};
    if result {
        Ok(sighash_out)
    } else {
        Err(())
    }
}
pub fn sighash_etc(params: SighashParams) -> Result<[u8; 32], ()> {
    let mut sighash_out = [0u8; 32];
    let params = sighash_prepare(params);
    let result = unsafe { bitbox02_sys::app_eth_sighash(params, sighash_out.as_mut_ptr())};
    if result {
        Ok(sighash_out)
    } else {
        Err(())
    }
}
fn sighash_prepare(params: SighashParams) -> bitbox02_sys::eth_sighash_params_t {
    bitbox02_sys::eth_sighash_params_t {
        nonce: in_buffer_t {
            data: params.nonce.as_ptr(),
            len: params.nonce.len() as _,
        },
        gas_price: in_buffer_t {
            data: params.gas_price.as_ptr(),
            len: params.gas_price.len() as _,
        },
        gas_limit: in_buffer_t {
            data: params.gas_limit.as_ptr(),
            len: params.gas_limit.len() as _,
        },
        recipient: in_buffer_t {
            data: params.recipient.as_ptr(),
            len: params.recipient.len() as _,
        },
        value: in_buffer_t {
            data: params.value.as_ptr(),
            len: params.value.len() as _,
        },
        data: in_buffer_t {
            data: params.data.as_ptr(),
            len: params.data.len() as _,
        },
        chain_id: params.chain_id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_sighash() {
        // Same as first test in test_app_eth_sighash.c.
        let params = SighashParams {
            nonce: b"\x12\x8e",
            gas_price: b"\xd6\x14\x4c\x88",
            gas_limit: b"\xb1\x07\x9b\x70\xe0\xcb\x1a\x84",
            recipient: b"\x53\x8c\x7f\x96\xb1\x64\xbf\x1b\x97\xbb\x9f\x4b\xb4\x72\xe8\x9f\x5b\x14\x84\xf2",
            value: b"\x52\x4d\x76\x42\x9b\x61\x7a\x0c\x9f\x9f\x0d\x3b\xa5\x5b\x0c\xc0",
            data: b"\x85\x35\xe1\x8f\xda\x9e\x6f\x82\xe5\x4e\x74\x8e\x81\xe7\x9e\x4b\xbd\x6f\xe3\x4c\xdc",
            chain_id: 4,
        };
        assert_eq!(
            sighash(params),
            Ok(*b"\xfc\x3f\xc4\xd3\x02\x02\xd9\x4e\x61\x7f\x57\xab\x0d\xcf\x32\x95\xe6\x5e\x3e\x08\x49\x71\x2a\x81\xe2\x72\x0b\x91\x2e\xa3\x94\x6b"),
        );
    }
}
