// Copyright 2022-2024 Shift Crypto AG
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

use crate::xpubcache::Bip32XpubCache;

use alloc::string::String;
use alloc::vec::Vec;

use pb::btc_script_config::SimpleType;
pub use pb::btc_sign_init_request::FormatUnit;
pub use pb::{BtcCoin, BtcOutputType};

use super::script_configs::{ValidatedScriptConfig, ValidatedScriptConfigWithKeypath};
use super::{multisig, params::Params, script};

use sha2::{Digest, Sha256};

const HASH160_LEN: usize = 20;
const SHA256_LEN: usize = 32;

/// Converts a satoshi value to a string, suffixed with `unit`, e.g. 1234567890 -> "12.3456789 BTC".
pub fn format_amount(
    params: &Params,
    format_unit: FormatUnit,
    satoshi: u64,
) -> Result<String, Error> {
    let (decimals, unit) = match params.coin {
        BtcCoin::Btc => match format_unit {
            FormatUnit::Default => (8, "BTC"),
            FormatUnit::Sat => (0, "sat"),
        },
        BtcCoin::Tbtc => match format_unit {
            FormatUnit::Default => (8, "TBTC"),
            FormatUnit::Sat => (0, "tsat"),
        },
        BtcCoin::Ltc => match format_unit {
            FormatUnit::Default => (8, "LTC"),
            _ => return Err(Error::InvalidInput),
        },
        BtcCoin::Tltc => match format_unit {
            FormatUnit::Default => (8, "TLTC"),
            _ => return Err(Error::InvalidInput),
        },
    };
    let mut s = match format_unit {
        FormatUnit::Default => util::decimal::format_no_trim(satoshi, decimals),
        _ => util::decimal::format(satoshi, decimals),
    };
    s.push(' ');
    s.push_str(unit);
    Ok(s)
}

/// Payload contains the data needed to construct output pkScripts and addresses.
pub struct Payload {
    pub data: Vec<u8>,
    pub output_type: BtcOutputType,
}

impl Payload {
    pub fn from_simple(
        xpub_cache: &mut Bip32XpubCache,
        params: &Params,
        simple_type: SimpleType,
        keypath: &[u32],
    ) -> Result<Self, Error> {
        match simple_type {
            SimpleType::P2wpkh => Ok(Payload {
                data: xpub_cache.get_xpub(keypath)?.pubkey_hash160(),
                output_type: BtcOutputType::P2wpkh,
            }),
            SimpleType::P2wpkhP2sh => {
                let payload_p2wpkh =
                    Payload::from_simple(xpub_cache, params, SimpleType::P2wpkh, keypath)?;
                let pkscript_p2wpkh = payload_p2wpkh.pk_script(params)?;
                Ok(Payload {
                    data: bitbox02::hash160(&pkscript_p2wpkh).to_vec(),
                    output_type: BtcOutputType::P2sh,
                })
            }
            SimpleType::P2tr => {
                if params.taproot_support {
                    Ok(Payload {
                        data: xpub_cache
                            .get_xpub(keypath)?
                            .schnorr_bip86_pubkey()?
                            .to_vec(),
                        output_type: BtcOutputType::P2tr,
                    })
                } else {
                    Err(Error::InvalidInput)
                }
            }
        }
    }

    /// Constructs sha256(<multisig pkScript>) from the provided multisig.
    /// Note that the multisig config and keypaths are *not* validated, this must be done before calling.
    /// The xpubs are account-level xpubs.
    /// keypath_change: 0 for receive addresses, 1 for change addresses.
    /// keypath_address: receive address index.
    pub fn from_multisig(
        params: &Params,
        multisig: &pb::btc_script_config::Multisig,
        keypath_change: u32,
        keypath_address: u32,
    ) -> Result<Self, Error> {
        // TODO: double check that the witness script must be <= 10,000 bytes /
        // 201 opCounts (consensus rule), resp. 3,600 bytes (standardness rule).
        // See https://bitcoincore.org/en/segwit_wallet_dev/.
        // Note that the witness script has an additional varint prefix.

        let script_type =
            pb::btc_script_config::multisig::ScriptType::try_from(multisig.script_type)?;
        let script = multisig::pkscript(multisig, keypath_change, keypath_address)?;
        let payload_p2wsh = Payload {
            data: Sha256::digest(script).to_vec(),
            output_type: BtcOutputType::P2wsh,
        };
        match script_type {
            pb::btc_script_config::multisig::ScriptType::P2wsh => Ok(payload_p2wsh),
            pb::btc_script_config::multisig::ScriptType::P2wshP2sh => {
                let pkscript_p2wsh = payload_p2wsh.pk_script(params)?;
                Ok(Payload {
                    data: bitbox02::hash160(&pkscript_p2wsh).to_vec(),
                    output_type: BtcOutputType::P2sh,
                })
            }
        }
    }

    /// Constructs payload from the provided policy.
    /// Note that the policy is *not* validated, this must be done before calling.
    ///
    /// The policy key xpubs are account-level xpubs.  The keypath must have a account-level keypath
    /// prefix followed by two unhardened elements.
    /// Example: wsh(and_v(v:pk(@0/<10;11>/*),pk(@1/<20;21>/*))) with our key [fp/48'/1'/0'/3']xpub...]
    /// derived using keypath m/48'/1'/0'/3'/11/5 derives the payload for
    /// wsh(and_v(v:pk(@0/11/5),pk(@1/21/5))).
    pub fn from_policy(
        params: &Params,
        policy: &super::policies::ParsedPolicy,
        keypath: &[u32],
    ) -> Result<Self, Error> {
        let derived_descriptor = policy.derive_at_keypath(keypath)?;
        match derived_descriptor {
            super::policies::Descriptor::Wsh(wsh) => Ok(Payload {
                data: Sha256::digest(wsh.witness_script()).to_vec(),
                output_type: BtcOutputType::P2wsh,
            }),
            super::policies::Descriptor::Tr(tr) => {
                if params.taproot_support {
                    Ok(Payload {
                        data: tr.output_key().to_vec(),
                        output_type: BtcOutputType::P2tr,
                    })
                } else {
                    Err(Error::InvalidInput)
                }
            }
        }
    }

    /// Computes the payload data from a script config. The payload can then be used generate a
    /// pkScript or an address.
    pub fn from(
        xpub_cache: &mut Bip32XpubCache,
        params: &Params,
        keypath: &[u32],
        script_config_account: &ValidatedScriptConfigWithKeypath,
    ) -> Result<Self, Error> {
        match &script_config_account.config {
            ValidatedScriptConfig::SimpleType(simple_type) => {
                Self::from_simple(xpub_cache, params, *simple_type, keypath)
            }
            ValidatedScriptConfig::Multisig(multisig) => Self::from_multisig(
                params,
                multisig,
                keypath[keypath.len() - 2],
                keypath[keypath.len() - 1],
            ),
            ValidatedScriptConfig::Policy(policy) => Self::from_policy(params, policy, keypath),
        }
    }

    /// Converts a payload to an address.
    pub fn address(&self, params: &Params) -> Result<String, ()> {
        let payload = self.data.as_slice();
        match self.output_type {
            BtcOutputType::Unknown => Err(()),
            BtcOutputType::P2pkh => {
                if payload.len() != HASH160_LEN {
                    return Err(());
                }
                let mut prefixed = [0; 21];
                prefixed[0] = params.base58_version_p2pkh;
                prefixed[1..].copy_from_slice(payload);
                Ok(bitcoin::base58::encode_check(&prefixed))
            }
            BtcOutputType::P2sh => {
                if payload.len() != HASH160_LEN {
                    return Err(());
                }
                let mut prefixed = [0; 21];
                prefixed[0] = params.base58_version_p2sh;
                prefixed[1..].copy_from_slice(payload);
                Ok(bitcoin::base58::encode_check(&prefixed))
            }
            BtcOutputType::P2wpkh => {
                if payload.len() != HASH160_LEN {
                    return Err(());
                }
                encode_segwit_addr(params.bech32_hrp, 0, payload)
            }
            BtcOutputType::P2wsh => {
                if payload.len() != SHA256_LEN {
                    return Err(());
                }
                encode_segwit_addr(params.bech32_hrp, 0, payload)
            }
            BtcOutputType::P2tr => {
                if !params.taproot_support || payload.len() != 32 {
                    return Err(());
                }
                encode_segwit_addr(params.bech32_hrp, 1, payload)
            }
        }
    }

    /// Computes the pkScript from a pubkey hash or script hash or pubkey, depending on the output type.
    pub fn pk_script(&self, params: &Params) -> Result<Vec<u8>, Error> {
        let payload = self.data.as_slice();
        match self.output_type {
            BtcOutputType::Unknown => Err(Error::InvalidInput),
            BtcOutputType::P2pkh => {
                if payload.len() != HASH160_LEN {
                    return Err(Error::Generic);
                }
                let mut result = vec![script::OP_DUP, script::OP_HASH160];
                script::push_data(&mut result, payload);
                result.extend_from_slice(&[script::OP_EQUALVERIFY, script::OP_CHECKSIG]);
                Ok(result)
            }
            BtcOutputType::P2sh => {
                if payload.len() != HASH160_LEN {
                    return Err(Error::Generic);
                }
                let mut result = vec![script::OP_HASH160];
                script::push_data(&mut result, payload);
                result.push(script::OP_EQUAL);
                Ok(result)
            }
            BtcOutputType::P2wpkh | BtcOutputType::P2wsh => {
                if (self.output_type == BtcOutputType::P2wpkh && payload.len() != HASH160_LEN)
                    || (self.output_type == BtcOutputType::P2wsh && payload.len() != SHA256_LEN)
                {
                    return Err(Error::Generic);
                }
                let mut result = vec![script::OP_0];
                script::push_data(&mut result, payload);
                Ok(result)
            }
            BtcOutputType::P2tr => {
                if !params.taproot_support {
                    return Err(Error::InvalidInput);
                }
                if payload.len() != 32 {
                    return Err(Error::Generic);
                }
                let mut result = vec![script::OP_1];
                script::push_data(&mut result, payload);
                Ok(result)
            }
        }
    }
}

fn encode_segwit_addr(
    hrp: &str,
    witness_version: u8,
    witness_program: &[u8],
) -> Result<String, ()> {
    let version = match witness_version {
        0 => bech32::segwit::VERSION_0,
        1 => bech32::segwit::VERSION_1,
        _ => return Err(()),
    };
    bech32::segwit::encode(bech32::Hrp::parse_unchecked(hrp), version, witness_program).or(Err(()))
}

#[cfg(test)]
mod tests {
    use super::*;

    use bitbox02::testing::mock_unlocked_using_mnemonic;
    use util::bip32::HARDENED;

    #[test]
    fn test_address_from_payload() {
        let params_btc = super::super::params::get(pb::BtcCoin::Btc);
        let params_ltc = super::super::params::get(pb::BtcCoin::Ltc);
        {
            // BTC & LTC p2pkh

            let payload = Payload {
                data: b"\x67\xfe\x0b\xdd\xe7\x98\x46\x71\xf2\xed\x59\xbb\x68\xa9\x7d\x9c\xc6\x8a\x02\xe0".to_vec(),
                output_type: BtcOutputType::P2pkh,
            };

            assert_eq!(
                payload.address(params_btc),
                Ok("1AUrwD77AL5ax5zj2BhZQ1x43wA5NLsYg1".into())
            );
            assert_eq!(
                payload.address(params_ltc),
                Ok("LUhpCRQwEzKeCtgtCKgrg31pG9XMZLm6qX".into())
            );
        }
        {
            // BTC & LTC p2wpkh

            let payload = Payload {
                data: b"\x3f\x0d\xc2\xe9\x14\x2d\x88\x39\xae\x9c\x90\xa1\x9c\xa8\x6c\x36\xd9\x23\xd8\xab".to_vec(),
                output_type: BtcOutputType::P2wpkh,
            };
            assert_eq!(
                payload.address(params_btc),
                Ok("bc1q8uxu96g59kyrnt5ujzsee2rvxmvj8k9trg5ltx".into())
            );
            assert_eq!(
                payload.address(params_ltc),
                Ok("ltc1q8uxu96g59kyrnt5ujzsee2rvxmvj8k9t85wmnk".into())
            );
        }

        {
            // BTC & LTC p2sh

            let payload = Payload {
                data: b"\x8d\xd0\x9c\x25\xc9\x28\xbe\x67\x66\xf4\x50\x73\x87\x0c\xe3\xbb\x93\x1f\x2f\x55".to_vec(),
                output_type: BtcOutputType::P2sh,
            };
            assert_eq!(
                payload.address(params_btc),
                Ok("3Ecs74kCeeAc6EKWMGe7RXupUoeeXPdyj7".into())
            );
            assert_eq!(
                payload.address(params_ltc),
                Ok("MLq1QxAAbm22tjbQT9dTFBADoWF6UwYB7R".into())
            );
        }

        {
            // BTC & LTC p2wsh

            let payload = Payload {
                data: b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_vec(),
                output_type: BtcOutputType::P2wsh,
            };
            assert_eq!(
                payload.address(params_btc),
                Ok("bc1qv9skzctpv9skzctpv9skzctpv9skzctpv9skzctpv9skzctpv9ss52vqes".into())
            );
            assert_eq!(
                payload.address(params_ltc),
                Ok("ltc1qv9skzctpv9skzctpv9skzctpv9skzctpv9skzctpv9skzctpv9sshwzsr4".into())
            );
        }

        // Taproot addresses, test vectors from
        // https://github.com/bitcoin/bips/blob/fb5bd37d0cdec14b47c45fda7aba4f7e8f801690/bip-0086.mediawiki#Test_vectors
        {
            // First receiving address

            let payload = Payload {
                data: b"\xa6\x08\x69\xf0\xdb\xcf\x1d\xc6\x59\xc9\xce\xcb\xaf\x80\x50\x13\x5e\xa9\xe8\xcd\xc4\x87\x05\x3f\x1d\xc6\x88\x09\x49\xdc\x68\x4c".to_vec(),
                output_type: BtcOutputType::P2tr,
            };
            assert!(payload.address(params_ltc).is_err());
            assert_eq!(
                payload.address(params_btc),
                Ok("bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr".into())
            );
        }
        {
            // Second receiving address

            let payload = Payload {
                data: b"\xa8\x2f\x29\x94\x4d\x65\xb8\x6a\xe6\xb5\xe5\xcc\x75\xe2\x94\xea\xd6\xc5\x93\x91\xa1\xed\xc5\xe0\x16\xe3\x49\x8c\x67\xfc\x7b\xbb".to_vec(),
                output_type: BtcOutputType::P2tr,
            };
            assert!(payload.address(params_ltc).is_err());
            assert_eq!(
                payload.address(params_btc),
                Ok("bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh".into())
            );
        }
        {
            // First change address

            let payload = Payload {
                data: b"\x88\x2d\x74\xe5\xd0\x57\x2d\x5a\x81\x6c\xef\x00\x41\xa9\x6b\x6c\x1d\xe8\x32\xf6\xf9\x67\x6d\x96\x05\xc4\x4d\x5e\x9a\x97\xd3\xdc".to_vec(),
                output_type: BtcOutputType::P2tr,
            };
            assert!(payload.address(params_ltc).is_err());
            assert_eq!(
                payload.address(params_btc),
                Ok("bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7".into())
            );
        }
    }

    #[test]
    fn test_format_amount() {
        let params = super::super::params::get(pb::BtcCoin::Btc);
        let params_tbtc = super::super::params::get(pb::BtcCoin::Tbtc);
        let params_ltc = super::super::params::get(pb::BtcCoin::Ltc);
        let params_tltc = super::super::params::get(pb::BtcCoin::Tltc);
        let tests: Vec<(&Params, FormatUnit, u64, Result<&str, Error>)> = vec![
            (
                params,
                FormatUnit::Default,
                1234567890,
                Ok("12.34567890 BTC"),
            ),
            (params, FormatUnit::Default, 0, Ok("0.00000000 BTC")),
            (params, FormatUnit::Sat, 0, Ok("0 sat")),
            (params, FormatUnit::Default, 1, Ok("0.00000001 BTC")),
            (params, FormatUnit::Sat, 1, Ok("1 sat")),
            (params, FormatUnit::Default, 2, Ok("0.00000002 BTC")),
            (params, FormatUnit::Sat, 2, Ok("2 sat")),
            (params, FormatUnit::Default, 10, Ok("0.00000010 BTC")),
            (params, FormatUnit::Sat, 10, Ok("10 sat")),
            (params, FormatUnit::Default, 15, Ok("0.00000015 BTC")),
            (params, FormatUnit::Default, 20, Ok("0.00000020 BTC")),
            (params, FormatUnit::Default, 300, Ok("0.00000300 BTC")),
            (params, FormatUnit::Default, 370, Ok("0.00000370 BTC")),
            (params, FormatUnit::Default, 371, Ok("0.00000371 BTC")),
            (params, FormatUnit::Sat, 371, Ok("371 sat")),
            (
                params,
                FormatUnit::Default,
                40000000000,
                Ok("400.00000000 BTC"),
            ),
            (params, FormatUnit::Sat, 40000000000, Ok("40000000000 sat")),
            (
                params,
                FormatUnit::Default,
                4000000000,
                Ok("40.00000000 BTC"),
            ),
            (params, FormatUnit::Default, 400000000, Ok("4.00000000 BTC")),
            (params, FormatUnit::Default, 40000000, Ok("0.40000000 BTC")),
            (params, FormatUnit::Default, 4000000, Ok("0.04000000 BTC")),
            (params, FormatUnit::Default, 400000, Ok("0.00400000 BTC")),
            (params, FormatUnit::Default, 40000, Ok("0.00040000 BTC")),
            (params, FormatUnit::Default, 4000, Ok("0.00004000 BTC")),
            (params, FormatUnit::Default, 400, Ok("0.00000400 BTC")),
            (params, FormatUnit::Default, 40, Ok("0.00000040 BTC")),
            (params, FormatUnit::Default, 4, Ok("0.00000004 BTC")),
            (params, FormatUnit::Default, 5432345, Ok("0.05432345 BTC")),
            (params, FormatUnit::Default, 54323452, Ok("0.54323452 BTC")),
            (params, FormatUnit::Default, 543234527, Ok("5.43234527 BTC")),
            (params, FormatUnit::Sat, 543234527, Ok("543234527 sat")),
            (
                params,
                FormatUnit::Default,
                5432345270,
                Ok("54.32345270 BTC"),
            ),
            (
                params,
                FormatUnit::Default,
                54323452708,
                Ok("543.23452708 BTC"),
            ),
            (params, FormatUnit::Default, 100000000, Ok("1.00000000 BTC")),
            (
                params,
                FormatUnit::Default,
                1234567800000001,
                Ok("12345678.00000001 BTC"),
            ),
            (
                params,
                FormatUnit::Sat,
                1234567800000001,
                Ok("1234567800000001 sat"),
            ),
            (
                params,
                FormatUnit::Default,
                0xffffffffffffffff,
                Ok("184467440737.09551615 BTC"),
            ),
            (
                params,
                FormatUnit::Default,
                0xffffffffffffffff - 5,
                Ok("184467440737.09551610 BTC"),
            ),
            // TBTC
            (
                params_tbtc,
                FormatUnit::Default,
                40001000000,
                Ok("400.01000000 TBTC"),
            ),
            // LTC
            (
                params_ltc,
                FormatUnit::Default,
                40001000000,
                Ok("400.01000000 LTC"),
            ),
            // TLTC
            (
                params_tltc,
                FormatUnit::Default,
                40001000000,
                Ok("400.01000000 TLTC"),
            ),
            // Failures
            // No sats in LTC
            (
                params_ltc,
                FormatUnit::Sat,
                40001000000,
                Err(Error::InvalidInput),
            ),
            // No sats in TLTC
            (
                params_tltc,
                FormatUnit::Sat,
                40001000000,
                Err(Error::InvalidInput),
            ),
        ];
        for (params, format_unit, satoshi, expected) in tests {
            assert_eq!(
                format_amount(params, format_unit, satoshi),
                expected.map(|s| s.into())
            );
        }
    }

    #[test]
    fn test_payload_simple() {
        mock_unlocked_using_mnemonic(
            "sudden tenant fault inject concert weather maid people chunk youth stumble grit",
            "",
        );
        let mut xpub_cache = Bip32XpubCache::new();
        let coin_params = super::super::params::get(pb::BtcCoin::Btc);
        // p2wpkh
        assert_eq!(
            Payload::from_simple(
                &mut xpub_cache,
                coin_params,
                SimpleType::P2wpkh,
                &[84 + HARDENED, 0 + HARDENED, 0 + HARDENED, 0, 0]
            )
            .unwrap()
            .data
            .as_slice(),
            b"\x3f\x0d\xc2\xe9\x14\x2d\x88\x39\xae\x9c\x90\xa1\x9c\xa8\x6c\x36\xd9\x23\xd8\xab"
        );

        //  p2wpkh-p2sh
        assert_eq!(
            Payload::from_simple(
                &mut xpub_cache,
                coin_params,
                SimpleType::P2wpkhP2sh,
                &[49 + HARDENED, 0 + HARDENED, 0 + HARDENED, 0, 0]
            )
            .unwrap()
            .data
            .as_slice(),
            b"\x8d\xd0\x9c\x25\xc9\x28\xbe\x67\x66\xf4\x50\x73\x87\x0c\xe3\xbb\x93\x1f\x2f\x55"
        );

        // p2tr
        assert_eq!(
            Payload::from_simple(
                &mut xpub_cache,
                coin_params,
                SimpleType::P2tr,
                &[86 + HARDENED, 0 + HARDENED, 0 + HARDENED, 0, 0]
            )
            .unwrap()
            .data
            .as_slice(),
            b"\x25\x0e\xc8\x02\xb6\xd3\xdb\x98\x42\xd1\xbd\xbe\x0e\xe4\x8d\x52\xf9\xa4\xb4\x6e\x60\xcb\xbb\xab\x3b\xcc\x4e\xe9\x15\x73\xfc\xe8"
        );
    }
}
