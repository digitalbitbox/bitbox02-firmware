// Copyright 2024 Shift Crypto AG
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

#![no_std]

extern crate alloc;

mod hash;

pub use bitcoin;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{self, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};

use alloc::vec::Vec;

pub enum Network {
    Btc,
    Tbtc,
}

impl Network {
    fn sp_hrp(&self) -> &str {
        match self {
            Network::Btc => "sp",
            Network::Tbtc => "tsp",
        }
    }
}

pub struct SilentPayment {
    secp: Secp256k1<secp256k1::All>,
    network: Network,
    smallest_outpoint: Option<bitcoin::OutPoint>,
    a_sum: Option<SecretKey>,
    // Done streaming inputs?
    inputs_done: bool,
    // We only allow one silent payment output for now. This tracks whether we've seen it.
    output_checked: bool,
}

fn calculate_t_k(ecdh_shared_secret: &PublicKey, k: u32) -> Result<SecretKey, ()> {
    let hash = hash::SharedSecretHash::from_ecdh_and_k(ecdh_shared_secret, k).to_byte_array();
    SecretKey::from_slice(&hash).map_err(|_| ())
}

fn decode_address(address: &str, expected_hrp: &str) -> Result<(PublicKey, PublicKey), ()> {
    let mut decoded_addr =
        bech32::primitives::decode::CheckedHrpstring::new::<bech32::Bech32m>(address)
            .map_err(|_| ())?;

    let hrp = decoded_addr.hrp();
    let hrp: &str = hrp.as_str();
    if hrp != expected_hrp {
        return Err(());
    }
    let witness_version = decoded_addr.remove_witness_version().unwrap();
    if witness_version != bech32::Fe32::Q {
        return Err(());
    }

    let data: Vec<u8> = decoded_addr.byte_iter().collect();
    if data.len() != 66 {
        return Err(());
    }
    let scan_pubkey = PublicKey::from_slice(&data[..33]).map_err(|_| ())?;
    let m_pubkey = PublicKey::from_slice(&data[33..]).map_err(|_| ())?;
    Ok((scan_pubkey, m_pubkey))
}

pub enum InputType {
    P2pkh,
    P2wpkhP2sh,
    P2wpkh,
    P2trKeypathspend,
}

impl InputType {
    fn is_taproot(&self) -> bool {
        matches!(self, InputType::P2trKeypathspend)
    }
}

impl SilentPayment {
    pub fn new(network: Network) -> Self {
        SilentPayment {
            secp: Secp256k1::new(),
            network,
            smallest_outpoint: None,
            a_sum: None,
            inputs_done: false,
            output_checked: false,
        }
    }

    /// This must be called for *every* input of the transaction.
    ///
    /// Important: if the input type cannot be represented by `InputType`, the transaction must be
    /// aborted, as other input types may influence the silent payment outputs (e.g. P2TR script
    /// path spends, which we currently do not support).
    pub fn add_input(
        &mut self,
        input_type: InputType,
        input_key: &SecretKey,
        prevout: bitcoin::OutPoint,
    ) -> Result<(), ()> {
        if self.inputs_done {
            return Err(());
        }
        match self.smallest_outpoint {
            None => self.smallest_outpoint = Some(prevout),
            Some(ref mut p) => {
                if bitcoin::consensus::serialize(&prevout) < bitcoin::consensus::serialize(p) {
                    *p = prevout
                }
            }
        }

        let (_, parity) = input_key.x_only_public_key(&self.secp);
        let negated_key: SecretKey = if input_type.is_taproot() && parity == secp256k1::Parity::Odd
        {
            input_key.negate()
        } else {
            *input_key
        };

        match self.a_sum {
            None => self.a_sum = Some(negated_key),
            Some(ref mut p) => {
                *p = p.add_tweak(&negated_key.into()).map_err(|_| ())?;
            }
        }

        Ok(())
    }

    /// Call this for silent payment outputs.
    /// `silent_payment_address` is the output address.
    /// This returns the SegWit v1 Taproot output key of the created output.
    pub fn create_output(&mut self, silent_payment_address: &str) -> Result<XOnlyPublicKey, ()> {
        self.inputs_done = true;
        if self.output_checked {
            return Err(());
        }
        self.output_checked = true;

        let (scan_pubkey, m_pubkey) =
            decode_address(silent_payment_address, self.network.sp_hrp())?;

        let a_sum = self.a_sum.as_ref().unwrap();
        #[allow(non_snake_case)]
        let A_sum = a_sum.public_key(&self.secp);

        let inputs_hash =
            hash::calculate_input_hash(self.smallest_outpoint.as_ref().ok_or(())?, A_sum);

        let partial_secret = a_sum.mul_tweak(&inputs_hash).map_err(|_| ())?;

        let ecdh_shared_secret: PublicKey = scan_pubkey
            .mul_tweak(&self.secp, &partial_secret.into())
            .map_err(|_| ())?;

        // If we want to support more than one silent pay4ment output, we need to get this value from
        // the host per output, and check before signing the tx that for each SP output with the
        // same scan pubkey has a different `k` and they are consecutive starting at 0, so the
        // recipient is sure to be able to find the output.  With only one silent payment output
        // supported, `k` must be 0.
        let silent_payment_k = 0;

        let t_k = calculate_t_k(&ecdh_shared_secret, silent_payment_k).map_err(|_| ())?;

        let res = t_k.public_key(&self.secp);
        let reskey = res.combine(&m_pubkey).map_err(|_| ())?;
        let (reskey_xonly, _) = reskey.x_only_public_key();
        Ok(reskey_xonly)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use core::str::FromStr;

    #[test]
    fn test_basic() {
        let mut v = SilentPayment::new(Network::Btc);
        v.add_input(
            InputType::P2wpkh,
            &SecretKey::from_str(
                "eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1",
            )
            .unwrap(),
            bitcoin::OutPoint::new(
                bitcoin::Txid::from_str(
                    "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
                )
                .unwrap(),
                0,
            ),
        )
        .unwrap();

        v.add_input(
            InputType::P2wpkh,
            &SecretKey::from_str(
                "93f5ed907ad5b2bdbbdcb5d9116ebc0a4e1f92f910d5260237fa45a9408aad16",
            )
            .unwrap(),
            bitcoin::OutPoint::new(
                bitcoin::Txid::from_str(
                    "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
                )
                .unwrap(),
                0,
            ),
        )
        .unwrap();

        assert_eq!(
            v.smallest_outpoint.unwrap().to_string().as_str(),
            "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16:0"
        );

        let expected = XOnlyPublicKey::from_str(
            "3e9fce73d4e77a4809908e3c3a2e54ee147b9312dc5044a193d1fc85de46e3c1",
        )
        .unwrap();
        assert_eq!(v.create_output("sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv").unwrap(), expected);
    }

    #[test]
    fn test_only_one_output() {
        let mut v = SilentPayment::new(Network::Btc);
        v.add_input(
            InputType::P2wpkh,
            &SecretKey::from_str(
                "eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1",
            )
            .unwrap(),
            bitcoin::OutPoint::new(
                bitcoin::Txid::from_str(
                    "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
                )
                .unwrap(),
                0,
            ),
        )
        .unwrap();

        v.add_input(
            InputType::P2wpkh,
            &SecretKey::from_str(
                "93f5ed907ad5b2bdbbdcb5d9116ebc0a4e1f92f910d5260237fa45a9408aad16",
            )
            .unwrap(),
            bitcoin::OutPoint::new(
                bitcoin::Txid::from_str(
                    "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
                )
                .unwrap(),
                0,
            ),
        )
        .unwrap();
        let _ = v.create_output("sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv").unwrap();
        assert!(v.create_output("sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv").is_err());
    }

    #[test]
    fn test_no_input_after_output() {
        let mut v = SilentPayment::new(Network::Btc);
        v.add_input(
            InputType::P2wpkh,
            &SecretKey::from_str(
                "eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1",
            )
            .unwrap(),
            bitcoin::OutPoint::new(
                bitcoin::Txid::from_str(
                    "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
                )
                .unwrap(),
                0,
            ),
        )
        .unwrap();

        v.add_input(
            InputType::P2wpkh,
            &SecretKey::from_str(
                "93f5ed907ad5b2bdbbdcb5d9116ebc0a4e1f92f910d5260237fa45a9408aad16",
            )
            .unwrap(),
            bitcoin::OutPoint::new(
                bitcoin::Txid::from_str(
                    "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
                )
                .unwrap(),
                0,
            ),
        )
        .unwrap();
        let _ = v.create_output("sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv").unwrap();

        assert!(v
            .add_input(
                InputType::P2wpkh,
                &SecretKey::from_str(
                    "93f5ed907ad5b2bdbbdcb5d9116ebc0a4e1f92f910d5260237fa45a9408aad16",
                )
                .unwrap(),
                bitcoin::OutPoint::new(
                    bitcoin::Txid::from_str(
                        "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
                    )
                    .unwrap(),
                    0,
                ),
            )
            .is_err());
    }
}
