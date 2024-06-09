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

#![allow(non_snake_case)]

use serde::Deserialize;
use std::fs::File;
use std::io::BufReader;
use std::str::FromStr;

use streaming_silent_payments::{
    bitcoin,
    bitcoin::secp256k1::{SecretKey, XOnlyPublicKey},
    InputType, Network, SilentPayment,
};

/// The following structs have been copied from:
/// https://github.com/cygnet3/rust-silentpayments/blob/395b153b6d98ea33a59306c1a8a189d4ca152571/tests/common/structs.rs

#[derive(Debug, Deserialize)]
pub struct TestData {
    pub comment: String,
    pub sending: Vec<SendingData>,
    pub receiving: Vec<ReceivingData>,
}

#[derive(Debug, Deserialize)]
pub struct ReceivingData {
    pub given: ReceivingDataGiven,
    pub expected: ReceivingDataExpected,
}

#[derive(Debug, Deserialize)]
pub struct ReceivingKeyMaterial {
    pub scan_priv_key: String,
    pub spend_priv_key: String,
}

#[derive(Debug, Deserialize)]
pub struct HexStr {
    pub hex: String,
}

#[derive(Debug, Deserialize)]
pub struct ScriptPubKey {
    pub scriptPubKey: HexStr,
}

#[derive(Debug, Deserialize)]
pub struct ReceivingVinData {
    pub txid: String,
    pub vout: u32,
    pub scriptSig: String,
    pub txinwitness: String,
    pub prevout: ScriptPubKey,
}

#[derive(Debug, Deserialize)]
pub struct ReceivingDataGiven {
    pub vin: Vec<ReceivingVinData>,
    pub key_material: ReceivingKeyMaterial,
    pub labels: Vec<u32>,
    pub outputs: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct ReceivingDataExpected {
    pub addresses: Vec<String>,
    pub outputs: Vec<OutputWithSignature>,
}

#[derive(Debug, Deserialize)]
pub struct SendingData {
    pub given: SendingDataGiven,
    pub expected: SendingDataExpected,
}

#[derive(Debug, Deserialize)]
pub struct SendingDataGiven {
    pub vin: Vec<SendingVinData>,
    pub recipients: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct SendingVinData {
    pub txid: String,
    pub vout: u32,
    pub scriptSig: String,
    pub txinwitness: String,
    pub prevout: ScriptPubKey,
    pub private_key: String,
}

#[derive(Debug, Deserialize)]
pub struct SendingDataExpected {
    pub outputs: Vec<Vec<String>>,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
pub struct OutputWithSignature {
    pub pub_key: String,
    pub priv_key_tweak: String,
    pub signature: String,
}

#[test]
fn test_sending() {
    let reader =
        BufReader::new(File::open("./tests/testdata/send_and_receive_test_vectors.json").unwrap());
    let tests: Vec<TestData> = serde_json::from_reader(reader).unwrap();
    for (i, test) in tests.iter().enumerate() {
        if test.comment == "Single recipient: taproot input with NUMS point" {
            // SilentPayment API does not allow passing P2TR script path spends - We only support BIP-86
            // Taproot key-path spends.
            continue;
        }
        if test.comment == "P2PKH and P2WPKH Uncompressed Keys are skipped" {
            // We don't support uncompressed keys.
            continue;
        }
        if test.comment == "Skip invalid P2SH inputs" {
            // SilentPayment API does not allow passing invalid P2SH inputs.
            continue;
        }

        for (j, sending_data) in test.sending.iter().enumerate() {
            if sending_data.expected.outputs.len() != 1
                || sending_data.expected.outputs[0].len() != 1
            {
                println!("Skipping test #{}/{}", i, j);
                continue;
            }
            println!("Running test #{}/{} - {}", i, j, test.comment);

            let expected = XOnlyPublicKey::from_str(&sending_data.expected.outputs[0][0]).unwrap();

            // One SP recipient results in one output.
            assert_eq!(sending_data.given.recipients.len(), 1);
            let sp_address = sending_data.given.recipients[0].as_str();

            let mut v = SilentPayment::new(Network::Btc);
            for inp in sending_data.given.vin.iter() {
                let pk_script_hex = inp.prevout.scriptPubKey.hex.as_str();
                let pk_script_bytes = hex::decode(pk_script_hex).unwrap();
                let pk_script = bitcoin::Script::from_bytes(&pk_script_bytes);

                let input_type = if pk_script.is_p2pkh() {
                    InputType::P2pkh
                } else if pk_script.is_p2wpkh() {
                    InputType::P2wpkh
                } else if pk_script.is_p2tr() {
                    let witness: bitcoin::Witness =
                        bitcoin::consensus::deserialize(&hex::decode(&inp.txinwitness).unwrap())
                            .unwrap();
                    // Regular keypath spend. One test case was skipped above (NUMS) which is a
                    // script path spend, which we currently don't support.
                    assert!(witness.len() == 1 && witness.nth(0).unwrap().len() == 64);
                    InputType::P2trKeypathspend
                } else if pk_script.is_p2sh() {
                    panic!("tests don't include p2sh - parse for p2sh-p2wpkh if needed")
                } else {
                    panic!("unreconigzed input")
                };
                v.add_input(
                    input_type,
                    &SecretKey::from_str(&inp.private_key).unwrap(),
                    bitcoin::OutPoint::new(bitcoin::Txid::from_str(&inp.txid).unwrap(), inp.vout),
                )
                .unwrap();
            }

            assert_eq!(v.create_output(sp_address).unwrap(), expected);
        }
    }
}
