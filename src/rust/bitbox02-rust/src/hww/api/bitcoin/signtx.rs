// Copyright 2022 Shift Crypto AG
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

use super::common::format_amount;
use super::payment_request;
use super::script::serialize_varint;
use super::{bip143, bip341, common, keypath};

use crate::workflow::{confirm, status, transaction};
use crate::xpubcache::Bip32XpubCache;

use alloc::vec::Vec;

use pb::request::Request;
use pb::response::Response;

use pb::btc_sign_init_request::FormatUnit;
use pb::btc_sign_next_response::Type as NextType;
use sha2::{Digest, Sha256};

use bitcoin::hashes::Hash;

use streaming_silent_payments::SilentPayment;

/// After each request from the host, we send a `BtcSignNextResponse` response back to the host,
/// containing information which request we want next, and containing additional metadata if
/// available (e.g. a signature after signing an input).
struct NextResponse {
    next: pb::BtcSignNextResponse,
    /// If true, `next` is wrapped in the `BTCResponse` protobuf message, otherwise it is sent
    /// directly in a `Response` message.
    wrap: bool,
}

impl NextResponse {
    fn to_protobuf(&self) -> Response {
        if self.wrap {
            Response::Btc(pb::BtcResponse {
                response: Some(pb::btc_response::Response::SignNext(self.next.clone())),
            })
        } else {
            Response::BtcSignNext(self.next.clone())
        }
    }
}

/// Wait for the next request sent by the host. Since host<->device communication is a
/// request/response pattern, we have to send a response (to the previous request) before getting
/// the next request.
///
/// In BTC signing, the response is always a `BtcSignNextResponse`, but depending on the previous
/// request, it is either a direct response result (hww.proto:Response), or a a result wrapped in a
/// `BTCResponse` (which was introduced latter, hence the messages are scattered). `response.wrap`
/// is set so the next call to this function wraps the response correctly.
///
/// The NextResponse contains information for the host as to which request we need, but also
/// additional results, e.g. a signature after an input is signed. The response is reset to default
/// values after this call so that this additional data is only sent once.
async fn get_request(
    typ: NextType,
    index: u32,
    prev_index: Option<u32>,
    response: &mut NextResponse,
) -> Result<Request, Error> {
    response.next.r#type = typ as _;
    response.next.index = index;
    if let Some(prev_index) = prev_index {
        response.next.prev_index = prev_index;
    }
    let request = crate::hww::next_request(response.to_protobuf()).await?;
    response.next = Default::default();
    Ok(request)
}

async fn get_tx_input(
    index: u32,
    response: &mut NextResponse,
) -> Result<pb::BtcSignInputRequest, Error> {
    let request = get_request(NextType::Input, index, None, response).await?;
    response.wrap = false;
    match request {
        Request::BtcSignInput(request) => Ok(request),
        _ => Err(Error::InvalidState),
    }
}

async fn get_prevtx_init(
    index: u32,
    response: &mut NextResponse,
) -> Result<pb::BtcPrevTxInitRequest, Error> {
    response.next.r#type = NextType::PrevtxInit as _;
    response.next.index = index;
    let request = get_request(NextType::PrevtxInit, index, None, response).await?;
    response.wrap = true;
    match request {
        Request::Btc(pb::BtcRequest {
            request: Some(pb::btc_request::Request::PrevtxInit(request)),
        }) => Ok(request),
        _ => Err(Error::InvalidState),
    }
}

async fn get_prevtx_input(
    input_index: u32,
    prevtx_input_index: u32,
    response: &mut NextResponse,
) -> Result<pb::BtcPrevTxInputRequest, Error> {
    let request = get_request(
        NextType::PrevtxInput,
        input_index,
        Some(prevtx_input_index),
        response,
    )
    .await?;
    response.wrap = true;
    match request {
        Request::Btc(pb::BtcRequest {
            request: Some(pb::btc_request::Request::PrevtxInput(request)),
        }) => Ok(request),
        _ => Err(Error::InvalidState),
    }
}

async fn get_prevtx_output(
    output_index: u32,
    prevtx_output_index: u32,
    response: &mut NextResponse,
) -> Result<pb::BtcPrevTxOutputRequest, Error> {
    let request = get_request(
        NextType::PrevtxOutput,
        output_index,
        Some(prevtx_output_index),
        response,
    )
    .await?;
    response.wrap = true;
    match request {
        Request::Btc(pb::BtcRequest {
            request: Some(pb::btc_request::Request::PrevtxOutput(request)),
        }) => Ok(request),
        _ => Err(Error::InvalidState),
    }
}

async fn get_tx_output(
    index: u32,
    response: &mut NextResponse,
) -> Result<pb::BtcSignOutputRequest, Error> {
    let request = get_request(NextType::Output, index, None, response).await?;
    response.wrap = false;
    match request {
        Request::BtcSignOutput(request) => Ok(request),
        _ => Err(Error::InvalidState),
    }
}

async fn get_payment_request(
    index: u32,
    response: &mut NextResponse,
) -> Result<pb::BtcPaymentRequestRequest, Error> {
    let request = get_request(NextType::PaymentRequest, index, None, response).await?;
    response.wrap = true;
    match request {
        Request::Btc(pb::BtcRequest {
            request: Some(pb::btc_request::Request::PaymentRequest(request)),
        }) => Ok(request),
        _ => Err(Error::InvalidState),
    }
}

async fn get_antiklepto_host_nonce(
    index: u32,
    response: &mut NextResponse,
) -> Result<pb::AntiKleptoSignatureRequest, Error> {
    let request = get_request(NextType::HostNonce, index, None, response).await?;
    response.wrap = true;
    match request {
        Request::Btc(pb::BtcRequest {
            request: Some(pb::btc_request::Request::AntikleptoSignature(request)),
        }) => Ok(request),
        _ => Err(Error::InvalidState),
    }
}

fn validate_keypath(
    params: &super::params::Params,
    script_config_account: &pb::BtcScriptConfigWithKeypath,
    keypath: &[u32],
    mode: keypath::ReceiveSpend,
) -> Result<(), Error> {
    match &script_config_account.script_config {
        Some(pb::BtcScriptConfig {
            config: Some(pb::btc_script_config::Config::SimpleType(simple_type)),
        }) => {
            let simple_type = pb::btc_script_config::SimpleType::try_from(*simple_type)?;
            keypath::validate_address_simple(
                keypath,
                params.bip44_coin,
                simple_type,
                params.taproot_support,
                mode,
            )
            .or(Err(Error::InvalidInput))?;
        }
        Some(pb::BtcScriptConfig {
            config: Some(pb::btc_script_config::Config::Multisig(_)),
        }) => {
            keypath::validate_address_policy(keypath, mode).or(Err(Error::InvalidInput))?;
        }
        Some(pb::BtcScriptConfig {
            config: Some(pb::btc_script_config::Config::Policy(_)),
        }) => {
            keypath::validate_address_policy(keypath, mode).or(Err(Error::InvalidInput))?;
        }
        _ => return Err(Error::InvalidInput),
    }
    // Check that keypath_account is a prefix to keypath with two elements left (change, address).
    if script_config_account.keypath.len() + 2 != keypath.len() {
        return Err(Error::InvalidInput);
    }
    if keypath[..script_config_account.keypath.len()] != script_config_account.keypath {
        return Err(Error::InvalidInput);
    }
    Ok(())
}

fn validate_input(
    input: &pb::BtcSignInputRequest,
    params: &super::params::Params,
    script_config_account: &pb::BtcScriptConfigWithKeypath,
) -> Result<(), Error> {
    if input.prev_out_value == 0 {
        return Err(Error::InvalidInput);
    }
    validate_keypath(
        params,
        script_config_account,
        &input.keypath,
        keypath::ReceiveSpend::Spend,
    )
}

fn is_taproot_bip86(script_config_account: &pb::BtcScriptConfigWithKeypath) -> bool {
    match script_config_account {
        pb::BtcScriptConfigWithKeypath {
            script_config:
                Some(pb::BtcScriptConfig {
                    config: Some(pb::btc_script_config::Config::SimpleType(simple_type)),
                }),
            ..
        } => *simple_type == pb::btc_script_config::SimpleType::P2tr as i32,
        _ => false,
    }
}

fn is_taproot(script_config_account: &pb::BtcScriptConfigWithKeypath) -> bool {
    is_taproot_bip86(script_config_account)
}

/// Generates the subscript (scriptCode without the length prefix) used in the bip143 sighash algo.
///
/// See https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#specification, item 5:
fn sighash_script(
    xpub_cache: &mut Bip32XpubCache,
    script_config_account: &pb::BtcScriptConfigWithKeypath,
    keypath: &[u32],
) -> Result<Vec<u8>, Error> {
    match script_config_account {
        pb::BtcScriptConfigWithKeypath {
            script_config:
                Some(pb::BtcScriptConfig {
                    config: Some(pb::btc_script_config::Config::SimpleType(simple_type)),
                }),
            ..
        } => {
            match pb::btc_script_config::SimpleType::try_from(*simple_type)? {
                pb::btc_script_config::SimpleType::P2wpkhP2sh
                | pb::btc_script_config::SimpleType::P2wpkh => {
                    // See https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#specification, item 5:
                    // > For P2WPKH witness program, the scriptCode is 0x1976a914{20-byte-pubkey-hash}88ac.
                    let pubkey_hash160 = xpub_cache.get_xpub(keypath)?.pubkey_hash160();
                    let mut result = Vec::<u8>::new();
                    result.extend_from_slice(b"\x76\xa9\x14");
                    result.extend_from_slice(&pubkey_hash160);
                    result.extend_from_slice(b"\x88\xac");
                    Ok(result)
                }
                _ => Err(Error::Generic),
            }
        }
        pb::BtcScriptConfigWithKeypath {
            script_config:
                Some(pb::BtcScriptConfig {
                    config: Some(pb::btc_script_config::Config::Multisig(multisig)),
                }),
            ..
        } => Ok(super::multisig::pkscript(
            multisig,
            keypath[keypath.len() - 2],
            keypath[keypath.len() - 1],
        )?),
        pb::BtcScriptConfigWithKeypath {
            script_config:
                Some(pb::BtcScriptConfig {
                    config: Some(pb::btc_script_config::Config::Policy(policy)),
                }),
            ..
        } => super::policies::parse(policy)?.witness_script_at_keypath(keypath),
        _ => Err(Error::InvalidInput),
    }
}

/// Stream an input's previous transaction and verify that the prev_out_hash in the input matches
/// the hash of the previous transaction, as well as that the amount provided in the input is correct.
async fn handle_prevtx(
    input_index: u32,
    input: &pb::BtcSignInputRequest,
    num_inputs: u32,
    progress_component: &mut bitbox02::ui::Component<'_>,
    next_response: &mut NextResponse,
) -> Result<(), Error> {
    let prevtx_init = get_prevtx_init(input_index, next_response).await?;

    if prevtx_init.num_inputs < 1
        || prevtx_init.num_outputs < 1
        || input.prev_out_index >= prevtx_init.num_outputs
    {
        return Err(Error::InvalidInput);
    }

    let mut hasher = Sha256::new();
    hasher.update(prevtx_init.version.to_le_bytes());

    hasher.update(serialize_varint(prevtx_init.num_inputs as u64).as_slice());
    for prevtx_input_index in 0..prevtx_init.num_inputs {
        // Update progress.
        bitbox02::ui::progress_set(progress_component, {
            let step = 1f32 / (num_inputs as f32);
            let subprogress: f32 = (prevtx_input_index as f32)
                / (prevtx_init.num_inputs + prevtx_init.num_outputs) as f32;
            (input_index as f32 + subprogress) * step
        });

        let prevtx_input = get_prevtx_input(input_index, prevtx_input_index, next_response).await?;
        hasher.update(prevtx_input.prev_out_hash.as_slice());
        hasher.update(prevtx_input.prev_out_index.to_le_bytes());
        hasher.update(serialize_varint(prevtx_input.signature_script.len() as u64).as_slice());
        hasher.update(prevtx_input.signature_script.as_slice());
        hasher.update(prevtx_input.sequence.to_le_bytes());
    }

    hasher.update(serialize_varint(prevtx_init.num_outputs as u64).as_slice());
    for prevtx_output_index in 0..prevtx_init.num_outputs {
        // Update progress.
        bitbox02::ui::progress_set(progress_component, {
            let step = 1f32 / (num_inputs as f32);
            let subprogress: f32 = (prevtx_init.num_inputs + prevtx_output_index) as f32
                / (prevtx_init.num_inputs + prevtx_init.num_outputs) as f32;
            (input_index as f32 + subprogress) * step
        });

        let prevtx_output =
            get_prevtx_output(input_index, prevtx_output_index, next_response).await?;
        if prevtx_output_index == input.prev_out_index
            && input.prev_out_value != prevtx_output.value
        {
            return Err(Error::InvalidInput);
        }
        hasher.update(prevtx_output.value.to_le_bytes());
        hasher.update(serialize_varint(prevtx_output.pubkey_script.len() as u64).as_slice());
        hasher.update(prevtx_output.pubkey_script.as_slice());
    }

    hasher.update(prevtx_init.locktime.to_le_bytes());
    // Hash again to produce the final double-hash.
    let hash = Sha256::digest(hasher.finalize());
    if hash.as_slice() != input.prev_out_hash.as_slice() {
        return Err(Error::InvalidInput);
    }
    Ok(())
}

async fn validate_script_configs(
    coin_params: &super::params::Params,
    script_configs: &[pb::BtcScriptConfigWithKeypath],
) -> Result<(), Error> {
    if script_configs.is_empty() {
        return Err(Error::InvalidInput);
    }

    // If there are multiple script configs, only SimpleType (single sig, no additional inputs)
    // configs are allowed, so e.g. mixing p2wpkh and pw2wpkh-p2sh is okay, but mixing p2wpkh with
    // multisig-pw2sh is not.

    // We get multisig out of the way first.

    if let [pb::BtcScriptConfigWithKeypath {
        script_config:
            Some(pb::BtcScriptConfig {
                config: Some(pb::btc_script_config::Config::Multisig(multisig)),
            }),
        keypath,
    }] = script_configs
    {
        super::multisig::validate(multisig, keypath)?;
        let name = super::multisig::get_name(coin_params.coin, multisig, keypath)?
            .ok_or(Error::InvalidInput)?;
        super::multisig::confirm("Spend from", coin_params, &name, multisig).await?;
        return Ok(());
    }

    // Then we get policies out of the way.

    if let [pb::BtcScriptConfigWithKeypath {
        script_config:
            Some(pb::BtcScriptConfig {
                config: Some(pb::btc_script_config::Config::Policy(policy)),
            }),
        keypath: _,
    }] = script_configs
    {
        super::policies::parse(policy)?.validate(coin_params.coin)?;
        let name =
            super::policies::get_name(coin_params.coin, policy)?.ok_or(Error::InvalidInput)?;

        // We could check here that the account keypath matches one of our keys in the policy and
        // abort early, but we don't have to - if the keypath does not match we will fail when
        // processing the first input, where it is checked that the account keypath is a prefix of
        // the input keypath, and the computation of the pk_script checks that full keypath is
        // valid.

        super::policies::confirm(
            "Spend from",
            coin_params,
            &name,
            policy,
            super::policies::Mode::Basic,
        )
        .await?;

        return Ok(());
    }

    for script_config in script_configs.iter() {
        // Only allow simple single sig configs here.
        match script_config {
            pb::BtcScriptConfigWithKeypath {
                script_config:
                    Some(pb::BtcScriptConfig {
                        config: Some(pb::btc_script_config::Config::SimpleType(simple_type)),
                    }),
                keypath,
            } => {
                keypath::validate_account_simple(
                    keypath,
                    coin_params.bip44_coin,
                    pb::btc_script_config::SimpleType::try_from(*simple_type)?,
                    coin_params.taproot_support,
                )
                .or(Err(Error::InvalidInput))?;

                // Check that the bip44 account is the same for all. While we allow mixing input
                // types (bip44 purpose), we do not allow mixing accounts.

                if keypath[2] != script_configs[0].keypath[2] {
                    return Err(Error::InvalidInput);
                }
            }
            _ => return Err(Error::InvalidInput),
        }
    }
    Ok(())
}

// We configure the xpub cache to cache up to change/receive level. If e.g. there is an input/change
// with keypath `m/84'/0'/0'/0/0`, we want the xpub cache to return the xpub at `m/84'/0'/0'/0`, so
// only one child derivation needs to be done for the input/change.
//
// Only xpubs for simple configs (single-sig) are cached - multisig already provides all necessary
// xpubs in the script config itself.
fn setup_xpub_cache(cache: &mut Bip32XpubCache, script_configs: &[pb::BtcScriptConfigWithKeypath]) {
    for script_config in script_configs.iter() {
        match script_config {
            pb::BtcScriptConfigWithKeypath {
                script_config:
                    Some(pb::BtcScriptConfig {
                        config: Some(pb::btc_script_config::Config::SimpleType(_)),
                    }),
                keypath,
            } => {
                let mut receive = keypath.to_vec();
                receive.push(0);
                let mut change = keypath.to_vec();
                change.push(1);
                // Cache xpubs at the receive chain, e.g. m/84'/0'/0'/0.
                cache.add_keypath(&receive);
                // Cache xpubs at change chain, e.g. m/84'/0'/0'/1.
                cache.add_keypath(&change);
                // Also cache xpubs at the account level, e.g. m/84'/0'/0', so that the above two
                // xpubs (change and receive) can reuse the xpub the account-level.
                cache.add_keypath(keypath);
            }
            _ => {
                // We don't need to cache anything for multisig, as there, the xpubs are already
                // provided in the script config.
            }
        }
    }
}

impl TryFrom<pb::BtcCoin> for streaming_silent_payments::Network {
    type Error = Error;
    fn try_from(value: pb::BtcCoin) -> Result<streaming_silent_payments::Network, Self::Error> {
        match value {
            pb::BtcCoin::Btc => Ok(streaming_silent_payments::Network::Btc),
            pb::BtcCoin::Tbtc => Ok(streaming_silent_payments::Network::Tbtc),
            _ => Err(Error::InvalidInput),
        }
    }
}

impl From<pb::btc_script_config::SimpleType> for streaming_silent_payments::InputType {
    fn from(value: pb::btc_script_config::SimpleType) -> streaming_silent_payments::InputType {
        match value {
            pb::btc_script_config::SimpleType::P2wpkhP2sh => {
                streaming_silent_payments::InputType::P2wpkhP2sh
            }
            pb::btc_script_config::SimpleType::P2wpkh => {
                streaming_silent_payments::InputType::P2wpkh
            }
            pb::btc_script_config::SimpleType::P2tr => {
                streaming_silent_payments::InputType::P2trKeypathspend
            }
        }
    }
}

impl TryFrom<&pb::BtcScriptConfigWithKeypath> for streaming_silent_payments::InputType {
    type Error = Error;
    fn try_from(
        value: &pb::BtcScriptConfigWithKeypath,
    ) -> Result<streaming_silent_payments::InputType, Self::Error> {
        match value {
            pb::BtcScriptConfigWithKeypath {
                script_config:
                    Some(pb::BtcScriptConfig {
                        config: Some(pb::btc_script_config::Config::SimpleType(simple_type)),
                    }),
                ..
            } => {
                let simple_type = pb::btc_script_config::SimpleType::try_from(*simple_type)?;
                Ok(simple_type.into())
            }
            _ => Err(Error::InvalidInput),
        }
    }
}

/// Singing flow:
///
/// init
/// for each input:
///    inputs_pass1
///    prevtx init
///    for each prevtx input:
///        prevtx inputs
///    for each prevtx output:
///        prevtx outputs
/// for each output:
///    outputs
/// for each input:
///    inputs_pass2
///    if input contains a host nonce commitment, the anti-klepto protocol is active:
///       inputs_pass2_antiklepto_host_nonce
///
/// The hash_prevout and hash_sequence and total_in are accumulated in inputs_pass1.
///
/// For each input in pass1, the input's prevtx is streamed to compute and compare the prevOutHash
/// and input amount. This only happens if the script_configs in the init request contain
/// non-taproot (legacy and v0 segwit) configs. If all inputs are taproot, this step is not needed
/// as the input amounts and pubkey scripts are committed to in the signature hash. With
/// SIGHASH_ALL/SIGHASH_DEFAULT, it would technically be enough if there was only one taproot input
/// to skip streaming the previous transactions, even if there are non-taproot inputs (every input
/// commits to the taproot inputs presence, and the taproot input commits to all amounts and pubkey
/// scripts), but we only skip streaming previous transactions if all inputs are taproot, for
/// simplicity.
///
/// For each output, the recipient is confirmed. At the last output, the total out, fee, locktime/RBF
/// are confirmed.
///
/// The inputs are signed in inputs_pass2.
///
/// IMPORTANT assumptions:
///
/// - In the 2nd pass, if the inputs provided by the host are not the same as in the 1st pass,
///   nothing bad will happen because the sighash uses the prevout and sequence hashes from the first
///   pass, and the value from the 2nd pass. The BTC consensus rules will reject the tx if there is a
///   mismatch.
///
/// - Only SIGHASH_ALL (SIGHASH_DEFAULT in taproot inputs). Other sighash types must be carefully
///   studied and might not be secure with the above flow or the above assumption.
async fn _process(request: &pb::BtcSignInitRequest) -> Result<Response, Error> {
    if bitbox02::keystore::is_locked() {
        return Err(Error::InvalidState);
    }
    // Validate the coin.
    let coin = pb::BtcCoin::try_from(request.coin)?;
    let coin_params = super::params::get(coin);
    // Validate the format_unit.
    let format_unit = FormatUnit::try_from(request.format_unit)?;
    // Currently we do not support time-based nlocktime
    if request.locktime >= 500000000 {
        return Err(Error::InvalidInput);
    }
    // Currently only support version 1 or version 2 tx.
    // Version 2: https://github.com/bitcoin/bips/blob/master/bip-0068.mediawiki
    if request.version != 1 && request.version != 2 {
        return Err(Error::InvalidInput);
    }
    if request.num_inputs < 1 || request.num_outputs < 1 {
        return Err(Error::InvalidInput);
    }
    validate_script_configs(coin_params, &request.script_configs).await?;

    let mut xpub_cache = Bip32XpubCache::new();
    setup_xpub_cache(&mut xpub_cache, &request.script_configs);

    // For now we only allow one payment request with one output per transaction.  In the future,
    // this could be extended to allow multiple outputs per payment request (payment request
    // requests payout to multiple addresses/outputs), as well as multiple payment requests per
    // transaction.
    let mut payment_request_seen = false;

    let mut progress_component = {
        let mut c = bitbox02::ui::progress_create("Loading transaction...");
        c.screen_stack_push();
        Some(c)
    };

    let mut next_response = NextResponse {
        next: Default::default(),
        wrap: false,
    };

    // Will contain the sum of all spent output values in the first inputs pass.
    let mut inputs_sum_pass1: u64 = 0;

    let mut locktime_applies: bool = false;
    let mut rbf: bool = false;

    let mut hasher_prevouts = Sha256::new();
    let mut hasher_sequence = Sha256::new();
    let mut hasher_amounts = Sha256::new();
    let mut hasher_scriptpubkeys = Sha256::new();

    // Are all inputs taproot?
    let taproot_only = request.script_configs.iter().all(is_taproot);

    let mut silent_payment = if request.contains_silent_payment_outputs {
        Some(SilentPayment::new(coin.try_into()?))
    } else {
        None
    };

    for input_index in 0..request.num_inputs {
        // Update progress.
        bitbox02::ui::progress_set(
            progress_component.as_mut().unwrap(),
            (input_index as f32) / (request.num_inputs as f32),
        );

        let tx_input = get_tx_input(input_index, &mut next_response).await?;
        let script_config_account = request
            .script_configs
            .get(tx_input.script_config_index as usize)
            .ok_or(Error::InvalidInput)?;
        validate_input(&tx_input, coin_params, script_config_account)?;
        if tx_input.sequence < 0xffffffff - 1 {
            rbf = true;
        }
        if tx_input.sequence < 0xffffffff {
            locktime_applies = true;
        }
        inputs_sum_pass1 = inputs_sum_pass1
            .checked_add(tx_input.prev_out_value)
            .ok_or(Error::InvalidInput)?;

        // https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
        // point 2: accumulate hashPrevouts
        // ANYONECANPAY not supported.
        hasher_prevouts.update(tx_input.prev_out_hash.as_slice());
        hasher_prevouts.update(tx_input.prev_out_index.to_le_bytes());

        // https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
        // point 3: accumulate hashSequence
        // only SIGHASH_ALL supported.
        hasher_sequence.update(tx_input.sequence.to_le_bytes());

        // https://github.com/bitcoin/bips/blob/bb8dc57da9b3c6539b88378348728a2ff43f7e9c/bip-0341.mediawiki#common-signature-message
        // accumulate `sha_amounts`
        hasher_amounts.update(tx_input.prev_out_value.to_le_bytes());

        // https://github.com/bitcoin/bips/blob/bb8dc57da9b3c6539b88378348728a2ff43f7e9c/bip-0341.mediawiki#common-signature-message
        // accumulate `sha_scriptpubkeys`
        let pk_script = common::Payload::from(
            &mut xpub_cache,
            coin_params,
            &tx_input.keypath,
            script_config_account,
        )?
        .pk_script(coin_params)?;
        hasher_scriptpubkeys.update(serialize_varint(pk_script.len() as u64).as_slice());
        hasher_scriptpubkeys.update(pk_script.as_slice());

        if !taproot_only {
            handle_prevtx(
                input_index,
                &tx_input,
                request.num_inputs,
                progress_component.as_mut().unwrap(),
                &mut next_response,
            )
            .await?;
        }

        if let Some(ref mut silent_payment) = silent_payment {
            let private_key = bitcoin::secp256k1::SecretKey::from_slice(
                &bitbox02::keystore::secp256k1_get_private_key(
                    &tx_input.keypath,
                    is_taproot(script_config_account),
                )?,
            )
            .map_err(|_| Error::Generic)?;

            silent_payment
                .add_input(
                    script_config_account.try_into()?,
                    &private_key,
                    bitcoin::OutPoint::new(
                        bitcoin::Txid::from_slice(&tx_input.prev_out_hash)
                            .map_err(|_| Error::InvalidInput)?,
                        tx_input.prev_out_index,
                    ),
                )
                .map_err(|_| Error::InvalidInput)?;
        }
    }

    // The progress for loading the inputs is 100%.
    bitbox02::ui::progress_set(progress_component.as_mut().unwrap(), 1.);

    let hash_prevouts = hasher_prevouts.finalize();
    let hash_sequence = hasher_sequence.finalize();
    let hash_amounts = hasher_amounts.finalize();
    let hash_scriptpubkeys = hasher_scriptpubkeys.finalize();

    // Base component on the screen stack during signing, which is shown while the device is waiting
    // for the next signing api call. Without this, the 'See the BitBoxApp' waiting screen would
    // flicker in between user confirmations. All user input happens during output processing.
    //
    // We only start rendering this (and stop rendering the inputs progress bar) after we receive
    // the first output, otherwise there is a noticable delay between processing the last input and
    // receiving the first output.
    let mut empty_component = None;

    // Will contain the sum of all our output values (change or receive to self).
    let mut outputs_sum_ours: u64 = 0;
    // Will contain the sum of all outgoing output values (non-change outputs).
    let mut outputs_sum_out: u64 = 0;

    let mut num_changes: u32 = 0;

    let mut hasher_outputs = Sha256::new();
    for output_index in 0..request.num_outputs {
        let tx_output = get_tx_output(output_index, &mut next_response).await?;
        if output_index == 0 {
            // Stop rendering inputs progress update.
            drop(progress_component.take());

            empty_component = {
                let mut c = bitbox02::ui::empty_create();
                c.screen_stack_push();
                Some(c)
            };
        }

        if tx_output.value == 0 {
            return Err(Error::InvalidInput);
        }

        let output_type = pb::BtcOutputType::try_from(tx_output.r#type)?;

        // Get payload. If the output is marked ours, we compute the payload from the keystore,
        // otherwise it is provided in tx_output.payload.
        let payload: common::Payload = if tx_output.ours {
            // Compute the payload from the keystore.
            let script_config_account = request
                .script_configs
                .get(tx_output.script_config_index as usize)
                .ok_or(Error::InvalidInput)?;

            validate_keypath(
                coin_params,
                script_config_account,
                &tx_output.keypath,
                keypath::ReceiveSpend::Receive,
            )?;

            common::Payload::from(
                &mut xpub_cache,
                coin_params,
                &tx_output.keypath,
                script_config_account,
            )?
        } else {
            // Take payload from provided output.

            // Create silent payment output.
            if let Some(output_silent_payment) = tx_output.silent_payment.as_ref() {
                match silent_payment {
                    None => return Err(Error::InvalidInput),
                    Some(ref mut silent_payment) => {
                        if output_type != pb::BtcOutputType::P2tr {
                            return Err(Error::InvalidInput);
                        }
                        let xonly = silent_payment
                            .create_output(&output_silent_payment.address)
                            .map_err(|_| Error::InvalidInput)?;
                        let payload = common::Payload {
                            data: xonly.serialize().to_vec(),
                            output_type,
                        };
                        next_response.next.generated_output_pkscript =
                            payload.pk_script(coin_params)?;
                        payload
                    }
                }
            } else {
                common::Payload {
                    data: tx_output.payload.clone(),
                    output_type,
                }
            }
        };

        let is_change = if tx_output.ours {
            let script_config_account = request
                .script_configs
                .get(tx_output.script_config_index as usize)
                .ok_or(Error::InvalidInput)?;

            match &script_config_account.script_config {
                // Policy.
                Some(pb::BtcScriptConfig {
                    config: Some(pb::btc_script_config::Config::Policy(policy)),
                }) => super::policies::parse(policy)?.is_change_keypath(&tx_output.keypath)?,
                // Everything else.
                _ => {
                    let change = tx_output.keypath[tx_output.keypath.len() - 2];
                    change == 1
                }
            }
        } else {
            false
        };

        // Only non-change outputs can belong to a payment request.
        if is_change && tx_output.payment_request_index.is_some() {
            return Err(Error::InvalidInput);
        }

        if is_change && tx_output.silent_payment.is_some() {
            return Err(Error::InvalidInput);
        }

        if !is_change {
            // Verify output if it is not a change output.
            // Assemble address to display, get user confirmation.
            let address = if let Some(sp) = tx_output.silent_payment.as_ref() {
                sp.address.clone()
            } else {
                payload.address(coin_params)?
            };

            if let Some(output_payment_request_index) = tx_output.payment_request_index {
                if output_payment_request_index != 0 {
                    return Err(Error::InvalidInput);
                }
                if payment_request_seen {
                    return Err(Error::InvalidInput);
                }
                let payment_request: pb::BtcPaymentRequestRequest =
                    get_payment_request(output_payment_request_index, &mut next_response).await?;
                payment_request::user_verify(coin_params, &payment_request, format_unit).await?;
                if payment_request::validate(
                    coin_params,
                    &payment_request,
                    tx_output.value,
                    &address,
                )
                .is_err()
                {
                    status::status("Invalid\npayment request", true).await;
                    return Err(Error::InvalidInput);
                }

                payment_request_seen = true;
            } else {
                transaction::verify_recipient(
                    &(if tx_output.ours {
                        format!("This BitBox02: {}", address)
                    } else {
                        address
                    }),
                    &format_amount(coin_params, format_unit, tx_output.value)?,
                )
                .await?;
            }
        }

        if is_change {
            num_changes += 1;
            outputs_sum_ours = outputs_sum_ours
                .checked_add(tx_output.value)
                .ok_or(Error::InvalidInput)?;
        } else {
            outputs_sum_out = outputs_sum_out
                .checked_add(tx_output.value)
                .ok_or(Error::InvalidInput)?;
        }

        // https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
        // point 8: accumulate hashOutputs
        // only SIGHASH_ALL supported.
        hasher_outputs.update(tx_output.value.to_le_bytes());
        let pk_script = payload.pk_script(coin_params)?;
        hasher_outputs.update(serialize_varint(pk_script.len() as u64).as_slice());
        hasher_outputs.update(pk_script.as_slice());
    }

    if num_changes > 1 {
        confirm::confirm(&confirm::Params {
            title: "Warning",
            body: &format!("There are {}\nchange outputs.\nProceed?", num_changes),
            accept_is_nextarrow: true,
            ..Default::default()
        })
        .await?;
    }

    // Verify locktime/rbf.
    // A locktime of 0 will also not be verified, as it's certainly in the past and can't do any
    // harm.
    //
    // This is not a security feature, the extra locktime/RBF user confirmation is skipped if the tx
    // is not rbf or has a locktime of 0.
    if request.locktime > 0 && locktime_applies {
        // The RBF nsequence bytes are often set in conjunction with a locktime,
        // so verify both simultaneously.
        confirm::confirm(&confirm::Params {
            body: &format!(
                "Locktime on block:\n{}\n{}",
                request.locktime,
                if coin_params.rbf_support {
                    if rbf {
                        "Transaction is RBF"
                    } else {
                        "Transaction is not RBF"
                    }
                } else {
                    // There is no RBF in Litecoin.
                    ""
                }
            ),
            accept_is_nextarrow: true,
            ..Default::default()
        })
        .await?;
    }

    // Total out, including fee.
    let total_out: u64 = inputs_sum_pass1
        .checked_sub(outputs_sum_ours)
        .ok_or(Error::InvalidInput)?;
    let fee: u64 = total_out
        .checked_sub(outputs_sum_out)
        .ok_or(Error::InvalidInput)?;
    let fee_percentage: Option<f64> = if outputs_sum_out == 0 {
        None
    } else {
        Some(100. * (fee as f64) / (outputs_sum_out as f64))
    };
    transaction::verify_total_fee(
        &format_amount(coin_params, format_unit, total_out)?,
        &format_amount(coin_params, format_unit, fee)?,
        fee_percentage,
    )
    .await?;
    status::status("Transaction\nconfirmed", true).await;

    let hash_outputs = hasher_outputs.finalize();

    // Stop rendering the empty component.
    drop(empty_component);

    // Show progress of signing inputs if there are more than 2 inputs. This is an arbitrary cutoff;
    // less or equal to 2 inputs is fast enough so it does not need a progress bar.
    let mut progress_component = if request.num_inputs > 2 {
        let mut c = bitbox02::ui::progress_create("Signing transaction...");
        c.screen_stack_push();
        Some(c)
    } else {
        None
    };

    // Will contain the sum of all spent output values in the second inputs pass.
    let mut inputs_sum_pass2: u64 = 0;
    for input_index in 0..request.num_inputs {
        let tx_input = get_tx_input(input_index, &mut next_response).await?;
        let script_config_account = request
            .script_configs
            .get(tx_input.script_config_index as usize)
            .ok_or(Error::InvalidInput)?;
        validate_input(&tx_input, coin_params, script_config_account)?;

        inputs_sum_pass2 = inputs_sum_pass2
            .checked_add(tx_input.prev_out_value)
            .ok_or(Error::InvalidInput)?;
        if inputs_sum_pass2 > inputs_sum_pass1 {
            return Err(Error::InvalidInput);
        }

        if is_taproot(script_config_account) {
            // This is a taproot (P2TR) input.

            // Anti-Klepto protocol not supported yet for Schnorr signatures.
            if tx_input.host_nonce_commitment.is_some() {
                return Err(Error::InvalidInput);
            }

            let sighash = bip341::sighash(&bip341::Args {
                version: request.version,
                locktime: request.locktime,
                hash_prevouts: hash_prevouts.as_slice().try_into().unwrap(),
                hash_amounts: hash_amounts.as_slice().try_into().unwrap(),
                hash_scriptpubkeys: hash_scriptpubkeys.as_slice().try_into().unwrap(),
                hash_sequences: hash_sequence.as_slice().try_into().unwrap(),
                hash_outputs: hash_outputs.as_slice().try_into().unwrap(),
                input_index,
            });
            next_response.next.has_signature = true;
            next_response.next.signature =
                bitbox02::keystore::secp256k1_schnorr_bip86_sign(&tx_input.keypath, &sighash)?
                    .to_vec();
        } else {
            // Sign all other supported inputs.

            const SIGHASH_ALL: u32 = 0x01;
            let sighash = bip143::sighash(&bip143::Args {
                version: request.version,
                hash_prevouts: Sha256::digest(hash_prevouts).into(),
                hash_sequence: Sha256::digest(hash_sequence).into(),
                outpoint_hash: tx_input.prev_out_hash.as_slice().try_into().unwrap(),
                outpoint_index: tx_input.prev_out_index,
                sighash_script: &sighash_script(
                    &mut xpub_cache,
                    script_config_account,
                    &tx_input.keypath,
                )?,
                prevout_value: tx_input.prev_out_value,
                sequence: tx_input.sequence,
                hash_outputs: Sha256::digest(hash_outputs).into(),
                locktime: request.locktime,
                sighash_flags: SIGHASH_ALL,
            });

            // Engage in the Anti-Klepto protocol if the host sends a host nonce commitment.
            let host_nonce: [u8; 32] = match tx_input.host_nonce_commitment {
                Some(pb::AntiKleptoHostNonceCommitment { ref commitment }) => {
                    let signer_commitment = bitbox02::keystore::secp256k1_nonce_commit(
                        &tx_input.keypath,
                        &sighash,
                        commitment
                            .as_slice()
                            .try_into()
                            .or(Err(Error::InvalidInput))?,
                    )?;
                    next_response.next.anti_klepto_signer_commitment =
                        Some(pb::AntiKleptoSignerCommitment {
                            commitment: signer_commitment.to_vec(),
                        });

                    get_antiklepto_host_nonce(input_index, &mut next_response)
                        .await?
                        .host_nonce
                        .as_slice()
                        .try_into()
                        .or(Err(Error::InvalidInput))?
                }
                // Return signature directly without the anti-klepto protocol, for backwards compatibility.
                None => [0; 32],
            };

            let sign_result =
                bitbox02::keystore::secp256k1_sign(&tx_input.keypath, &sighash, &host_nonce)?;
            next_response.next.has_signature = true;
            next_response.next.signature = sign_result.signature.to_vec();
        }

        // Update progress.
        if let Some(ref mut c) = progress_component {
            bitbox02::ui::progress_set(c, (input_index + 1) as f32 / (request.num_inputs as f32));
        }
    }

    if inputs_sum_pass1 != inputs_sum_pass2 {
        return Err(Error::InvalidInput);
    }

    next_response.next.r#type = NextType::Done as _;
    Ok(next_response.to_protobuf())
}

pub async fn process(request: &pb::BtcSignInitRequest) -> Result<Response, Error> {
    let result = _process(request).await;
    if let Err(Error::UserAbort) = result {
        status::status("Transaction\ncanceled", false).await;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bb02_async::block_on;
    use crate::bip32::parse_xpub;
    use alloc::boxed::Box;
    use bitbox02::testing::{mock, mock_memory, mock_unlocked, mock_unlocked_using_mnemonic, Data};
    use pb::btc_payment_request_request::{memo, Memo};
    use util::bip32::HARDENED;

    fn extract_next(response: &Response) -> &pb::BtcSignNextResponse {
        match response {
            Response::BtcSignNext(next) => next,
            Response::Btc(pb::BtcResponse {
                response: Some(pb::btc_response::Response::SignNext(next)),
            }) => next,
            _ => panic!("wrong response type"),
        }
    }

    struct TxInput {
        input: pb::BtcSignInputRequest,
        prevtx_version: u32,
        prevtx_inputs: Vec<pb::BtcPrevTxInputRequest>,
        prevtx_outputs: Vec<pb::BtcPrevTxOutputRequest>,
        prevtx_locktime: u32,
        host_nonce: Option<Vec<u8>>,
    }

    struct Transaction {
        coin: pb::BtcCoin,
        // How many dialogs the user has to confirm in the test transaction
        total_confirmations: u32,
        version: u32,
        inputs: Vec<TxInput>,
        outputs: Vec<pb::BtcSignOutputRequest>,
        locktime: u32,
        payment_request: Option<pb::BtcPaymentRequestRequest>,
    }

    impl Transaction {
        /// An arbitrary test transaction with some inputs and outputs.
        fn new(coin: pb::BtcCoin) -> Self {
            let bip44_coin = super::super::params::get(coin).bip44_coin;
            Transaction {
                coin,
                total_confirmations: 6,
                version: 1,
                inputs: vec![
                    TxInput {
                        input: pb::BtcSignInputRequest {
                            prev_out_hash: vec![
                                0x45, 0x17, 0x74, 0x50, 0x1b, 0xaf, 0xdf, 0xf7, 0x46, 0x9, 0xe,
                                0x6, 0x16, 0xd9, 0x5e, 0xd0, 0x80, 0xd7, 0x82, 0x9a, 0xfe, 0xa2,
                                0xbd, 0x97, 0x8a, 0xf8, 0x11, 0xf4, 0x5e, 0x43, 0x81, 0x39,
                            ],
                            prev_out_index: 1,
                            prev_out_value: 1010000000,
                            sequence: 0xffffffff,
                            keypath: vec![84 + HARDENED, bip44_coin, 10 + HARDENED, 0, 5],
                            script_config_index: 0,
                            host_nonce_commitment: None,
                        },
                        prevtx_version: 1,
                        prevtx_inputs: vec![
                            pb::BtcPrevTxInputRequest {
                                prev_out_hash: vec![
                                    0x74, 0x74, 0x74, 0x74, 0x74, 0x74, 0x74, 0x74, 0x74, 0x74,
                                    0x74, 0x74, 0x74, 0x74, 0x74, 0x74, 0x74, 0x74, 0x74, 0x74,
                                    0x74, 0x74, 0x74, 0x74, 0x74, 0x74, 0x74, 0x74, 0x74, 0x74,
                                    0x74, 0x74,
                                ],
                                prev_out_index: 3,
                                signature_script: b"signature script".to_vec(),
                                sequence: 0xffffffff - 2,
                            },
                            pb::BtcPrevTxInputRequest {
                                prev_out_hash: vec![
                                    0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75,
                                    0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75,
                                    0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75,
                                    0x75, 0x75,
                                ],
                                prev_out_index: 23,
                                signature_script: b"signature script 2".to_vec(),
                                sequence: 123456,
                            },
                        ],
                        prevtx_outputs: vec![
                            pb::BtcPrevTxOutputRequest {
                                value: 101000000, // btc 1.01
                                pubkey_script: b"pubkey script".to_vec(),
                            },
                            pb::BtcPrevTxOutputRequest {
                                value: 1010000000, // btc 10.1
                                pubkey_script: b"pubkey script 2".to_vec(),
                            },
                        ],
                        prevtx_locktime: 0,
                        host_nonce: None,
                    },
                    TxInput {
                        input: pb::BtcSignInputRequest {
                            prev_out_hash: vec![
                                0x40, 0x9b, 0x4f, 0x56, 0xca, 0x9f, 0x6, 0xcb, 0x88, 0x28, 0x3,
                                0xad, 0x55, 0x4b, 0xeb, 0x1d, 0x9e, 0xf8, 0x78, 0x7, 0xf0, 0x52,
                                0x29, 0xe7, 0x55, 0x15, 0xe4, 0xb2, 0xaa, 0x87, 0x69, 0x1d,
                            ],
                            prev_out_index: 0,
                            prev_out_value: 1020000000, // btc 10.2, matches prevout tx output at index 0.
                            sequence: 0xffffffff,
                            keypath: vec![84 + HARDENED, bip44_coin, 10 + HARDENED, 0, 7],
                            script_config_index: 0,
                            host_nonce_commitment: None,
                        },
                        prevtx_version: 2,
                        prevtx_inputs: vec![pb::BtcPrevTxInputRequest {
                            prev_out_hash: vec![
                                0x74, 0x74, 0x74, 0x74, 0x74, 0x74, 0x74, 0x74, 0x74, 0x74, 0x74,
                                0x74, 0x74, 0x74, 0x74, 0x74, 0x74, 0x74, 0x74, 0x74, 0x74, 0x74,
                                0x74, 0x74, 0x74, 0x74, 0x74, 0x74, 0x74, 0x74, 0x74, 0x74,
                            ],
                            prev_out_index: 3,
                            signature_script: b"signature script".to_vec(),
                            sequence: 0xffffffff - 2,
                        }],
                        prevtx_outputs: vec![pb::BtcPrevTxOutputRequest {
                            value: 1020000000, // btc 10.2
                            pubkey_script: b"pubkey script".to_vec(),
                        }],
                        prevtx_locktime: 87654,
                        host_nonce: None,
                    },
                ],
                outputs: vec![
                    pb::BtcSignOutputRequest {
                        ours: false,
                        r#type: pb::BtcOutputType::P2pkh as _,
                        value: 100000000, // btc 1,
                        payload: vec![
                            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                        ],
                        ..Default::default()
                    },
                    pb::BtcSignOutputRequest {
                        ours: false,
                        r#type: pb::BtcOutputType::P2sh as _,
                        value: 1234567890, // btc 12.3456789,
                        payload: vec![
                            0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
                            0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
                        ],
                        ..Default::default()
                    },
                    pb::BtcSignOutputRequest {
                        ours: false,
                        r#type: pb::BtcOutputType::P2wpkh as _,
                        value: 6000, // btc .00006
                        payload: vec![
                            0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
                            0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
                        ],
                        ..Default::default()
                    },
                    pb::BtcSignOutputRequest {
                        ours: false,
                        r#type: pb::BtcOutputType::P2wsh as _,
                        value: 7000, // btc .00007
                        payload: vec![
                            0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
                            0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
                            0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
                        ],
                        ..Default::default()
                    },
                    pb::BtcSignOutputRequest {
                        // change
                        ours: true,
                        r#type: 0,
                        value: 690000000, // btc 6.9
                        keypath: vec![84 + HARDENED, bip44_coin, 10 + HARDENED, 1, 3],
                        ..Default::default()
                    },
                    pb::BtcSignOutputRequest {
                        // change #2
                        ours: true,
                        r#type: 0,
                        value: 100,
                        keypath: vec![84 + HARDENED, bip44_coin, 10 + HARDENED, 1, 30],
                        ..Default::default()
                    },
                ],
                locktime: 0,
                payment_request: None,
            }
        }

        /// An arbitrary multisig test transaction with some inputs and outputs.
        fn new_multisig() -> Self {
            let coin = pb::BtcCoin::Tbtc;
            let bip44_coin = super::super::params::get(coin).bip44_coin;
            Transaction {
                coin,
                total_confirmations: 5,
                version: 2,
                inputs: vec![TxInput {
                    input: pb::BtcSignInputRequest {
                        prev_out_hash: vec![
                            0x41, 0x3b, 0x8e, 0x74, 0x05, 0x15, 0x96, 0x6b, 0x20, 0x2b, 0x24, 0xc3,
                            0x19, 0xfc, 0xf3, 0x5f, 0xc5, 0x37, 0x6e, 0xb2, 0x71, 0x95, 0xb8, 0x76,
                            0x62, 0x9a, 0x44, 0x1d, 0x19, 0xaa, 0x6c, 0x0f,
                        ],
                        prev_out_index: 0,
                        prev_out_value: 100000, // btc 0.001
                        sequence: 0xffffffff - 1,
                        keypath: vec![48 + HARDENED, bip44_coin, 0 + HARDENED, 2 + HARDENED, 0, 0],
                        script_config_index: 0,
                        host_nonce_commitment: None,
                    },
                    prevtx_version: 1,
                    prevtx_inputs: vec![pb::BtcPrevTxInputRequest {
                        prev_out_hash: vec![
                            0x74, 0x74, 0x74, 0x74, 0x74, 0x74, 0x74, 0x74, 0x74, 0x74, 0x74, 0x74,
                            0x74, 0x74, 0x74, 0x74, 0x74, 0x74, 0x74, 0x74, 0x74, 0x74, 0x74, 0x74,
                            0x74, 0x74, 0x74, 0x74, 0x74, 0x74, 0x74, 0x74,
                        ],
                        prev_out_index: 3,
                        signature_script: b"signature script".to_vec(),
                        sequence: 0xffffffff - 2,
                    }],
                    prevtx_outputs: vec![pb::BtcPrevTxOutputRequest {
                        value: 100000, // btc 0.001
                        pubkey_script: b"pubkey script".to_vec(),
                    }],
                    prevtx_locktime: 0,
                    host_nonce: None,
                }],
                outputs: vec![
                    pb::BtcSignOutputRequest {
                        ours: true,
                        r#type: pb::BtcOutputType::Unknown as _,
                        value: 9825, // btc 0.00009825
                        keypath: vec![48 + HARDENED, bip44_coin, 0 + HARDENED, 2 + HARDENED, 1, 0],
                        ..Default::default()
                    },
                    pb::BtcSignOutputRequest {
                        ours: false,
                        r#type: pb::BtcOutputType::P2wsh as _,
                        value: 90000, // btc 0.0009
                        payload: vec![
                            0x59, 0x88, 0x02, 0x4d, 0x26, 0x74, 0x2c, 0x74, 0xd1, 0x1c, 0x3b, 0x28,
                            0x83, 0xe7, 0x57, 0x84, 0x67, 0x25, 0xa3, 0xf6, 0x23, 0xae, 0xc2, 0x09,
                            0x76, 0xd3, 0x0e, 0x29, 0xb0, 0xd4, 0xb3, 0x5b,
                        ],
                        ..Default::default()
                    },
                ],
                locktime: 1663289,
                payment_request: None,
            }
        }

        /// An arbitrary policy test transaction with some inputs and outputs.
        fn new_policy() -> Self {
            let mut tx = Self::new_multisig();
            tx.total_confirmations = 9;
            let bip44_coin = super::super::params::get(tx.coin).bip44_coin;
            tx.inputs[0].input.keypath =
                vec![48 + HARDENED, bip44_coin, 0 + HARDENED, 3 + HARDENED, 0, 0];
            tx.outputs[0].keypath =
                vec![48 + HARDENED, bip44_coin, 0 + HARDENED, 3 + HARDENED, 1, 0];
            tx
        }

        fn init_request(&self) -> pb::BtcSignInitRequest {
            pb::BtcSignInitRequest {
                coin: self.coin as _,
                script_configs: vec![pb::BtcScriptConfigWithKeypath {
                    script_config: Some(pb::BtcScriptConfig {
                        config: Some(pb::btc_script_config::Config::SimpleType(
                            pb::btc_script_config::SimpleType::P2wpkh as _,
                        )),
                    }),
                    keypath: vec![
                        84 + HARDENED,
                        super::super::params::get(self.coin).bip44_coin,
                        10 + HARDENED,
                    ],
                }],
                version: self.version,
                num_inputs: self.inputs.len() as _,
                num_outputs: self.outputs.len() as _,
                locktime: self.locktime,
                format_unit: FormatUnit::Default as _,
                contains_silent_payment_outputs: self
                    .outputs
                    .iter()
                    .any(|output| output.silent_payment.is_some()),
            }
        }

        fn init_request_policy(
            &self,
            policy: pb::btc_script_config::Policy,
            keypath_account: &[u32],
        ) -> pb::BtcSignInitRequest {
            pb::BtcSignInitRequest {
                coin: self.coin as _,
                script_configs: vec![pb::BtcScriptConfigWithKeypath {
                    script_config: Some(pb::BtcScriptConfig {
                        config: Some(pb::btc_script_config::Config::Policy(policy)),
                    }),
                    keypath: keypath_account.to_vec(),
                }],
                version: self.version,
                num_inputs: self.inputs.len() as _,
                num_outputs: self.outputs.len() as _,
                locktime: self.locktime,
                format_unit: FormatUnit::Default as _,
                contains_silent_payment_outputs: false,
            }
        }

        /// Return the transaction part requested by the device.
        fn make_host_request(&self, response: Response) -> Request {
            let next = extract_next(&response);
            match NextType::try_from(next.r#type).unwrap() {
                NextType::Input => {
                    Request::BtcSignInput(self.inputs[next.index as usize].input.clone())
                }
                NextType::Output => {
                    Request::BtcSignOutput(self.outputs[next.index as usize].clone())
                }
                NextType::PaymentRequest => Request::Btc(pb::BtcRequest {
                    request: Some(pb::btc_request::Request::PaymentRequest(
                        self.payment_request.clone().unwrap(),
                    )),
                }),
                NextType::PrevtxInit => Request::Btc(pb::BtcRequest {
                    request: Some(pb::btc_request::Request::PrevtxInit(
                        pb::BtcPrevTxInitRequest {
                            version: self.inputs[next.index as usize].prevtx_version,
                            num_inputs: self.inputs[next.index as usize].prevtx_inputs.len() as _,
                            num_outputs: self.inputs[next.index as usize].prevtx_outputs.len() as _,
                            locktime: self.inputs[next.index as usize].prevtx_locktime,
                        },
                    )),
                }),
                NextType::PrevtxInput => Request::Btc(pb::BtcRequest {
                    request: Some(pb::btc_request::Request::PrevtxInput(
                        self.inputs[next.index as usize].prevtx_inputs[next.prev_index as usize]
                            .clone(),
                    )),
                }),
                NextType::PrevtxOutput => Request::Btc(pb::BtcRequest {
                    request: Some(pb::btc_request::Request::PrevtxOutput(
                        self.inputs[next.index as usize].prevtx_outputs[next.prev_index as usize]
                            .clone(),
                    )),
                }),
                NextType::HostNonce => Request::Btc(pb::BtcRequest {
                    request: Some(pb::btc_request::Request::AntikleptoSignature(
                        pb::AntiKleptoSignatureRequest {
                            host_nonce: self.inputs[next.index as usize]
                                .host_nonce
                                .as_ref()
                                .expect("need host_nonce")
                                .clone(),
                        },
                    )),
                }),
                _ => panic!("unexpected next response"),
            }
        }
    }

    fn mock_host_responder(tx: alloc::rc::Rc<core::cell::RefCell<Transaction>>) {
        *crate::hww::MOCK_NEXT_REQUEST.0.borrow_mut() =
            Some(Box::new(move |response: Response| {
                Ok(tx.borrow().make_host_request(response))
            }));
    }

    /// Pass/accept all user confirmations.
    fn mock_default_ui() {
        mock(Data {
            ui_confirm_create: Some(Box::new(move |_params| true)),
            ui_transaction_address_create: Some(Box::new(|_amount, _address| true)),
            ui_transaction_fee_create: Some(Box::new(|_total, _fee, _longtouch| true)),
            ..Default::default()
        });
    }

    #[test]
    pub fn test_sign_init_fail() {
        *crate::hww::MOCK_NEXT_REQUEST.0.borrow_mut() = None;

        let init_req_valid = pb::BtcSignInitRequest {
            coin: pb::BtcCoin::Btc as _,
            script_configs: vec![pb::BtcScriptConfigWithKeypath {
                script_config: Some(pb::BtcScriptConfig {
                    config: Some(pb::btc_script_config::Config::SimpleType(
                        pb::btc_script_config::SimpleType::P2wpkh as _,
                    )),
                }),
                keypath: vec![84 + HARDENED, 0 + HARDENED, 10 + HARDENED],
            }],
            version: 1,
            num_inputs: 1,
            num_outputs: 1,
            locktime: 0,
            format_unit: FormatUnit::Default as _,
            contains_silent_payment_outputs: false,
        };

        {
            // test keystore locked
            bitbox02::keystore::lock();
            assert_eq!(block_on(process(&init_req_valid)), Err(Error::InvalidState));
        }

        mock_unlocked();
        {
            // test invalid format unit
            let mut init_req_invalid = init_req_valid.clone();
            init_req_invalid.coin = pb::BtcCoin::Ltc as _;
            init_req_invalid.format_unit = FormatUnit::Sat as _;
            assert_eq!(
                block_on(process(&init_req_invalid)),
                Err(Error::InvalidInput)
            );
        }
        {
            // test invalid version
            let mut init_req_invalid = init_req_valid.clone();
            for version in 3..10 {
                init_req_invalid.version = version;
                assert_eq!(
                    block_on(process(&init_req_invalid)),
                    Err(Error::InvalidInput)
                );
            }
        }
        {
            // test invalid locktime
            let mut init_req_invalid = init_req_valid.clone();
            init_req_invalid.locktime = 500000000;
            assert_eq!(
                block_on(process(&init_req_invalid)),
                Err(Error::InvalidInput)
            );
        }
        {
            // test invalid inputs
            let mut init_req_invalid = init_req_valid.clone();
            init_req_invalid.num_inputs = 0;
            assert_eq!(
                block_on(process(&init_req_invalid)),
                Err(Error::InvalidInput)
            );
        }
        {
            // test invalid outputs
            let mut init_req_invalid = init_req_valid.clone();
            init_req_invalid.num_outputs = 0;
            assert_eq!(
                block_on(process(&init_req_invalid)),
                Err(Error::InvalidInput)
            );
        }
        {
            // test invalid coin
            let mut init_req_invalid = init_req_valid.clone();
            init_req_invalid.coin = 4; // BtcCoin is defined from 0 to 3.
            assert_eq!(
                block_on(process(&init_req_invalid)),
                Err(Error::InvalidInput)
            );
        }
        {
            // test invalid account keypath
            let mut init_req_invalid = init_req_valid.clone();
            init_req_invalid.script_configs[0].keypath[2] = HARDENED + 100;
            assert_eq!(
                block_on(process(&init_req_invalid)),
                Err(Error::InvalidInput)
            );
        }
        {
            // no script configs is invalid
            let mut init_req_invalid = init_req_valid.clone();
            init_req_invalid.script_configs = vec![];
            assert_eq!(
                block_on(process(&init_req_invalid)),
                Err(Error::InvalidInput)
            );
        }
        {
            // can't mix script configs from different bip44 accounts
            // (mixing input scripts is allowed, but only from the same bip44 account).
            let mut init_req_invalid = init_req_valid.clone();
            init_req_invalid.script_configs = vec![
                pb::BtcScriptConfigWithKeypath {
                    script_config: Some(pb::BtcScriptConfig {
                        config: Some(pb::btc_script_config::Config::SimpleType(
                            pb::btc_script_config::SimpleType::P2wpkh as _,
                        )),
                    }),
                    keypath: vec![84 + HARDENED, 0 + HARDENED, 10 + HARDENED],
                },
                pb::BtcScriptConfigWithKeypath {
                    script_config: Some(pb::BtcScriptConfig {
                        config: Some(pb::btc_script_config::Config::SimpleType(
                            pb::btc_script_config::SimpleType::P2wpkhP2sh as _,
                        )),
                    }),
                    keypath: vec![49 + HARDENED, 0 + HARDENED, 0 + HARDENED],
                },
            ];
            assert_eq!(
                block_on(process(&init_req_invalid)),
                Err(Error::InvalidInput)
            );
        }

        {
            // can't mix simple type (singlesig) and multisig configs in one tx
            let mut init_req_invalid = init_req_valid.clone();
            init_req_invalid.script_configs = vec![
                pb::BtcScriptConfigWithKeypath {
                    script_config: Some(pb::BtcScriptConfig {
                        config: Some(pb::btc_script_config::Config::SimpleType(
                            pb::btc_script_config::SimpleType::P2wpkh as _,
                        )),
                    }),
                    keypath: vec![84 + HARDENED, 0 + HARDENED, 10 + HARDENED],
                },
                pb::BtcScriptConfigWithKeypath {
                    script_config: Some(pb::BtcScriptConfig {
                        config: Some(pb::btc_script_config::Config::Multisig(
                            pb::btc_script_config::Multisig {
                                threshold: 1,
                                xpubs: vec![
                                    pb::XPub {
                                        ..Default::default()
                                    },
                                    pb::XPub {
                                        ..Default::default()
                                    },
                                ],
                                our_xpub_index: 0,
                                script_type: pb::btc_script_config::multisig::ScriptType::P2wsh
                                    as _,
                            },
                        )),
                    }),
                    keypath: vec![49 + HARDENED, 0 + HARDENED, 0 + HARDENED],
                },
            ];
            assert_eq!(
                block_on(process(&init_req_invalid)),
                Err(Error::InvalidInput)
            );
        }
        {
            // no taproot in Litecoin
            assert_eq!(
                block_on(process(&pb::BtcSignInitRequest {
                    coin: pb::BtcCoin::Ltc as _,
                    script_configs: vec![pb::BtcScriptConfigWithKeypath {
                        script_config: Some(pb::BtcScriptConfig {
                            config: Some(pb::btc_script_config::Config::SimpleType(
                                pb::btc_script_config::SimpleType::P2tr as _,
                            )),
                        }),
                        keypath: vec![84 + HARDENED, 2 + HARDENED, 10 + HARDENED],
                    }],
                    version: 1,
                    num_inputs: 1,
                    num_outputs: 1,
                    locktime: 0,
                    format_unit: FormatUnit::Default as _,
                    contains_silent_payment_outputs: false,
                })),
                Err(Error::InvalidInput)
            );
        }
    }

    #[test]
    pub fn test_process() {
        static mut UI_COUNTER: u32 = 0;
        static mut PREVTX_REQUESTED: u32 = 0;

        for (coin, format_unit) in [
            (pb::BtcCoin::Btc, FormatUnit::Default),
            (pb::BtcCoin::Btc, FormatUnit::Sat),
            (pb::BtcCoin::Ltc, FormatUnit::Default),
        ] {
            unsafe {
                UI_COUNTER = 0;
                PREVTX_REQUESTED = 0;
            }

            let transaction = alloc::rc::Rc::new(core::cell::RefCell::new(Transaction::new(coin)));

            let tx = transaction.clone();
            *crate::hww::MOCK_NEXT_REQUEST.0.borrow_mut() =
                Some(Box::new(move |response: Response| {
                    let next = extract_next(&response);
                    if NextType::try_from(next.r#type).unwrap() == NextType::PrevtxInit {
                        unsafe { PREVTX_REQUESTED += 1 }
                    }
                    Ok(tx.borrow().make_host_request(response))
                }));

            mock(Data {
                ui_transaction_address_create: Some(Box::new(move |amount, address| {
                    match unsafe {
                        UI_COUNTER += 1;
                        UI_COUNTER
                    } {
                        1 => {
                            match coin {
                                pb::BtcCoin::Btc => {
                                    assert_eq!(address, "12ZEw5Hcv1hTb6YUQJ69y1V7uhcoDz92PH");
                                    match format_unit {
                                        FormatUnit::Default => assert_eq!(amount, "1.00000000 BTC"),
                                        FormatUnit::Sat => assert_eq!(amount, "100000000 sat"),
                                    }
                                }
                                pb::BtcCoin::Ltc => {
                                    assert_eq!(address, "LLnCCHbSzfwWquEdaS5TF2Yt7uz5Qb1SZ1");
                                    assert_eq!(amount, "1.00000000 LTC");
                                }
                                _ => panic!("unexpected coin"),
                            }
                            true
                        }
                        2 => {
                            match coin {
                                pb::BtcCoin::Btc => {
                                    assert_eq!(address, "34oVnh4gNviJGMnNvgquMeLAxvXJuaRVMZ");
                                    match format_unit {
                                        FormatUnit::Default => {
                                            assert_eq!(amount, "12.34567890 BTC")
                                        }
                                        FormatUnit::Sat => assert_eq!(amount, "1234567890 sat"),
                                    }
                                }
                                pb::BtcCoin::Ltc => {
                                    assert_eq!(address, "MB1e6aUeL3Zj4s4H2ZqFBHaaHd7kvvzTco");
                                    assert_eq!(amount, "12.34567890 LTC");
                                }
                                _ => panic!("unexpected coin"),
                            }
                            true
                        }
                        3 => {
                            match coin {
                                pb::BtcCoin::Btc => {
                                    assert_eq!(
                                        address,
                                        "bc1qxvenxvenxvenxvenxvenxvenxvenxven2ymjt8"
                                    );
                                    match format_unit {
                                        FormatUnit::Default => {
                                            assert_eq!(amount, "0.00006000 BTC")
                                        }
                                        FormatUnit::Sat => assert_eq!(amount, "6000 sat"),
                                    }
                                }
                                pb::BtcCoin::Ltc => {
                                    assert_eq!(
                                        address,
                                        "ltc1qxvenxvenxvenxvenxvenxvenxvenxvenwcpknh"
                                    );
                                    assert_eq!(amount, "0.00006000 LTC");
                                }
                                _ => panic!("unexpected coin"),
                            }
                            true
                        }
                        4 => {
                            match coin {
                                pb::BtcCoin::Btc => {
                                    assert_eq!(
                                        address,
                                        "bc1qg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zqd8sxw4"
                                    );
                                    match format_unit {
                                        FormatUnit::Default => {
                                            assert_eq!(amount, "0.00007000 BTC")
                                        }
                                        FormatUnit::Sat => assert_eq!(amount, "7000 sat"),
                                    }
                                }
                                pb::BtcCoin::Ltc => {
                                    assert_eq!(
                                        address,
                                        "ltc1qg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zqwr7k5s"
                                    );
                                    assert_eq!(amount, "0.00007000 LTC");
                                }
                                _ => panic!("unexpected coin"),
                            }
                            true
                        }
                        _ => panic!("unexpected UI dialog"),
                    }
                })),
                ui_transaction_fee_create: Some(Box::new(move |total, fee, longtouch| {
                    match unsafe {
                        UI_COUNTER += 1;
                        UI_COUNTER
                    } {
                        6 => {
                            match coin {
                                pb::BtcCoin::Btc => match format_unit {
                                    FormatUnit::Default => {
                                        assert_eq!(total, "13.39999900 BTC");
                                        assert_eq!(fee, "0.05419010 BTC");
                                    }
                                    FormatUnit::Sat => {
                                        assert_eq!(total, "1339999900 sat");
                                        assert_eq!(fee, "5419010 sat");
                                    }
                                },
                                pb::BtcCoin::Ltc => {
                                    assert_eq!(total, "13.39999900 LTC");
                                    assert_eq!(fee, "0.05419010 LTC");
                                }
                                _ => panic!("unexpected coin"),
                            }
                            assert!(longtouch);
                            true
                        }
                        _ => panic!("unexpected UI dialog"),
                    }
                })),
                ui_confirm_create: Some(Box::new(|params| {
                    match unsafe {
                        UI_COUNTER += 1;
                        UI_COUNTER
                    } {
                        5 => {
                            assert_eq!(params.title, "Warning");
                            assert_eq!(params.body, "There are 2\nchange outputs.\nProceed?");
                            true
                        }
                        _ => panic!("unexpected UI dialog"),
                    }
                })),
                ..Default::default()
            });
            mock_unlocked();
            let tx = transaction.borrow();
            let mut init_request = tx.init_request();
            init_request.format_unit = format_unit as _;
            let result = block_on(process(&init_request));
            match result {
                Ok(Response::BtcSignNext(next)) => {
                    assert!(next.has_signature);
                    match coin {
                        pb::BtcCoin::Btc => {
                            assert_eq!(
                                &next.signature,
                                b"\x2e\x08\x4a\x0a\x5f\x9b\xab\xb3\x5d\xf6\xec\x3a\x89\x72\x0b\xcf\xc0\x88\xd4\xba\x6a\xee\x47\x97\x3c\x55\xfe\xc3\xb3\xdd\xaa\x60\x07\xc7\xb1\x1c\x8b\x5a\x1a\x68\x20\xca\x74\xa8\x5a\xeb\x4c\xf5\x45\xc1\xb3\x37\x53\x70\xf4\x4f\x24\xd5\x3d\x61\xfe\x67\x6e\x4c");
                        }
                        _ => {}
                    }
                }
                _ => panic!("wrong result"),
            }
            assert_eq!(unsafe { UI_COUNTER }, tx.total_confirmations);
            assert_eq!(unsafe { PREVTX_REQUESTED }, tx.inputs.len() as _);
        }
    }

    /// Test that receiving an unexpected message from the host results in an invalid state error.
    #[test]
    pub fn test_invalid_state() {
        let transaction =
            alloc::rc::Rc::new(core::cell::RefCell::new(Transaction::new(pb::BtcCoin::Btc)));
        mock_unlocked();
        let tx = transaction.clone();
        static mut COUNTER: u32 = 0;
        *crate::hww::MOCK_NEXT_REQUEST.0.borrow_mut() =
            Some(Box::new(move |_response: Response| {
                unsafe { COUNTER += 1 }
                // The first input is only expected once, the other times other parts of the
                // transaction are expected.
                Ok(Request::BtcSignInput(tx.borrow().inputs[0].input.clone()))
            }));

        let result = block_on(process(&transaction.borrow().init_request()));
        assert_eq!(result, Err(Error::InvalidState));
        assert_eq!(unsafe { COUNTER }, 2);
    }

    /// Test signing if all inputs are of type P2WPKH-P2SH.
    #[test]
    pub fn test_script_type_p2wpkh_p2sh() {
        let transaction =
            alloc::rc::Rc::new(core::cell::RefCell::new(Transaction::new(pb::BtcCoin::Btc)));
        for input in transaction.borrow_mut().inputs.iter_mut() {
            input.input.keypath[0] = 49 + HARDENED;
        }
        for output in transaction.borrow_mut().outputs.iter_mut() {
            if output.ours {
                output.keypath[0] = 49 + HARDENED;
            }
        }

        mock_host_responder(transaction.clone());
        mock_default_ui();
        mock_unlocked();
        let mut init_request = transaction.borrow().init_request();
        init_request.script_configs[0] = pb::BtcScriptConfigWithKeypath {
            script_config: Some(pb::BtcScriptConfig {
                config: Some(pb::btc_script_config::Config::SimpleType(
                    pb::btc_script_config::SimpleType::P2wpkhP2sh as _,
                )),
            }),
            keypath: vec![49 + HARDENED, 0 + HARDENED, 10 + HARDENED],
        };
        let result = block_on(process(&init_request));
        match result {
            Ok(Response::BtcSignNext(next)) => {
                assert!(next.has_signature);
                assert_eq!(&next.signature, b"\x3a\x46\x18\xf6\x16\x3c\x1d\x55\x3b\xeb\xc2\xc6\xac\x08\x86\x6d\x9f\x02\x7c\xa6\x63\xee\xa7\x43\x65\x8b\xb0\x58\x1c\x42\x33\xa4\x32\x98\x4c\xca\xeb\x52\x04\x4f\x70\x47\x47\x94\xc5\x54\x46\xa5\xd8\x23\xe1\xfb\x96\x9a\x39\x13\x2f\x7d\xa2\x30\xd2\xdd\x33\x75");
            }
            _ => panic!("wrong result"),
        }
    }

    /// Test signing if all inputs are of type P2TR.
    #[test]
    pub fn test_script_type_p2tr() {
        let transaction =
            alloc::rc::Rc::new(core::cell::RefCell::new(Transaction::new(pb::BtcCoin::Btc)));
        for input in transaction.borrow_mut().inputs.iter_mut() {
            input.input.keypath[0] = 86 + HARDENED;
        }
        for output in transaction.borrow_mut().outputs.iter_mut() {
            if output.ours {
                output.keypath[0] = 86 + HARDENED;
            }
        }

        let tx = transaction.clone();
        // Check that previous transactions are not streamed, as all inputs are taproot.
        static mut PREVTX_REQUESTED: bool = false;
        *crate::hww::MOCK_NEXT_REQUEST.0.borrow_mut() =
            Some(Box::new(move |response: Response| {
                let next = extract_next(&response);
                if NextType::try_from(next.r#type).unwrap() == NextType::PrevtxInit {
                    unsafe { PREVTX_REQUESTED = true }
                }
                Ok(tx.borrow().make_host_request(response))
            }));

        mock_default_ui();
        mock_unlocked();
        bitbox02::random::mock_reset();
        let mut init_request = transaction.borrow().init_request();
        init_request.script_configs[0] = pb::BtcScriptConfigWithKeypath {
            script_config: Some(pb::BtcScriptConfig {
                config: Some(pb::btc_script_config::Config::SimpleType(
                    pb::btc_script_config::SimpleType::P2tr as _,
                )),
            }),
            keypath: vec![86 + HARDENED, 0 + HARDENED, 10 + HARDENED],
        };
        let result = block_on(process(&init_request));
        match result {
            Ok(Response::BtcSignNext(next)) => {
                assert!(next.has_signature);
                assert_eq!(&next.signature, b"\x47\x2e\xf2\xaa\x29\x3d\x56\x97\x64\x9a\x53\x64\xd4\x05\x67\xd6\xea\xf5\x08\xfc\xa9\xe5\x13\x21\xc5\xa4\x8d\xe4\x2c\x32\xb4\xbb\xc2\xd0\xce\xe4\xab\x6f\xea\x1f\x3b\x13\x7a\x1c\xbc\xa2\xab\xe7\x2a\xa9\x45\xc5\x0e\x95\xe0\x2f\xa8\xac\x35\x4f\xdd\xf2\xca\x10");
            }
            _ => panic!("wrong result"),
        }
        assert!(unsafe { !PREVTX_REQUESTED });
    }

    /// Test signing if with mixed inputs, one of them being taproot. Previous transactions of all
    /// inputs should be streamed in this case.
    #[test]
    pub fn test_script_type_p2tr_mixed() {
        let transaction =
            alloc::rc::Rc::new(core::cell::RefCell::new(Transaction::new(pb::BtcCoin::Btc)));
        transaction.borrow_mut().inputs[0].input.script_config_index = 1;
        transaction.borrow_mut().inputs[0].input.keypath[0] = 86 + HARDENED;

        let tx = transaction.clone();
        // Check that previous transactions are streamed, as not all input are taproot.
        static mut PREVTX_REQUESTED: u32 = 0;
        *crate::hww::MOCK_NEXT_REQUEST.0.borrow_mut() =
            Some(Box::new(move |response: Response| {
                let next = extract_next(&response);
                if NextType::try_from(next.r#type).unwrap() == NextType::PrevtxInit {
                    unsafe { PREVTX_REQUESTED += 1 }
                }
                Ok(tx.borrow().make_host_request(response))
            }));

        mock_default_ui();
        mock_unlocked();
        let mut init_request = transaction.borrow().init_request();
        init_request
            .script_configs
            .push(pb::BtcScriptConfigWithKeypath {
                script_config: Some(pb::BtcScriptConfig {
                    config: Some(pb::btc_script_config::Config::SimpleType(
                        pb::btc_script_config::SimpleType::P2tr as _,
                    )),
                }),
                keypath: vec![86 + HARDENED, 0 + HARDENED, 10 + HARDENED],
            });
        assert!(block_on(process(&init_request)).is_ok());
        assert_eq!(
            unsafe { PREVTX_REQUESTED },
            transaction.borrow().inputs.len() as _
        );
    }

    /// Test signing UTXOs with high keypath address indices. Even though we don't support verifying
    /// receive addresses at these indices (to mitigate ransom attacks), we should still be able to
    /// spend them.
    #[test]
    pub fn test_spend_high_address_index() {
        let transaction =
            alloc::rc::Rc::new(core::cell::RefCell::new(Transaction::new(pb::BtcCoin::Btc)));
        transaction.borrow_mut().inputs[0].input.keypath[4] = 100000;

        mock_host_responder(transaction.clone());
        mock_default_ui();
        mock_unlocked();
        bitbox02::random::mock_reset();
        let result = block_on(process(&transaction.borrow().init_request()));
        assert!(result.is_ok());
    }

    /// Test invalid input cases.
    #[test]
    pub fn test_invalid_input() {
        enum TestCase {
            // all inputs should be the same coin type.
            WrongCoinInput,
            // all change outputs should be the same coin type.
            WrongCoinChange,
            // all inputs should be from the same account.
            WrongAccountInput,
            // all change outputs should go the same account.
            WrongAccountChange,
            // change num in bip44, should be 1.
            WrongBip44Change(u32),
            // change address index in bip44, should be <10000
            WrongBip44ChangeAddressTooHigh,
            // referenced script config does not exist.
            InvalidInputScriptConfigIndex,
            // referenced script config does not exist.
            InvalidChangeScriptConfigIndex,
            // value 0 is invalid
            WrongOutputValue,
            // input value does not match prevtx output value
            WrongInputValue,
            // input's prevtx hash does not match input's prevOutHash
            WrongPrevoutHash,
            // input's prev_out_index too high
            WrongPrevoutIndex,
            // no inputs in prevtx
            PrevTxNoInputs,
            // no outputs in prevtx
            PrevTxNoOutputs,
        }
        for value in [
            TestCase::WrongCoinInput,
            TestCase::WrongCoinChange,
            TestCase::WrongAccountInput,
            TestCase::WrongAccountChange,
            TestCase::WrongBip44Change(2),
            TestCase::WrongBip44ChangeAddressTooHigh,
            TestCase::InvalidInputScriptConfigIndex,
            TestCase::InvalidChangeScriptConfigIndex,
            TestCase::WrongOutputValue,
            TestCase::WrongInputValue,
            TestCase::WrongPrevoutHash,
            TestCase::WrongPrevoutIndex,
            TestCase::PrevTxNoInputs,
            TestCase::PrevTxNoOutputs,
        ] {
            let transaction =
                alloc::rc::Rc::new(core::cell::RefCell::new(Transaction::new(pb::BtcCoin::Btc)));
            match value {
                TestCase::WrongCoinInput => {
                    transaction.borrow_mut().inputs[0].input.keypath[1] = 1 + HARDENED;
                }
                TestCase::WrongCoinChange => {
                    assert!(transaction.borrow().outputs[4].ours);
                    transaction.borrow_mut().outputs[4].keypath[1] = 1 + HARDENED;
                }
                TestCase::WrongAccountInput => {
                    transaction.borrow_mut().inputs[0].input.keypath[2] += 1;
                }
                TestCase::WrongAccountChange => {
                    assert!(transaction.borrow().outputs[4].ours);
                    transaction.borrow_mut().outputs[4].keypath[2] += 1;
                }
                TestCase::WrongBip44Change(change) => {
                    assert!(transaction.borrow().outputs[4].ours);
                    transaction.borrow_mut().outputs[4].keypath[3] = change;
                }
                TestCase::WrongBip44ChangeAddressTooHigh => {
                    assert!(transaction.borrow().outputs[4].ours);
                    transaction.borrow_mut().outputs[4].keypath[4] = 10000;
                }
                TestCase::InvalidInputScriptConfigIndex => {
                    transaction.borrow_mut().inputs[0].input.script_config_index = 1;
                }
                TestCase::InvalidChangeScriptConfigIndex => {
                    assert!(transaction.borrow().outputs[4].ours);
                    transaction.borrow_mut().outputs[4].script_config_index = 1;
                }
                TestCase::WrongOutputValue => {
                    transaction.borrow_mut().outputs[0].value = 0;
                }
                TestCase::WrongInputValue => {
                    transaction.borrow_mut().inputs[0].input.prev_out_value += 1;
                }
                TestCase::WrongPrevoutHash => {
                    transaction.borrow_mut().inputs[0].input.prev_out_hash[0] += 1;
                }
                TestCase::WrongPrevoutIndex => {
                    let mut tx = transaction.borrow_mut();
                    tx.inputs[0].input.prev_out_index = tx.inputs[0].prevtx_outputs.len() as _;
                }
                TestCase::PrevTxNoInputs => {
                    transaction.borrow_mut().inputs[0].prevtx_inputs.clear();
                }
                TestCase::PrevTxNoOutputs => {
                    transaction.borrow_mut().inputs[0].prevtx_outputs.clear();
                }
            }
            mock_host_responder(transaction.clone());
            mock_default_ui();
            mock_unlocked();
            let result = block_on(process(&transaction.borrow().init_request()));
            assert_eq!(result, Err(Error::InvalidInput));
        }
    }

    /// Test signing with mixed input types.
    #[test]
    pub fn test_mixed_inputs() {
        let transaction =
            alloc::rc::Rc::new(core::cell::RefCell::new(Transaction::new(pb::BtcCoin::Btc)));
        transaction.borrow_mut().inputs[0].input.script_config_index = 1;
        transaction.borrow_mut().inputs[0].input.keypath[0] = 49 + HARDENED;
        mock_host_responder(transaction.clone());
        mock_default_ui();
        mock_unlocked();
        let mut init_request = transaction.borrow().init_request();
        init_request
            .script_configs
            .push(pb::BtcScriptConfigWithKeypath {
                script_config: Some(pb::BtcScriptConfig {
                    config: Some(pb::btc_script_config::Config::SimpleType(
                        pb::btc_script_config::SimpleType::P2wpkhP2sh as _,
                    )),
                }),
                keypath: vec![49 + HARDENED, 0 + HARDENED, 10 + HARDENED],
            });
        assert!(block_on(process(&init_request)).is_ok());
    }

    #[test]
    fn test_user_aborts() {
        let transaction =
            alloc::rc::Rc::new(core::cell::RefCell::new(Transaction::new(pb::BtcCoin::Btc)));
        mock_host_responder(transaction.clone());
        static mut UI_COUNTER: u32 = 0;
        static mut CURRENT_COUNTER: u32 = 0;
        // We go through all possible user confirmations and abort one of them at a time.
        for counter in 1..=transaction.borrow().total_confirmations {
            unsafe {
                UI_COUNTER = 0;
                CURRENT_COUNTER = counter
            }
            mock(Data {
                ui_transaction_address_create: Some(Box::new(|_amount, _address| unsafe {
                    UI_COUNTER += 1;
                    UI_COUNTER != CURRENT_COUNTER
                })),
                ui_transaction_fee_create: Some(Box::new(|_total, _fee, _longtouch| unsafe {
                    UI_COUNTER += 1;
                    UI_COUNTER != CURRENT_COUNTER
                })),
                ui_confirm_create: Some(Box::new(move |_params| unsafe {
                    UI_COUNTER += 1;
                    UI_COUNTER != CURRENT_COUNTER
                })),
                ..Default::default()
            });
            mock_unlocked();
            assert_eq!(
                block_on(process(&transaction.borrow().init_request())),
                Err(Error::UserAbort)
            );
        }
    }

    /// Check workflow when a locktime applies.
    #[test]
    fn test_locktime() {
        struct Test {
            coin: pb::BtcCoin,
            locktime: u32,
            sequence: u32,
            // If None: no user confirmation expected.
            // If Some: confirmation body and user response.
            confirm: Option<(&'static str, bool)>,
        }
        static mut LOCKTIME_CONFIRMED: bool = false;
        for test_case in &[
            Test {
                coin: pb::BtcCoin::Btc,
                locktime: 0,
                sequence: 0xffffffff,
                confirm: None,
            },
            Test {
                coin: pb::BtcCoin::Btc,
                locktime: 0,
                sequence: 0xffffffff - 1,
                confirm: None,
            },
            Test {
                coin: pb::BtcCoin::Btc,
                locktime: 0,
                sequence: 0xffffffff - 2,
                confirm: None,
            },
            Test {
                coin: pb::BtcCoin::Btc,
                locktime: 1,
                sequence: 0xffffffff - 1,
                confirm: Some(("Locktime on block:\n1\nTransaction is not RBF", true)),
            },
            Test {
                coin: pb::BtcCoin::Btc,
                locktime: 1,
                sequence: 0xffffffff - 1,
                confirm: Some(("Locktime on block:\n1\nTransaction is not RBF", false)),
            },
            Test {
                coin: pb::BtcCoin::Btc,
                locktime: 10,
                sequence: 0xffffffff - 1,
                confirm: Some(("Locktime on block:\n10\nTransaction is not RBF", true)),
            },
            Test {
                coin: pb::BtcCoin::Btc,
                locktime: 10,
                sequence: 0xffffffff - 2,
                confirm: Some(("Locktime on block:\n10\nTransaction is RBF", true)),
            },
            Test {
                coin: pb::BtcCoin::Ltc,
                locktime: 10,
                sequence: 0xffffffff - 1,
                confirm: Some(("Locktime on block:\n10\n", true)),
            },
            Test {
                coin: pb::BtcCoin::Ltc,
                locktime: 10,
                sequence: 0xffffffff - 2,
                confirm: Some(("Locktime on block:\n10\n", true)),
            },
        ] {
            let transaction =
                alloc::rc::Rc::new(core::cell::RefCell::new(Transaction::new(test_case.coin)));
            transaction.borrow_mut().inputs[0].input.sequence = test_case.sequence;
            mock_host_responder(transaction.clone());
            unsafe { LOCKTIME_CONFIRMED = false }
            mock_default_ui();
            mock(Data {
                ui_transaction_fee_create: Some(Box::new(|_total, _fee, _longtouch| true)),
                ui_transaction_address_create: Some(Box::new(|_amount, _address| true)),
                ui_confirm_create: Some(Box::new(move |params| {
                    if params.body.contains("Locktime") {
                        if let Some((confirm_str, user_response)) = test_case.confirm {
                            assert_eq!(params.title, "");
                            assert_eq!(params.body, confirm_str);
                            unsafe { LOCKTIME_CONFIRMED = true }
                            return user_response;
                        }
                        panic!("Unexpected RBF confirmation");
                    }
                    true
                })),
                ..Default::default()
            });
            mock_unlocked();

            let mut init_request = transaction.borrow().init_request();
            init_request.locktime = test_case.locktime;
            let result = block_on(process(&init_request));
            if let Some((_, false)) = test_case.confirm {
                assert_eq!(result, Err(Error::UserAbort));
            } else {
                assert!(result.is_ok());
            }
            assert_eq!(unsafe { LOCKTIME_CONFIRMED }, test_case.confirm.is_some());
        }
    }

    // Test a transaction with an unusually high fee.
    #[test]
    fn test_high_fee_warning() {
        let transaction =
            alloc::rc::Rc::new(core::cell::RefCell::new(Transaction::new(pb::BtcCoin::Btc)));
        transaction.borrow_mut().outputs[1].value = 1034567890;
        // One more confirmation for the high fee warning.
        transaction.borrow_mut().total_confirmations += 1;
        mock_host_responder(transaction.clone());
        static mut UI_COUNTER: u32 = 0;
        static mut FEE_CHECKED: bool = false;
        mock(Data {
            ui_transaction_address_create: Some(Box::new(|_amount, _address| unsafe {
                UI_COUNTER += 1;
                true
            })),
            ui_transaction_fee_create: Some(Box::new(|total, fee, longtouch| unsafe {
                UI_COUNTER += 1;
                assert_eq!(total, "13.39999900 BTC");
                assert_eq!(fee, "2.05419010 BTC");
                assert!(!longtouch);
                true
            })),
            ui_confirm_create: Some(Box::new(move |params| unsafe {
                UI_COUNTER += 1;
                match UI_COUNTER {
                    7 => {
                        assert_eq!(params.title, "High fee");
                        assert_eq!(params.body, "The fee is 18.1%\nthe send amount.\nProceed?");
                        assert!(params.longtouch);
                        FEE_CHECKED = true;
                        true
                    }
                    _ => true,
                }
            })),
            ..Default::default()
        });
        mock_unlocked();
        let tx = transaction.borrow();
        assert!(block_on(process(&tx.init_request())).is_ok());
        assert_eq!(unsafe { UI_COUNTER }, tx.total_confirmations);
        assert!(unsafe { FEE_CHECKED });
    }

    // Test a P2TR output. It is not part of the default test transaction because Taproot is not
    // active on Litecoin yet.
    #[test]
    fn test_p2tr_output() {
        let transaction =
            alloc::rc::Rc::new(core::cell::RefCell::new(Transaction::new(pb::BtcCoin::Btc)));
        transaction.borrow_mut().outputs[0].r#type = pb::BtcOutputType::P2tr as _;
        transaction.borrow_mut().outputs[0].payload = b"\xa6\x08\x69\xf0\xdb\xcf\x1d\xc6\x59\xc9\xce\xcb\xaf\x80\x50\x13\x5e\xa9\xe8\xcd\xc4\x87\x05\x3f\x1d\xc6\x88\x09\x49\xdc\x68\x4c".to_vec();
        mock_host_responder(transaction.clone());
        static mut UI_COUNTER: u32 = 0;
        mock(Data {
            ui_transaction_address_create: Some(Box::new(|amount, address| unsafe {
                UI_COUNTER += 1;
                if UI_COUNTER == 1 {
                    assert_eq!(
                        address,
                        "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
                    );
                    assert_eq!(amount, "1.00000000 BTC");
                }
                true
            })),
            ui_transaction_fee_create: Some(Box::new(|_total, _fee, _longtouch| true)),
            ui_confirm_create: Some(Box::new(move |_params| true)),
            ..Default::default()
        });
        mock_unlocked();
        let result = block_on(process(&transaction.borrow().init_request()));
        assert!(unsafe { UI_COUNTER >= 1 });
        match result {
            Ok(Response::BtcSignNext(next)) => {
                assert!(next.has_signature);
                assert_eq!(&next.signature, b"\x8f\x1e\x0e\x8f\x98\xd3\x6d\xb1\x19\x62\x64\xf1\xa3\x00\xfa\xe3\x17\xf1\x50\x8d\x2c\x48\x9f\xbb\xd6\x60\xe0\x48\xc4\x52\x9c\x61\x2f\x59\x57\x6c\x86\xa2\x6f\xfa\x47\x6d\x97\x35\x1e\x46\x9e\xf6\xed\x27\x84\xae\xcb\x71\x05\x3a\x51\x66\x77\x5c\xcb\x4d\x7b\x9b");
            }
            _ => panic!("wrong result"),
        }
    }

    #[test]
    fn test_silent_payment_output() {
        let transaction =
            alloc::rc::Rc::new(core::cell::RefCell::new(Transaction::new(pb::BtcCoin::Btc)));

        // Make an input a P2TR input to verify the right (tweaked) private key is used in the
        // derivation of the silent payment output.
        transaction.borrow_mut().inputs[0].input.script_config_index = 1;
        transaction.borrow_mut().inputs[0].input.keypath[0] = 86 + HARDENED;

        // Make first output a silent payment output.
        transaction.borrow_mut().outputs[0].r#type = pb::BtcOutputType::P2tr as _;
        transaction.borrow_mut().outputs[0].payload = b"\x7b\x91\x01\xd6\x0c\x64\x61\xff\x3e\x18\xf0\x83\x2e\x7f\x1e\x95\x20\x84\x20\x50\x62\xd7\xe0\xb7\xb0\x88\x12\xc2\x64\xcf\xe7\x13".to_vec();
        transaction.borrow_mut().outputs[0].silent_payment =
            Some(pb::btc_sign_output_request::SilentPayment {
                address: "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv".into(),
            });
        //mock_host_responder(transaction.clone());
        let tx = transaction.clone();
        *crate::hww::MOCK_NEXT_REQUEST.0.borrow_mut() = Some(Box::new(
            move |response: Response| {
                let next = extract_next(&response);

                if NextType::try_from(next.r#type).unwrap() == NextType::Output && next.index == 1 {
                    assert_eq!(next.generated_output_pkscript.as_slice(), b"\x51\x20\x7b\x91\x01\xd6\x0c\x64\x61\xff\x3e\x18\xf0\x83\x2e\x7f\x1e\x95\x20\x84\x20\x50\x62\xd7\xe0\xb7\xb0\x88\x12\xc2\x64\xcf\xe7\x13");
                }
                Ok(tx.borrow().make_host_request(response))
            },
        ));

        static mut UI_COUNTER: u32 = 0;
        mock(Data {
            ui_transaction_address_create: Some(Box::new(|amount, address| unsafe {
                UI_COUNTER += 1;
                if UI_COUNTER == 1 {
                    assert_eq!(
                        address,
                        "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv"
                    );
                    assert_eq!(amount, "1.00000000 BTC");
                }
                true
            })),
            ui_transaction_fee_create: Some(Box::new(|_total, _fee, _longtouch| true)),
            ui_confirm_create: Some(Box::new(move |_params| true)),
            ..Default::default()
        });
        mock_unlocked();

        let mut init_request = transaction.borrow().init_request();
        init_request
            .script_configs
            .push(pb::BtcScriptConfigWithKeypath {
                script_config: Some(pb::BtcScriptConfig {
                    config: Some(pb::btc_script_config::Config::SimpleType(
                        pb::btc_script_config::SimpleType::P2tr as _,
                    )),
                }),
                keypath: vec![86 + HARDENED, 0 + HARDENED, 10 + HARDENED],
            });
        assert!(block_on(process(&init_request)).is_ok());
        assert!(unsafe { UI_COUNTER >= 1 });
    }

    // Test an output that is marked ours but is not a change output by keypath.
    #[test]
    fn test_our_non_change_output() {
        let transaction =
            alloc::rc::Rc::new(core::cell::RefCell::new(Transaction::new(pb::BtcCoin::Btc)));
        transaction.borrow_mut().outputs[5].keypath[3] = 0;
        mock_host_responder(transaction.clone());
        static mut UI_COUNTER: u32 = 0;
        static mut TOTAL_AND_FEE_CHECKED: bool = false;
        mock(Data {
            ui_transaction_address_create: Some(Box::new(|amount, address| unsafe {
                UI_COUNTER += 1;
                if UI_COUNTER == 5 {
                    assert_eq!(
                        address,
                        "This BitBox02: bc1qnu4x8dlrx6dety47gehf4uhk5tj3q7yhywgry6"
                    );
                    assert_eq!(amount, "0.00000100 BTC");
                }
                true
            })),
            ui_transaction_fee_create: Some(Box::new(|total, fee, _longtouch| unsafe {
                // The total is the same as if the output was an external output. It includes the
                // amount sent to the internal non-change address.
                assert_eq!(total, "13.40000000 BTC");
                assert_eq!(fee, "0.05419010 BTC");
                TOTAL_AND_FEE_CHECKED = true;
                true
            })),
            ui_confirm_create: Some(Box::new(move |_params| true)),
            ..Default::default()
        });
        mock_unlocked();
        let result = block_on(process(&transaction.borrow().init_request()));
        assert!(unsafe { UI_COUNTER >= 5 });
        assert!(unsafe { TOTAL_AND_FEE_CHECKED });
        match result {
            Ok(Response::BtcSignNext(next)) => {
                assert!(next.has_signature);
                assert_eq!(&next.signature, b"\xe1\x15\xd7\xd2\xd2\xb7\xef\x06\x8e\x7b\x89\xde\x83\xec\x79\x17\x44\xd4\x6b\x8b\xae\x8a\x59\x31\xa7\x3e\xf6\x44\xc0\xdb\x01\xcf\x2f\x2e\x2a\x02\x79\x7a\x29\xa1\x81\xfe\x74\xea\x1f\x5d\x2b\xca\xba\x4d\x70\xe0\xe7\x74\x24\x12\xa6\x80\xfd\x62\x95\x7a\x90\xf7");
            }
            _ => panic!("wrong result"),
        }
    }

    /// Exercise the antiklepto protocol
    #[test]
    fn test_antiklepto() {
        let transaction =
            alloc::rc::Rc::new(core::cell::RefCell::new(Transaction::new(pb::BtcCoin::Btc)));
        let host_nonce = b"\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab";
        // The host nonce commitment value does not impact this test, but an invalid commitment
        // would fail the antiklepto signature check on the host. The host check is skipped here and
        // tested in test_keystore_antiklepto.c. That the host nonce was included in the sig is
        // tested by the siganture fixture test below.x
        let host_nonce_commitment = pb::AntiKleptoHostNonceCommitment {
            commitment: bitbox02::secp256k1::ecdsa_anti_exfil_host_commit(host_nonce).unwrap(),
        };
        transaction.borrow_mut().inputs[1].host_nonce = Some(host_nonce.to_vec());
        transaction.borrow_mut().inputs[1]
            .input
            .host_nonce_commitment = Some(host_nonce_commitment);
        mock_host_responder(transaction.clone());
        mock_default_ui();
        mock_unlocked();
        let result = block_on(process(&transaction.borrow().init_request()));
        match result {
            Ok(Response::Btc(pb::BtcResponse {
                response: Some(pb::btc_response::Response::SignNext(next)),
            })) => {
                assert!(next.has_signature);
                assert_eq!(&next.signature, b"\x2e\x6d\xe6\x54\x62\x6e\xe9\x12\xbf\x2e\x0c\xf5\xa5\x67\x49\x89\x1a\xa9\x89\x56\xd4\x0e\x29\xe3\x8b\x8a\x64\x4d\x5c\x62\xcf\xcc\x44\xe7\x72\x92\x84\xff\x30\xf9\x24\x8c\xd7\x0a\x54\x57\xb0\xe2\x32\x4e\x7c\x47\x3f\x66\x00\x43\x2a\xcd\xc8\xd9\x2f\xb1\x67\x66");
            }
            _ => panic!("wrong result"),
        }
    }

    /// The sum of the inputs in the 2nd pass can't be higher than in the first for all inputs.
    #[test]
    fn test_input_sum_changes() {
        let transaction =
            alloc::rc::Rc::new(core::cell::RefCell::new(Transaction::new(pb::BtcCoin::Btc)));
        static mut PASS2_INPUT_REQUESTS_COUNTER: u32 = 0;
        *crate::hww::MOCK_NEXT_REQUEST.0.borrow_mut() = {
            let tx = transaction.clone();
            static mut PASS2: bool = false;
            Some(Box::new(move |response: Response| {
                let tx = tx.borrow();
                let next = extract_next(&response);
                match NextType::try_from(next.r#type).unwrap() {
                    NextType::Output => unsafe { PASS2 = true },
                    NextType::Input => {
                        if unsafe { PASS2 } {
                            unsafe { PASS2_INPUT_REQUESTS_COUNTER += 1 }
                            if next.index == 0 {
                                let mut input = tx.inputs[next.index as usize].input.clone();
                                // Amount in first input in pass2 is bigger than the the sum of all
                                // inputs in the first pass, which fails immediately.
                                input.prev_out_value = tx
                                    .inputs
                                    .iter()
                                    .map(|inp| inp.input.prev_out_value)
                                    .sum::<u64>()
                                    + 1;
                                return Ok(Request::BtcSignInput(input));
                            }
                        }
                    }
                    _ => {}
                }
                Ok(tx.make_host_request(response))
            }))
        };
        mock_default_ui();
        mock_unlocked();
        let result = block_on(process(&transaction.borrow().init_request()));
        assert_eq!(result, Err(Error::InvalidInput));
        // Only one input in the 2nd pass was requested, meaning the process failed after validating
        // the amount in the first input.
        assert_eq!(unsafe { PASS2_INPUT_REQUESTS_COUNTER }, 1);
    }

    /// At the last input, the sum of the inputs in the 2nd pass must be the same as the sum of the
    /// inputs in the first pass.
    #[test]
    fn test_input_sum_last_mismatch() {
        let transaction =
            alloc::rc::Rc::new(core::cell::RefCell::new(Transaction::new(pb::BtcCoin::Btc)));
        static mut PASS2_INPUT_REQUESTS_COUNTER: u32 = 0;
        *crate::hww::MOCK_NEXT_REQUEST.0.borrow_mut() = {
            let tx = transaction.clone();
            static mut PASS2: bool = false;
            Some(Box::new(move |response: Response| {
                let tx = tx.borrow();
                let next = extract_next(&response);
                match NextType::try_from(next.r#type).unwrap() {
                    NextType::Output => unsafe { PASS2 = true },
                    NextType::Input => {
                        if unsafe { PASS2 } {
                            unsafe { PASS2_INPUT_REQUESTS_COUNTER += 1 }
                            if next.index == 0 {
                                let mut input = tx.inputs[next.index as usize].input.clone();
                                // errors even if we decrease the amount
                                input.prev_out_value -= 1;
                                return Ok(Request::BtcSignInput(input));
                            }
                        }
                    }
                    _ => {}
                }
                Ok(tx.make_host_request(response))
            }))
        };
        mock_default_ui();
        mock_unlocked();
        let result = block_on(process(&transaction.borrow().init_request()));
        assert_eq!(result, Err(Error::InvalidInput));
        // All inputs were requested, the failure happens when comparing the sums of the two passes
        // at the end.
        assert_eq!(
            unsafe { PASS2_INPUT_REQUESTS_COUNTER },
            transaction.borrow().inputs.len() as u32
        );
    }

    /// Outgoing sum overflows.
    #[test]
    fn test_overflow_output_out() {
        let transaction =
            alloc::rc::Rc::new(core::cell::RefCell::new(Transaction::new(pb::BtcCoin::Btc)));
        *crate::hww::MOCK_NEXT_REQUEST.0.borrow_mut() = {
            let tx = transaction.clone();
            Some(Box::new(move |response: Response| {
                let tx = tx.borrow();
                let next = extract_next(&response);
                match NextType::try_from(next.r#type).unwrap() {
                    NextType::Output => {
                        let mut output = tx.outputs[next.index as usize].clone();
                        if next.index == 0 {
                            assert!(!output.ours);
                            output.value = u64::MAX;
                        }
                        Ok(Request::BtcSignOutput(output))
                    }
                    _ => Ok(tx.make_host_request(response)),
                }
            }))
        };
        mock_default_ui();
        mock_unlocked();
        let result = block_on(process(&transaction.borrow().init_request()));
        assert_eq!(result, Err(Error::InvalidInput));
    }

    /// Outgoing change overflows.
    #[test]
    fn test_overflow_output_ours() {
        let transaction =
            alloc::rc::Rc::new(core::cell::RefCell::new(Transaction::new(pb::BtcCoin::Btc)));
        *crate::hww::MOCK_NEXT_REQUEST.0.borrow_mut() = {
            let tx = transaction.clone();
            Some(Box::new(move |response: Response| {
                let tx = tx.borrow();
                let next = extract_next(&response);
                match NextType::try_from(next.r#type).unwrap() {
                    NextType::Output => {
                        let mut output = tx.outputs[next.index as usize].clone();
                        if next.index == 4 {
                            assert!(output.ours);
                            output.value = u64::MAX;
                        }
                        Ok(Request::BtcSignOutput(output))
                    }
                    _ => Ok(tx.make_host_request(response)),
                }
            }))
        };
        mock_default_ui();
        mock_unlocked();
        let result = block_on(process(&transaction.borrow().init_request()));
        assert_eq!(result, Err(Error::InvalidInput));
    }

    #[test]
    fn test_multisig_p2wsh() {
        let transaction = alloc::rc::Rc::new(core::cell::RefCell::new(Transaction::new_multisig()));
        mock_host_responder(transaction.clone());
        static mut UI_COUNTER: u32 = 0;
        mock(Data {
            ui_confirm_create: Some(Box::new(move |params| {
                match unsafe {
                    UI_COUNTER += 1;
                    UI_COUNTER
                } {
                    1 => {
                        assert_eq!(params.title, "Spend from");
                        assert_eq!(params.body, "1-of-2\nBTC Testnet multisig");
                    }
                    2 => {
                        assert_eq!(params.title, "Spend from");
                        assert_eq!(params.body, "test multisig account name");
                    }
                    4 => {
                        assert_eq!(params.title, "");
                        assert_eq!(
                            params.body,
                            "Locktime on block:\n1663289\nTransaction is not RBF"
                        );
                    }
                    _ => panic!("unexpected UI dialog"),
                }
                true
            })),
            ui_transaction_address_create: Some(Box::new(move |amount, address| {
                match unsafe {
                    UI_COUNTER += 1;
                    UI_COUNTER
                } {
                    3 => {
                        assert_eq!(
                            address,
                            "tb1qtxyqynfxwsk8f5gu8v5g8e6hs3njtglkywhvyztk6v8znvx5kddsmhuve2"
                        );
                        assert_eq!(amount, "0.00090000 TBTC");
                    }
                    _ => panic!("unexpected UI dialog"),
                }
                true
            })),
            ui_transaction_fee_create: Some(Box::new(|total, fee, longtouch| {
                match unsafe {
                    UI_COUNTER += 1;
                    UI_COUNTER
                } {
                    5 => {
                        assert_eq!(total, "0.00090175 TBTC");
                        assert_eq!(fee, "0.00000175 TBTC");
                        assert!(longtouch);
                    }
                    _ => panic!("unexpected UI dialog"),
                }
                true
            })),
            ..Default::default()
        });
        mock_unlocked_using_mnemonic(
            "sudden tenant fault inject concert weather maid people chunk youth stumble grit",
            "",
        );
        // For the multisig registration below.
        mock_memory();

        // Hash of the multisig configuration as computed by `btc_common_multisig_hash_sorted()`.
        let multisig_hash = b"\x89\x75\x1d\x19\xe4\xe2\x6f\xbe\xee\x2f\xd2\xc4\xf5\x6a\xb7\xae\x5b\xe6\xdc\x46\x48\x2e\x81\x24\x1f\x4a\xcc\xfb\xc0\xa1\x58\x4e";
        bitbox02::memory::multisig_set_by_hash(multisig_hash, "test multisig account name")
            .unwrap();

        let init_request = {
            let tx = transaction.borrow();
            pb::BtcSignInitRequest {
                coin: tx.coin as _,
                script_configs: vec![pb::BtcScriptConfigWithKeypath {
                    script_config: Some(pb::BtcScriptConfig {
                        config: Some(pb::btc_script_config::Config::Multisig(
                            pb::btc_script_config::Multisig {
                                threshold: 1,
                                xpubs: vec![
                                    // sudden tenant fault inject concert weather maid people chunk
                                    // youth stumble grit / 48'/1'/0'/2'
                                    parse_xpub("xpub6EMfjyGVUvwhpc3WKN1zXhMFGKJGMaSBPqbja4tbGoYvRBSXeTBCaqrRDjcuGTcaY95JrrAnQvDG3pdQPdtnYUCugjeksHSbyZT7rq38VQF").unwrap(),
                                    // dumb rough room report huge dry sudden hamster wait foot crew
                                    // obvious / 48'/1'/0'/2'
                                    parse_xpub("xpub6ERxBysTYfQyY4USv6c6J1HNVv9hpZFN9LHVPu47Ac4rK8fLy6NnAeeAHyEsMvG4G66ay5aFZii2VM7wT3KxLKX8Q8keZPd67kRGmrD1WJj").unwrap(),
                                ],
                                our_xpub_index: 0,
                                script_type: pb::btc_script_config::multisig::ScriptType::P2wsh
                                    as _,
                            },
                        )),
                    }),
                    keypath: vec![
                        48 + HARDENED,
                        super::super::params::get(tx.coin).bip44_coin,
                        0 + HARDENED,
                        2 + HARDENED,
                    ],
                }],
                version: tx.version,
                num_inputs: tx.inputs.len() as _,
                num_outputs: tx.outputs.len() as _,
                locktime: tx.locktime,
                format_unit: FormatUnit::Default as _,
                contains_silent_payment_outputs: false,
            }
        };
        let result = block_on(process(&init_request));
        match result {
            Ok(Response::BtcSignNext(next)) => {
                assert!(next.has_signature);
                assert_eq!(&next.signature, b"\x1b\xee\x37\xe9\x12\x3f\xd3\x7f\xb8\xbe\x2d\xd2\x53\xea\x81\x0a\x02\x13\x02\xe1\x49\x62\xf4\x6e\xee\xa9\x79\xd9\x6f\xfb\x4c\x67\x69\xd0\x07\xde\x36\x0f\x50\xe1\xde\x37\x8d\xe4\x8e\x7a\x9f\xc7\x9c\x47\x24\x5b\x36\x0d\xaf\x27\x64\x75\x29\xc9\x2e\x86\xb2\x03");
            }
            _ => panic!("wrong result"),
        }
        assert_eq!(
            unsafe { UI_COUNTER },
            transaction.borrow().total_confirmations
        );
    }

    /// If the multisig has not been registered before, signing fails.
    #[test]
    fn test_multisig_not_registered() {
        let transaction = alloc::rc::Rc::new(core::cell::RefCell::new(Transaction::new_multisig()));
        mock_host_responder(transaction.clone());
        mock_default_ui();
        mock_unlocked_using_mnemonic(
            "sudden tenant fault inject concert weather maid people chunk youth stumble grit",
            "",
        );
        let init_request = {
            let tx = transaction.borrow();
            pb::BtcSignInitRequest {
                coin: tx.coin as _,
                script_configs: vec![pb::BtcScriptConfigWithKeypath {
                    script_config: Some(pb::BtcScriptConfig {
                        config: Some(pb::btc_script_config::Config::Multisig(
                            pb::btc_script_config::Multisig {
                                threshold: 1,
                                xpubs: vec![
                                    // sudden tenant fault inject concert weather maid people chunk
                                    // youth stumble grit / 48'/1'/0'/2'
                                    parse_xpub("xpub6EMfjyGVUvwhpc3WKN1zXhMFGKJGMaSBPqbja4tbGoYvRBSXeTBCaqrRDjcuGTcaY95JrrAnQvDG3pdQPdtnYUCugjeksHSbyZT7rq38VQF").unwrap(),
                                    // dumb rough room report huge dry sudden hamster wait foot crew
                                    // obvious / 48'/1'/0'/2'
                                    parse_xpub("xpub6ERxBysTYfQyY4USv6c6J1HNVv9hpZFN9LHVPu47Ac4rK8fLy6NnAeeAHyEsMvG4G66ay5aFZii2VM7wT3KxLKX8Q8keZPd67kRGmrD1WJj").unwrap(),
                                ],
                                our_xpub_index: 0,
                                script_type: pb::btc_script_config::multisig::ScriptType::P2wsh
                                    as _,
                            },
                        )),
                    }),
                    keypath: vec![
                        48 + HARDENED,
                        super::super::params::get(tx.coin).bip44_coin,
                        0 + HARDENED,
                        2 + HARDENED,
                    ],
                }],
                version: tx.version,
                num_inputs: tx.inputs.len() as _,
                num_outputs: tx.outputs.len() as _,
                locktime: tx.locktime,
                format_unit: FormatUnit::Default as _,
                contains_silent_payment_outputs: false,
            }
        };
        assert_eq!(block_on(process(&init_request)), Err(Error::InvalidInput));
    }

    #[test]
    fn test_multisig_p2wsh_p2sh() {
        let transaction = alloc::rc::Rc::new(core::cell::RefCell::new(Transaction::new_multisig()));
        for input in transaction.borrow_mut().inputs.iter_mut() {
            input.input.keypath[3] = 1 + HARDENED;
        }
        for output in transaction.borrow_mut().outputs.iter_mut() {
            if output.ours {
                output.keypath[3] = 1 + HARDENED;
            }
        }

        mock_host_responder(transaction.clone());
        mock_default_ui();
        mock_unlocked_using_mnemonic(
            "sudden tenant fault inject concert weather maid people chunk youth stumble grit",
            "",
        );
        // For the multisig registration below.
        mock_memory();

        // Hash of the multisig configuration as computed by `btc_common_multisig_hash_sorted()`.
        let multisig_hash = b"\xa0\xa9\x82\xa6\xf5\xba\x92\x86\xee\x45\xcd\x14\x0f\xd7\x63\xd4\x34\x43\xd6\x85\xa8\x9b\xc6\x07\x72\x55\x3c\xc5\x41\x8f\xcc\xc4";
        bitbox02::memory::multisig_set_by_hash(multisig_hash, "test multisig account name")
            .unwrap();

        let init_request = {
            let tx = transaction.borrow();
            pb::BtcSignInitRequest {
                coin: tx.coin as _,
                script_configs: vec![pb::BtcScriptConfigWithKeypath {
                    script_config: Some(pb::BtcScriptConfig {
                        config: Some(pb::btc_script_config::Config::Multisig(
                            pb::btc_script_config::Multisig {
                                threshold: 1,
                                xpubs: vec![
                                    // sudden tenant fault inject concert weather maid people chunk
                                    // youth stumble grit / 48'/1'/0'/1'
                                    parse_xpub("xpub6EMfjyGVUvwhn1H2BwoVysVJi9cX78eyNTkoM3d26NHW4Zd75zrAcikT3dmoii4eZPwobzK4pMBYrLmE2y918UayfqBQFr6HpVze5mQHGyu").unwrap(),
                                    // dumb rough room report huge dry sudden hamster wait foot crew
                                    // obvious / 48'/1'/0'/1'
                                    parse_xpub("xpub6ERxBysTYfQyV5NYAV6WZVj1dfTzESVGkWUiqERomNKCA6nCA8qX4qSLX2RRGNqckn3ps9B9sdfDkpg11nsJwCjXYXSZvkTED2Jx8jFpB9M").unwrap(),
                                ],
                                our_xpub_index: 0,
                                script_type: pb::btc_script_config::multisig::ScriptType::P2wshP2sh
                                    as _,
                            },
                        )),
                    }),
                    keypath: vec![
                        48 + HARDENED,
                        super::super::params::get(tx.coin).bip44_coin,
                        0 + HARDENED,
                        1 + HARDENED,
                    ],
                }],
                version: tx.version,
                num_inputs: tx.inputs.len() as _,
                num_outputs: tx.outputs.len() as _,
                locktime: tx.locktime,
                format_unit: FormatUnit::Default as _,
                contains_silent_payment_outputs: false,
            }
        };
        let result = block_on(process(&init_request));
        match result {
            Ok(Response::BtcSignNext(next)) => {
                assert!(next.has_signature);
                assert_eq!(&next.signature, b"\xa7\x23\x42\x86\x9a\x29\xb0\x24\x33\xfa\xae\x2a\xc5\xc4\x9f\x03\x3e\xff\xd3\xa6\xb6\x06\x23\x87\x8e\xf7\xbf\x8b\x14\xde\xe2\xa0\x3a\x76\x51\x1b\x37\xba\xf1\x5e\x70\x75\x07\xf4\x8b\x10\xcd\xf5\xa8\xf3\x0b\x0a\xda\x4d\xa2\x2a\x38\xa5\x47\x6f\x69\x91\x1d\x8e");
            }
            _ => panic!("wrong result"),
        }
    }

    #[test]
    fn test_multisig_large() {
        let transaction = alloc::rc::Rc::new(core::cell::RefCell::new(Transaction::new_multisig()));

        mock_host_responder(transaction.clone());
        mock_default_ui();
        mock_unlocked_using_mnemonic(
            "sudden tenant fault inject concert weather maid people chunk youth stumble grit",
            "",
        );
        // For the multisig registration below.
        mock_memory();

        // Hash of the multisig configuration as computed by `btc_common_multisig_hash_sorted()`.
        let multisig_hash = b"\x9d\xfc\x06\x52\xe2\xa3\x05\xc8\xb9\x94\x96\x20\xf9\x8e\xe1\x46\x50\x30\x2e\x38\x5f\x23\x94\x1b\xc6\x07\xcc\x35\xfd\x7a\x77\x81";
        bitbox02::memory::multisig_set_by_hash(multisig_hash, "test multisig account name")
            .unwrap();

        let init_request = {
            let tx = transaction.borrow();
            pb::BtcSignInitRequest {
                coin: tx.coin as _,
                script_configs: vec![pb::BtcScriptConfigWithKeypath {
                    script_config: Some(pb::BtcScriptConfig {
                        config: Some(pb::btc_script_config::Config::Multisig(
                            pb::btc_script_config::Multisig {
                                threshold: 7,
                                xpubs: vec![
                                    parse_xpub("xpub6Eu7xJRyXRCi4eLYhJPnfZVjgAQtM7qFaEZwUhvgxGf4enEZMxevGzWvZTawCj9USP2MFTEhKQAwnqHwoaPHetTLqGuvq5r5uaLKyGx5QDZ").unwrap(),
                                    parse_xpub("xpub6EQcxF2jFkYGn89AwoQJEEJkYMbRjED9AZgt7bkxQA5BLhZEoaQpUHcADbB5GxcMrTdDSGmjP7M3u462Q9otyE2PPam66P5KFLWitPVfYz9").unwrap(),
                                    parse_xpub("xpub6EP4EycVS5dq1PN7ZqsxBtptkYhfLvLGokZjnB3fvPshMiAohh6E5TaJjAafZWoPRjo6uiZxhtDXLgCuk81ooQgwrsnEdfSWSfa4VUtX8nu").unwrap(),
                                    parse_xpub("xpub6Eszd4BGGmHShcGtys5gbvV2zrBtW1gaorKf9YuvV4L3bePw7XePyyb2DKswZ5AhFfkcQwjQsiJEUTKhfRstRdHZUjQnJ2RJoQqL8g7FS4b").unwrap(),
                                    parse_xpub("xpub6Df3nbvH6P3FTvjgKaZcSuydyEofK545U4Bb15JY8R9MtFkKrhYrc3bpEF6fHtNM7xQ1qHwsVpS56TJWUjbKcmRwPkQr17ovV2RaVSJaBq3").unwrap(),
                                    parse_xpub("xpub6FQQ62gUYzS9wnHWHMPLWrpVnzS8xAf8XvfW1xzXEXTkTCtBrfbeww2zNeCgm3PbueMoq8opQvQDzp5Yf9EtiqVd7d1ASDoWSC1m7g1KHza").unwrap(),
                                    parse_xpub("xpub6EQNZUUAzJAoFAVVetYUrFVrf7mLyYsnHiQihkA3KPhoRHx7m6SgKBYV4z5Rd9CvUc11ACN8Ap5Wxigt6GYRPUqXGFfm3833ezJpjAmvJKt").unwrap(),
                                    parse_xpub("xpub6EGZy7cizYn2zUf9NT4qJ3Kr1ZrxdzPRcv2CwAnB1BTGWw7n9ZgDYvwmzzJXM6V7AgZ6CL3DrARZk5DzM9o8tz2RVTeC7QoHh9SxbW3b7Pw").unwrap(),
                                    parse_xpub("xpub6DaV7oCAkm4HJQMoProrrKYq1RvcgpStgYUCzLRaaeJSBSy9WBRFMNnQyAWJUYy9myUFRTvogq1C2f7x4A2yhtYgr7gL6eZXv2eJvzU12pe").unwrap(),
                                    parse_xpub("xpub6FFVRbdHt5DgHqR69KuWXRVDp93e1xKxv8rRLwhhCGnWaoF1ecnfdxpg2Nf1pvJTgT1UYg28CVt7YbUXFJL86vi9FaPN9QGtWLeCmf9dA24").unwrap(),
                                    parse_xpub("xpub6FNywxebMjvSSginZrk7DfNmAHvPJAy3j6pJ9FmUQCoh4FKPzNymdHnkA1z77Ke4GK7g5GkdrBhpyXfWTbZkH6Yo1t4v524wDwF8SAKny9J").unwrap(),
                                    parse_xpub("xpub6F1V9y6gXejomurTy2hN1UDCJidYahVkqtQJSZLYmcPcPDWkxGgWTrrLnCrCkGESSUSq6GpVVQx9kejPV97BEa9F85utABNL9r6xyPZFiDm").unwrap(),
                                    parse_xpub("xpub6ECHc4kmTC2tQg2ZoAoazwyag9C4V6yFsZEhjwMJixdVNsUibot6uEvsZY38ZLVqWCtyc9gbzFEwHQLHCT8EiDDKSNNsFAB8NQYRgkiAQwu").unwrap(),
                                    parse_xpub("xpub6F7CaxXzBCtvXwpRi61KYyhBRkgT1856ujHV5AbJK6ySCUYoDruBH6Pnsi6eHkDiuKuAJ2tSc9x3emP7aax9Dc3u7nP7RCQXEjLKihQu6w1").unwrap(),
                                    // sudden tenant fault inject concert weather maid people chunk
                                    // youth stumble grit / 48'/1'/0'/2'
                                    parse_xpub("xpub6EMfjyGVUvwhpc3WKN1zXhMFGKJGMaSBPqbja4tbGoYvRBSXeTBCaqrRDjcuGTcaY95JrrAnQvDG3pdQPdtnYUCugjeksHSbyZT7rq38VQF").unwrap(),
                                ],
                                our_xpub_index: 14,
                                script_type: pb::btc_script_config::multisig::ScriptType::P2wsh
                                    as _,
                            },
                        )),
                    }),
                    keypath: vec![
                        48 + HARDENED,
                        super::super::params::get(tx.coin).bip44_coin,
                        0 + HARDENED,
                        2 + HARDENED,
                    ],
                }],
                version: tx.version,
                num_inputs: tx.inputs.len() as _,
                num_outputs: tx.outputs.len() as _,
                locktime: tx.locktime,
                format_unit: FormatUnit::Default as _,
                contains_silent_payment_outputs: false,
            }
        };
        let result = block_on(process(&init_request));
        match result {
            Ok(Response::BtcSignNext(next)) => {
                assert!(next.has_signature);
                assert_eq!(&next.signature, b"\xdb\xed\x8b\x1a\xef\xbd\xcf\xd7\xf3\xe6\xd9\xdf\xf5\xec\x83\xc5\xed\x77\xca\xd7\x27\x8b\x06\xc5\xf4\xd3\x30\x72\xf3\x00\xc2\xd6\x13\xd1\x66\x17\x1c\x54\xd2\x02\x41\x5b\x53\x44\xa9\x2d\x4f\x6f\x9b\x36\xac\x31\x4d\xc9\x3e\x18\xbd\xcf\x61\x35\xde\x4d\x11\xbf");
            }
            _ => panic!("wrong result"),
        }
    }

    #[test]
    fn test_policy() {
        let transaction = alloc::rc::Rc::new(core::cell::RefCell::new(Transaction::new_policy()));
        mock_host_responder(transaction.clone());

        static mut UI_COUNTER: u32 = 0;
        mock(Data {
            ui_confirm_create: Some(Box::new(move |params| {
                match unsafe {
                    UI_COUNTER += 1;
                    UI_COUNTER
                } {
                    1 => {
                        assert_eq!(params.title, "Spend from");
                        assert_eq!(params.body, "BTC Testnet\npolicy with\n2 keys");
                    }
                    2 => {
                        assert_eq!(params.title, "Name");
                        assert_eq!(params.body, "test policy account name");
                    }
                    3 => {
                        assert_eq!(params.title, "");
                        assert_eq!(params.body, "Show policy\ndetails?");
                    }
                    4 => {
                        assert_eq!(params.title, "Policy");
                        assert_eq!(params.body, "wsh(multi(2,@0/**,@1/**))");
                        assert!(params.scrollable);
                    }
                    5 => {
                        assert_eq!(params.title, "Key 1/2");
                        assert_eq!(params.body, "This device: [93531fa9/48'/1'/0'/3']tpubDEjJGD6BCCuA7VHrbk3gMeQ5HocbZ4eSQ121DcvCkC8xaeRFjyoJC9iVrSz1bWfNwAY5K2Vfz5bnHR3y4RrqVpkc5ikz4trfhSyosZPrcnk");
                        assert!(params.scrollable);
                    }
                    6 => {
                        assert_eq!(params.title, "Key 2/2");
                        assert_eq!(params.body, "tpubDFGkUYFfEhAALSXQ9VNssUq71HWYLWLK7sAEqFyqJBQxQ4uGSBW1RSBkoVfijE6iEHZFs2kZrVzzV1nZCSEXYKudtsfEWcWKVXvjjLeRyd8");
                        assert!(params.scrollable);
                    }
                    8 => {
                        assert_eq!(params.title, "");
                        assert_eq!(
                            params.body,
                            "Locktime on block:\n1663289\nTransaction is not RBF"
                        );
                    }
                    _ => panic!("unexpected UI dialog"),
                }
                true
            })),
            ui_transaction_address_create: Some(Box::new(move |amount, address| {
                match unsafe {
                    UI_COUNTER += 1;
                    UI_COUNTER
                } {
                    7 => {
                        assert_eq!(
                            address,
                            "tb1qtxyqynfxwsk8f5gu8v5g8e6hs3njtglkywhvyztk6v8znvx5kddsmhuve2"
                        );
                        assert_eq!(amount, "0.00090000 TBTC");
                    }
                    _ => panic!("unexpected UI dialog"),
                }
                true
            })),
            ui_transaction_fee_create: Some(Box::new(|total, fee, longtouch| {
                match unsafe {
                    UI_COUNTER += 1;
                    UI_COUNTER
                } {
                    9 => {
                        assert_eq!(total, "0.00090175 TBTC");
                        assert_eq!(fee, "0.00000175 TBTC");
                        assert!(longtouch);
                    }
                    _ => panic!("unexpected UI dialog"),
                }
                true
            })),
            ..Default::default()
        });

        mock_unlocked_using_mnemonic(
            "sudden tenant fault inject concert weather maid people chunk youth stumble grit",
            "",
        );
        // For the policy registration below.
        mock_memory();

        let keypath_account = &[48 + HARDENED, 1 + HARDENED, 0 + HARDENED, 3 + HARDENED];

        let policy = pb::btc_script_config::Policy {
            policy: "wsh(multi(2,@0/**,@1/**))".into(),
            keys: vec![
                pb::KeyOriginInfo {
                    root_fingerprint: crate::keystore::root_fingerprint().unwrap(),
                    keypath: keypath_account.to_vec(),
                    xpub: Some(crate::keystore::get_xpub(keypath_account).unwrap().into()),
                },
                pb::KeyOriginInfo {
                    root_fingerprint: vec![],
                    keypath: vec![],
                    xpub: Some(parse_xpub("tpubDFGkUYFfEhAALSXQ9VNssUq71HWYLWLK7sAEqFyqJBQxQ4uGSBW1RSBkoVfijE6iEHZFs2kZrVzzV1nZCSEXYKudtsfEWcWKVXvjjLeRyd8").unwrap()),
                },
            ],
        };

        // Register policy.
        let policy_hash = super::super::policies::get_hash(pb::BtcCoin::Tbtc, &policy).unwrap();
        bitbox02::memory::multisig_set_by_hash(&policy_hash, "test policy account name").unwrap();

        let result = block_on(process(
            &transaction
                .borrow()
                .init_request_policy(policy, keypath_account),
        ));
        match result {
            Ok(Response::BtcSignNext(next)) => {
                assert!(next.has_signature);
                assert_eq!(&next.signature, b"\x57\x36\xb8\xee\xc7\x59\x4a\xd9\x06\xda\xf8\xd3\xfa\xc6\x4d\x58\xae\xd3\x5f\xc5\x07\x26\xb0\xed\x6d\x5f\xb1\xc8\x01\x9f\xca\xb0\x60\x6c\xed\x7d\x09\xbc\x9a\x75\xfa\xdf\x5b\xa4\x5c\xc9\x5d\xc1\x5f\xb6\x79\x69\x97\x46\x67\x39\xa9\xf6\x38\x3b\xd1\x59\xda\xe4");
            }
            _ => panic!("wrong result"),
        }
        assert_eq!(
            unsafe { UI_COUNTER },
            transaction.borrow().total_confirmations
        );
    }

    /// Test that a policy with derivations other than `/**` work.
    #[test]
    fn test_policy_different_multipath_derivations() {
        let policy_str = "wsh(multi(2,@0/<10;11>/*,@1/<20;21>/*))";

        let transaction = alloc::rc::Rc::new(core::cell::RefCell::new(Transaction::new_policy()));
        transaction.borrow_mut().inputs[0].input.keypath[4] = 10; // receive path at /10/*
        transaction.borrow_mut().outputs[0].keypath[4] = 11; // change path at /11/*

        mock_host_responder(transaction.clone());

        static mut UI_COUNTER: u32 = 0;
        mock_default_ui();

        mock_unlocked_using_mnemonic(
            "sudden tenant fault inject concert weather maid people chunk youth stumble grit",
            "",
        );
        // For the policy registration below.
        mock_memory();

        let keypath_account = &[48 + HARDENED, 1 + HARDENED, 0 + HARDENED, 3 + HARDENED];

        let policy = pb::btc_script_config::Policy {
            policy: policy_str.into(),
            keys: vec![
                pb::KeyOriginInfo {
                    root_fingerprint: crate::keystore::root_fingerprint().unwrap(),
                    keypath: keypath_account.to_vec(),
                    xpub: Some(crate::keystore::get_xpub(keypath_account).unwrap().into()),
                },
                pb::KeyOriginInfo {
                    root_fingerprint: vec![],
                    keypath: vec![],
                    xpub: Some(parse_xpub("tpubDFGkUYFfEhAALSXQ9VNssUq71HWYLWLK7sAEqFyqJBQxQ4uGSBW1RSBkoVfijE6iEHZFs2kZrVzzV1nZCSEXYKudtsfEWcWKVXvjjLeRyd8").unwrap()),
                },
            ],
        };

        // Register policy.
        let policy_hash = super::super::policies::get_hash(pb::BtcCoin::Tbtc, &policy).unwrap();
        bitbox02::memory::multisig_set_by_hash(&policy_hash, "test policy account name").unwrap();

        let result = block_on(process(
            &transaction
                .borrow()
                .init_request_policy(policy, keypath_account),
        ));
        match result {
            Ok(Response::BtcSignNext(next)) => {
                assert!(next.has_signature);
                assert_eq!(&next.signature, b"\x1c\x6b\x54\x65\x85\x9d\xb7\xdb\xd8\x8f\x17\x4d\x07\xa9\xdf\x41\x6d\x6d\xfa\x1e\x74\x29\x03\x98\x95\x84\xcd\x72\xe9\x89\xd1\x41\x48\x5a\xd9\xd7\x12\xdf\x28\x52\xa6\x50\x0e\x06\x85\x64\x04\x95\x9c\x01\x0d\x52\x54\x35\x3d\x11\xab\x31\x67\x37\x7e\xd4\xee\x88");
            }
            _ => panic!("wrong result"),
        }
    }

    #[test]
    fn test_policy_wrong_account_keypath() {
        let transaction = alloc::rc::Rc::new(core::cell::RefCell::new(Transaction::new_policy()));
        mock_host_responder(transaction.clone());

        static mut UI_COUNTER: u32 = 0;
        mock_default_ui();

        mock_unlocked_using_mnemonic(
            "sudden tenant fault inject concert weather maid people chunk youth stumble grit",
            "",
        );
        // For the policy registration below.
        mock_memory();

        let keypath_account = &[48 + HARDENED, 1 + HARDENED, 0 + HARDENED, 3 + HARDENED];
        let wrong_keypath_account = &[48 + HARDENED, 1 + HARDENED, 0 + HARDENED, 4 + HARDENED];

        let policy = pb::btc_script_config::Policy {
            policy: "wsh(multi(2,@0/**,@1/**))".into(),
            keys: vec![
                pb::KeyOriginInfo {
                    root_fingerprint: crate::keystore::root_fingerprint().unwrap(),
                    keypath: keypath_account.to_vec(),
                    xpub: Some(crate::keystore::get_xpub(keypath_account).unwrap().into()),
                },
                pb::KeyOriginInfo {
                    root_fingerprint: vec![],
                    keypath: vec![],
                    xpub: Some(parse_xpub("tpubDFGkUYFfEhAALSXQ9VNssUq71HWYLWLK7sAEqFyqJBQxQ4uGSBW1RSBkoVfijE6iEHZFs2kZrVzzV1nZCSEXYKudtsfEWcWKVXvjjLeRyd8").unwrap()),
                },
            ],
        };

        // Register policy.
        let policy_hash = super::super::policies::get_hash(pb::BtcCoin::Tbtc, &policy).unwrap();
        bitbox02::memory::multisig_set_by_hash(&policy_hash, "test policy account name").unwrap();

        assert_eq!(
            block_on(process(
                &transaction
                    .borrow()
                    .init_request_policy(policy, wrong_keypath_account)
            )),
            Err(Error::InvalidInput)
        );
    }

    /// Avoid change keypaths with a too high address index.
    #[test]
    fn test_policy_wrong_change_keypath() {
        let transaction = alloc::rc::Rc::new(core::cell::RefCell::new(Transaction::new_policy()));
        transaction.borrow_mut().outputs[0].keypath[5] = 10000; // Too high change address index.
        mock_host_responder(transaction.clone());

        static mut UI_COUNTER: u32 = 0;
        mock_default_ui();

        mock_unlocked_using_mnemonic(
            "sudden tenant fault inject concert weather maid people chunk youth stumble grit",
            "",
        );
        // For the policy registration below.
        mock_memory();

        let keypath_account = &[48 + HARDENED, 1 + HARDENED, 0 + HARDENED, 3 + HARDENED];

        let policy = pb::btc_script_config::Policy {
            policy: "wsh(multi(2,@0/**,@1/**))".into(),
            keys: vec![
                pb::KeyOriginInfo {
                    root_fingerprint: crate::keystore::root_fingerprint().unwrap(),
                    keypath: keypath_account.to_vec(),
                    xpub: Some(crate::keystore::get_xpub(keypath_account).unwrap().into()),
                },
                pb::KeyOriginInfo {
                    root_fingerprint: vec![],
                    keypath: vec![],
                    xpub: Some(parse_xpub("tpubDFGkUYFfEhAALSXQ9VNssUq71HWYLWLK7sAEqFyqJBQxQ4uGSBW1RSBkoVfijE6iEHZFs2kZrVzzV1nZCSEXYKudtsfEWcWKVXvjjLeRyd8").unwrap()),
                },
            ],
        };

        // Register policy.
        let policy_hash = super::super::policies::get_hash(pb::BtcCoin::Tbtc, &policy).unwrap();
        bitbox02::memory::multisig_set_by_hash(&policy_hash, "test policy account name").unwrap();

        assert_eq!(
            block_on(process(
                &transaction
                    .borrow()
                    .init_request_policy(policy, keypath_account)
            )),
            Err(Error::InvalidInput)
        );
    }

    #[test]
    pub fn test_payment_request() {
        let transaction =
            alloc::rc::Rc::new(core::cell::RefCell::new(Transaction::new(pb::BtcCoin::Btc)));

        // Attach second output to a payment request.
        {
            let mut tx = transaction.borrow_mut();
            // An additional confirmation for the text memo.
            tx.total_confirmations += 1;
            let payment_request_output_index = 1;
            let output_value = tx.outputs[payment_request_output_index].value;
            let mut payment_request = pb::BtcPaymentRequestRequest {
                recipient_name: "Test Merchant".into(),
                memos: vec![Memo {
                    memo: Some(memo::Memo::TextMemo(memo::TextMemo {
                        note: "Test memo".into(),
                    })),
                }],
                nonce: vec![],
                total_amount: output_value,
                signature: vec![],
            };
            let coin_params = super::super::params::get(tx.coin);
            payment_request::tst_sign_payment_request(
                coin_params,
                &mut payment_request,
                output_value,
                "34oVnh4gNviJGMnNvgquMeLAxvXJuaRVMZ",
            );
            tx.payment_request = Some(payment_request);
            tx.outputs[payment_request_output_index].payment_request_index = Some(0);
        }

        mock_host_responder(transaction.clone());
        static mut UI_COUNTER: u32 = 0;
        mock(Data {
            ui_transaction_address_create: Some(Box::new(move |amount, address| {
                match unsafe {
                    UI_COUNTER += 1;
                    UI_COUNTER
                } {
                    1 => {
                        assert_eq!(address, "12ZEw5Hcv1hTb6YUQJ69y1V7uhcoDz92PH");
                        assert_eq!(amount, "1.00000000 BTC");
                        true
                    }
                    2 => {
                        // Payment request
                        assert_eq!(address, "Test Merchant");
                        assert_eq!(amount, "12.34567890 BTC");
                        true
                    }
                    4 => {
                        assert_eq!(address, "bc1qxvenxvenxvenxvenxvenxvenxvenxven2ymjt8");
                        assert_eq!(amount, "0.00006000 BTC");
                        true
                    }
                    5 => {
                        assert_eq!(
                            address,
                            "bc1qg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zqd8sxw4"
                        );
                        assert_eq!(amount, "0.00007000 BTC");
                        true
                    }
                    _ => panic!("unexpected UI dialog"),
                }
            })),
            ui_transaction_fee_create: Some(Box::new(move |total, fee, _longtouch| {
                match unsafe {
                    UI_COUNTER += 1;
                    UI_COUNTER
                } {
                    7 => {
                        assert_eq!(total, "13.39999900 BTC");
                        assert_eq!(fee, "0.05419010 BTC");
                        true
                    }
                    _ => panic!("unexpected UI dialog"),
                }
            })),
            ui_confirm_create: Some(Box::new(|params| {
                match unsafe {
                    UI_COUNTER += 1;
                    UI_COUNTER
                } {
                    3 => {
                        assert_eq!(params.body, "Memo from Test Merchant: Test memo");
                        true
                    }
                    6 => {
                        assert_eq!(params.title, "Warning");
                        assert_eq!(params.body, "There are 2\nchange outputs.\nProceed?");
                        true
                    }
                    _ => panic!("unexpected UI dialog"),
                }
            })),
            ..Default::default()
        });
        mock_unlocked();
        bitbox02::random::mock_reset();
        let init_request = transaction.borrow().init_request();
        let result = block_on(process(&init_request));
        assert!(result.is_ok());
        assert_eq!(
            unsafe { UI_COUNTER },
            transaction.borrow().total_confirmations
        );
    }
}
