#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PubResponse {
    #[prost(string, tag = "1")]
    pub r#pub: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RootFingerprintRequest {}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RootFingerprintResponse {
    #[prost(bytes = "vec", tag = "1")]
    pub fingerprint: ::prost::alloc::vec::Vec<u8>,
}
/// See <https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki.>
/// version field dropped as it will set dynamically based on the context (xpub, ypub, etc.).
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct XPub {
    #[prost(bytes = "vec", tag = "1")]
    pub depth: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub parent_fingerprint: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint32, tag = "3")]
    pub child_num: u32,
    #[prost(bytes = "vec", tag = "4")]
    pub chain_code: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    pub public_key: ::prost::alloc::vec::Vec<u8>,
}
/// This message exists for use in oneof or repeated fields, where one can't inline `repeated uint32` due to protobuf rules.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Keypath {
    #[prost(uint32, repeated, tag = "1")]
    pub keypath: ::prost::alloc::vec::Vec<u32>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct KeyOriginInfo {
    #[prost(bytes = "vec", tag = "1")]
    pub root_fingerprint: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint32, repeated, tag = "2")]
    pub keypath: ::prost::alloc::vec::Vec<u32>,
    #[prost(message, optional, tag = "3")]
    pub xpub: ::core::option::Option<XPub>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CheckBackupRequest {
    #[prost(bool, tag = "1")]
    pub silent: bool,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CheckBackupResponse {
    #[prost(string, tag = "1")]
    pub id: ::prost::alloc::string::String,
}
/// Timestamp must be in UTC
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CreateBackupRequest {
    #[prost(uint32, tag = "1")]
    pub timestamp: u32,
    #[prost(int32, tag = "2")]
    pub timezone_offset: i32,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListBackupsRequest {}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BackupInfo {
    #[prost(string, tag = "1")]
    pub id: ::prost::alloc::string::String,
    #[prost(uint32, tag = "2")]
    pub timestamp: u32,
    /// uint32 timezone_offset = 3;
    #[prost(string, tag = "4")]
    pub name: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListBackupsResponse {
    #[prost(message, repeated, tag = "1")]
    pub info: ::prost::alloc::vec::Vec<BackupInfo>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RestoreBackupRequest {
    #[prost(string, tag = "1")]
    pub id: ::prost::alloc::string::String,
    #[prost(uint32, tag = "2")]
    pub timestamp: u32,
    #[prost(int32, tag = "3")]
    pub timezone_offset: i32,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CheckSdCardRequest {}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CheckSdCardResponse {
    #[prost(bool, tag = "1")]
    pub inserted: bool,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DeviceInfoRequest {}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DeviceInfoResponse {
    #[prost(string, tag = "1")]
    pub name: ::prost::alloc::string::String,
    #[prost(bool, tag = "2")]
    pub initialized: bool,
    #[prost(string, tag = "3")]
    pub version: ::prost::alloc::string::String,
    #[prost(bool, tag = "4")]
    pub mnemonic_passphrase_enabled: bool,
    #[prost(uint32, tag = "5")]
    pub monotonic_increments_remaining: u32,
    /// From v9.6.0: "ATECC608A" or "ATECC608B".
    #[prost(string, tag = "6")]
    pub securechip_model: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InsertRemoveSdCardRequest {
    #[prost(enumeration = "insert_remove_sd_card_request::SdCardAction", tag = "1")]
    pub action: i32,
}
/// Nested message and enum types in `InsertRemoveSDCardRequest`.
pub mod insert_remove_sd_card_request {
    #[derive(
        Clone,
        Copy,
        Debug,
        PartialEq,
        Eq,
        Hash,
        PartialOrd,
        Ord,
        ::prost::Enumeration
    )]
    #[repr(i32)]
    pub enum SdCardAction {
        RemoveCard = 0,
        InsertCard = 1,
    }
    impl SdCardAction {
        /// String value of the enum field names used in the ProtoBuf definition.
        ///
        /// The values are not transformed in any way and thus are considered stable
        /// (if the ProtoBuf definition does not change) and safe for programmatic use.
        pub fn as_str_name(&self) -> &'static str {
            match self {
                SdCardAction::RemoveCard => "REMOVE_CARD",
                SdCardAction::InsertCard => "INSERT_CARD",
            }
        }
        /// Creates an enum from field names used in the ProtoBuf definition.
        pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
            match value {
                "REMOVE_CARD" => Some(Self::RemoveCard),
                "INSERT_CARD" => Some(Self::InsertCard),
                _ => None,
            }
        }
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ResetRequest {}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SetDeviceLanguageRequest {
    #[prost(string, tag = "1")]
    pub language: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SetDeviceNameRequest {
    #[prost(string, tag = "1")]
    pub name: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SetPasswordRequest {
    #[prost(bytes = "vec", tag = "1")]
    pub entropy: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AntiKleptoHostNonceCommitment {
    #[prost(bytes = "vec", tag = "1")]
    pub commitment: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AntiKleptoSignerCommitment {
    #[prost(bytes = "vec", tag = "1")]
    pub commitment: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AntiKleptoSignatureRequest {
    #[prost(bytes = "vec", tag = "1")]
    pub host_nonce: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BtcScriptConfig {
    #[prost(oneof = "btc_script_config::Config", tags = "1, 2, 3")]
    pub config: ::core::option::Option<btc_script_config::Config>,
}
/// Nested message and enum types in `BTCScriptConfig`.
pub mod btc_script_config {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Multisig {
        #[prost(uint32, tag = "1")]
        pub threshold: u32,
        /// xpubs are acount-level xpubs. Addresses are going to be derived from it using: `m/<change>/<receive>`.
        /// The number of xpubs defines the number of cosigners.
        #[prost(message, repeated, tag = "2")]
        pub xpubs: ::prost::alloc::vec::Vec<super::XPub>,
        /// Index to the xpub of our keystore in xpubs. The keypath to it is provided via
        /// BTCPubRequest/BTCSignInit.
        #[prost(uint32, tag = "3")]
        pub our_xpub_index: u32,
        #[prost(enumeration = "multisig::ScriptType", tag = "4")]
        pub script_type: i32,
    }
    /// Nested message and enum types in `Multisig`.
    pub mod multisig {
        #[derive(
            Clone,
            Copy,
            Debug,
            PartialEq,
            Eq,
            Hash,
            PartialOrd,
            Ord,
            ::prost::Enumeration
        )]
        #[repr(i32)]
        pub enum ScriptType {
            /// native segwit v0 multisig (bech32 addresses)
            P2wsh = 0,
            /// wrapped segwit for legacy address compatibility
            P2wshP2sh = 1,
        }
        impl ScriptType {
            /// String value of the enum field names used in the ProtoBuf definition.
            ///
            /// The values are not transformed in any way and thus are considered stable
            /// (if the ProtoBuf definition does not change) and safe for programmatic use.
            pub fn as_str_name(&self) -> &'static str {
                match self {
                    ScriptType::P2wsh => "P2WSH",
                    ScriptType::P2wshP2sh => "P2WSH_P2SH",
                }
            }
            /// Creates an enum from field names used in the ProtoBuf definition.
            pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
                match value {
                    "P2WSH" => Some(Self::P2wsh),
                    "P2WSH_P2SH" => Some(Self::P2wshP2sh),
                    _ => None,
                }
            }
        }
    }
    /// A policy as specified by 'Wallet policies':
    /// <https://github.com/bitcoin/bips/pull/1389>
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Policy {
        #[prost(string, tag = "1")]
        pub policy: ::prost::alloc::string::String,
        #[prost(message, repeated, tag = "2")]
        pub keys: ::prost::alloc::vec::Vec<super::KeyOriginInfo>,
    }
    /// SimpleType is a "simple" script: one public key, no additional inputs.
    #[derive(
        Clone,
        Copy,
        Debug,
        PartialEq,
        Eq,
        Hash,
        PartialOrd,
        Ord,
        ::prost::Enumeration
    )]
    #[repr(i32)]
    pub enum SimpleType {
        P2wpkhP2sh = 0,
        P2wpkh = 1,
        P2tr = 2,
    }
    impl SimpleType {
        /// String value of the enum field names used in the ProtoBuf definition.
        ///
        /// The values are not transformed in any way and thus are considered stable
        /// (if the ProtoBuf definition does not change) and safe for programmatic use.
        pub fn as_str_name(&self) -> &'static str {
            match self {
                SimpleType::P2wpkhP2sh => "P2WPKH_P2SH",
                SimpleType::P2wpkh => "P2WPKH",
                SimpleType::P2tr => "P2TR",
            }
        }
        /// Creates an enum from field names used in the ProtoBuf definition.
        pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
            match value {
                "P2WPKH_P2SH" => Some(Self::P2wpkhP2sh),
                "P2WPKH" => Some(Self::P2wpkh),
                "P2TR" => Some(Self::P2tr),
                _ => None,
            }
        }
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Config {
        #[prost(enumeration = "SimpleType", tag = "1")]
        SimpleType(i32),
        #[prost(message, tag = "2")]
        Multisig(Multisig),
        #[prost(message, tag = "3")]
        Policy(Policy),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BtcPubRequest {
    #[prost(enumeration = "BtcCoin", tag = "1")]
    pub coin: i32,
    #[prost(uint32, repeated, tag = "2")]
    pub keypath: ::prost::alloc::vec::Vec<u32>,
    #[prost(bool, tag = "5")]
    pub display: bool,
    #[prost(oneof = "btc_pub_request::Output", tags = "3, 4")]
    pub output: ::core::option::Option<btc_pub_request::Output>,
}
/// Nested message and enum types in `BTCPubRequest`.
pub mod btc_pub_request {
    #[derive(
        Clone,
        Copy,
        Debug,
        PartialEq,
        Eq,
        Hash,
        PartialOrd,
        Ord,
        ::prost::Enumeration
    )]
    #[repr(i32)]
    pub enum XPubType {
        Tpub = 0,
        Xpub = 1,
        Ypub = 2,
        /// zpub
        Zpub = 3,
        /// vpub
        Vpub = 4,
        Upub = 5,
        /// Vpub
        CapitalVpub = 6,
        /// Zpub
        CapitalZpub = 7,
        /// Upub
        CapitalUpub = 8,
        /// Ypub
        CapitalYpub = 9,
    }
    impl XPubType {
        /// String value of the enum field names used in the ProtoBuf definition.
        ///
        /// The values are not transformed in any way and thus are considered stable
        /// (if the ProtoBuf definition does not change) and safe for programmatic use.
        pub fn as_str_name(&self) -> &'static str {
            match self {
                XPubType::Tpub => "TPUB",
                XPubType::Xpub => "XPUB",
                XPubType::Ypub => "YPUB",
                XPubType::Zpub => "ZPUB",
                XPubType::Vpub => "VPUB",
                XPubType::Upub => "UPUB",
                XPubType::CapitalVpub => "CAPITAL_VPUB",
                XPubType::CapitalZpub => "CAPITAL_ZPUB",
                XPubType::CapitalUpub => "CAPITAL_UPUB",
                XPubType::CapitalYpub => "CAPITAL_YPUB",
            }
        }
        /// Creates an enum from field names used in the ProtoBuf definition.
        pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
            match value {
                "TPUB" => Some(Self::Tpub),
                "XPUB" => Some(Self::Xpub),
                "YPUB" => Some(Self::Ypub),
                "ZPUB" => Some(Self::Zpub),
                "VPUB" => Some(Self::Vpub),
                "UPUB" => Some(Self::Upub),
                "CAPITAL_VPUB" => Some(Self::CapitalVpub),
                "CAPITAL_ZPUB" => Some(Self::CapitalZpub),
                "CAPITAL_UPUB" => Some(Self::CapitalUpub),
                "CAPITAL_YPUB" => Some(Self::CapitalYpub),
                _ => None,
            }
        }
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Output {
        #[prost(enumeration = "XPubType", tag = "3")]
        XpubType(i32),
        #[prost(message, tag = "4")]
        ScriptConfig(super::BtcScriptConfig),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BtcScriptConfigWithKeypath {
    #[prost(message, optional, tag = "2")]
    pub script_config: ::core::option::Option<BtcScriptConfig>,
    #[prost(uint32, repeated, tag = "3")]
    pub keypath: ::prost::alloc::vec::Vec<u32>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BtcSignInitRequest {
    #[prost(enumeration = "BtcCoin", tag = "1")]
    pub coin: i32,
    /// used script configs in inputs and changes
    #[prost(message, repeated, tag = "2")]
    pub script_configs: ::prost::alloc::vec::Vec<BtcScriptConfigWithKeypath>,
    /// must be 1 or 2
    #[prost(uint32, tag = "4")]
    pub version: u32,
    #[prost(uint32, tag = "5")]
    pub num_inputs: u32,
    #[prost(uint32, tag = "6")]
    pub num_outputs: u32,
    /// must be <500000000
    #[prost(uint32, tag = "7")]
    pub locktime: u32,
    #[prost(enumeration = "btc_sign_init_request::FormatUnit", tag = "8")]
    pub format_unit: i32,
}
/// Nested message and enum types in `BTCSignInitRequest`.
pub mod btc_sign_init_request {
    #[derive(
        Clone,
        Copy,
        Debug,
        PartialEq,
        Eq,
        Hash,
        PartialOrd,
        Ord,
        ::prost::Enumeration
    )]
    #[repr(i32)]
    pub enum FormatUnit {
        /// According to `coin` (BTC, LTC, etc.).
        Default = 0,
        /// Only valid for BTC/TBTC, formats as "sat"/"tsat".
        Sat = 1,
    }
    impl FormatUnit {
        /// String value of the enum field names used in the ProtoBuf definition.
        ///
        /// The values are not transformed in any way and thus are considered stable
        /// (if the ProtoBuf definition does not change) and safe for programmatic use.
        pub fn as_str_name(&self) -> &'static str {
            match self {
                FormatUnit::Default => "DEFAULT",
                FormatUnit::Sat => "SAT",
            }
        }
        /// Creates an enum from field names used in the ProtoBuf definition.
        pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
            match value {
                "DEFAULT" => Some(Self::Default),
                "SAT" => Some(Self::Sat),
                _ => None,
            }
        }
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BtcSignNextResponse {
    #[prost(enumeration = "btc_sign_next_response::Type", tag = "1")]
    pub r#type: i32,
    /// index of the current input or output
    #[prost(uint32, tag = "2")]
    pub index: u32,
    /// only as a response to BTCSignInputRequest
    #[prost(bool, tag = "3")]
    pub has_signature: bool,
    /// 64 bytes (32 bytes big endian R, 32 bytes big endian S). Only if has_signature is true.
    #[prost(bytes = "vec", tag = "4")]
    pub signature: ::prost::alloc::vec::Vec<u8>,
    /// Previous tx's input/output index in case of PREV_INPUT or PREV_OUTPUT, for the input at `index`.
    #[prost(uint32, tag = "5")]
    pub prev_index: u32,
    #[prost(message, optional, tag = "6")]
    pub anti_klepto_signer_commitment: ::core::option::Option<
        AntiKleptoSignerCommitment,
    >,
}
/// Nested message and enum types in `BTCSignNextResponse`.
pub mod btc_sign_next_response {
    #[derive(
        Clone,
        Copy,
        Debug,
        PartialEq,
        Eq,
        Hash,
        PartialOrd,
        Ord,
        ::prost::Enumeration
    )]
    #[repr(i32)]
    pub enum Type {
        Input = 0,
        Output = 1,
        Done = 2,
        /// For the previous transaction at input `index`.
        PrevtxInit = 3,
        PrevtxInput = 4,
        PrevtxOutput = 5,
        HostNonce = 6,
    }
    impl Type {
        /// String value of the enum field names used in the ProtoBuf definition.
        ///
        /// The values are not transformed in any way and thus are considered stable
        /// (if the ProtoBuf definition does not change) and safe for programmatic use.
        pub fn as_str_name(&self) -> &'static str {
            match self {
                Type::Input => "INPUT",
                Type::Output => "OUTPUT",
                Type::Done => "DONE",
                Type::PrevtxInit => "PREVTX_INIT",
                Type::PrevtxInput => "PREVTX_INPUT",
                Type::PrevtxOutput => "PREVTX_OUTPUT",
                Type::HostNonce => "HOST_NONCE",
            }
        }
        /// Creates an enum from field names used in the ProtoBuf definition.
        pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
            match value {
                "INPUT" => Some(Self::Input),
                "OUTPUT" => Some(Self::Output),
                "DONE" => Some(Self::Done),
                "PREVTX_INIT" => Some(Self::PrevtxInit),
                "PREVTX_INPUT" => Some(Self::PrevtxInput),
                "PREVTX_OUTPUT" => Some(Self::PrevtxOutput),
                "HOST_NONCE" => Some(Self::HostNonce),
                _ => None,
            }
        }
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BtcSignInputRequest {
    #[prost(bytes = "vec", tag = "1")]
    pub prev_out_hash: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint32, tag = "2")]
    pub prev_out_index: u32,
    #[prost(uint64, tag = "3")]
    pub prev_out_value: u64,
    /// must be 0xffffffff-2, 0xffffffff-1 or 0xffffffff
    #[prost(uint32, tag = "4")]
    pub sequence: u32,
    /// all inputs must be ours.
    #[prost(uint32, repeated, tag = "6")]
    pub keypath: ::prost::alloc::vec::Vec<u32>,
    /// References a script config from BTCSignInitRequest
    #[prost(uint32, tag = "7")]
    pub script_config_index: u32,
    #[prost(message, optional, tag = "8")]
    pub host_nonce_commitment: ::core::option::Option<AntiKleptoHostNonceCommitment>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BtcSignOutputRequest {
    #[prost(bool, tag = "1")]
    pub ours: bool,
    /// if ours is false
    #[prost(enumeration = "BtcOutputType", tag = "2")]
    pub r#type: i32,
    /// 20 bytes for p2pkh, p2sh, pw2wpkh. 32 bytes for p2wsh.
    #[prost(uint64, tag = "3")]
    pub value: u64,
    /// if ours is false. Renamed from `hash`.
    #[prost(bytes = "vec", tag = "4")]
    pub payload: ::prost::alloc::vec::Vec<u8>,
    /// if ours is true
    #[prost(uint32, repeated, tag = "5")]
    pub keypath: ::prost::alloc::vec::Vec<u32>,
    /// If ours is true. References a script config from BTCSignInitRequest
    #[prost(uint32, tag = "6")]
    pub script_config_index: u32,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BtcScriptConfigRegistration {
    #[prost(enumeration = "BtcCoin", tag = "1")]
    pub coin: i32,
    #[prost(message, optional, tag = "2")]
    pub script_config: ::core::option::Option<BtcScriptConfig>,
    /// Unused for policy registrations.
    #[prost(uint32, repeated, tag = "3")]
    pub keypath: ::prost::alloc::vec::Vec<u32>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BtcSuccess {}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BtcIsScriptConfigRegisteredRequest {
    #[prost(message, optional, tag = "1")]
    pub registration: ::core::option::Option<BtcScriptConfigRegistration>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BtcIsScriptConfigRegisteredResponse {
    #[prost(bool, tag = "1")]
    pub is_registered: bool,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BtcRegisterScriptConfigRequest {
    #[prost(message, optional, tag = "1")]
    pub registration: ::core::option::Option<BtcScriptConfigRegistration>,
    /// If empty, the name is entered on the device instead.
    #[prost(string, tag = "2")]
    pub name: ::prost::alloc::string::String,
    #[prost(enumeration = "btc_register_script_config_request::XPubType", tag = "3")]
    pub xpub_type: i32,
}
/// Nested message and enum types in `BTCRegisterScriptConfigRequest`.
pub mod btc_register_script_config_request {
    #[derive(
        Clone,
        Copy,
        Debug,
        PartialEq,
        Eq,
        Hash,
        PartialOrd,
        Ord,
        ::prost::Enumeration
    )]
    #[repr(i32)]
    pub enum XPubType {
        /// Automatically choose to match Electrum's xpub format (e.g. Zpub/Vpub for p2wsh multisig mainnet/testnet).
        AutoElectrum = 0,
        /// Always xpub for mainnets, tpub for testnets.
        AutoXpubTpub = 1,
    }
    impl XPubType {
        /// String value of the enum field names used in the ProtoBuf definition.
        ///
        /// The values are not transformed in any way and thus are considered stable
        /// (if the ProtoBuf definition does not change) and safe for programmatic use.
        pub fn as_str_name(&self) -> &'static str {
            match self {
                XPubType::AutoElectrum => "AUTO_ELECTRUM",
                XPubType::AutoXpubTpub => "AUTO_XPUB_TPUB",
            }
        }
        /// Creates an enum from field names used in the ProtoBuf definition.
        pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
            match value {
                "AUTO_ELECTRUM" => Some(Self::AutoElectrum),
                "AUTO_XPUB_TPUB" => Some(Self::AutoXpubTpub),
                _ => None,
            }
        }
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BtcPrevTxInitRequest {
    #[prost(uint32, tag = "1")]
    pub version: u32,
    #[prost(uint32, tag = "2")]
    pub num_inputs: u32,
    #[prost(uint32, tag = "3")]
    pub num_outputs: u32,
    #[prost(uint32, tag = "4")]
    pub locktime: u32,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BtcPrevTxInputRequest {
    #[prost(bytes = "vec", tag = "1")]
    pub prev_out_hash: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint32, tag = "2")]
    pub prev_out_index: u32,
    #[prost(bytes = "vec", tag = "3")]
    pub signature_script: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint32, tag = "4")]
    pub sequence: u32,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BtcPrevTxOutputRequest {
    #[prost(uint64, tag = "1")]
    pub value: u64,
    #[prost(bytes = "vec", tag = "2")]
    pub pubkey_script: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BtcSignMessageRequest {
    #[prost(enumeration = "BtcCoin", tag = "1")]
    pub coin: i32,
    #[prost(message, optional, tag = "2")]
    pub script_config: ::core::option::Option<BtcScriptConfigWithKeypath>,
    #[prost(bytes = "vec", tag = "3")]
    pub msg: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag = "4")]
    pub host_nonce_commitment: ::core::option::Option<AntiKleptoHostNonceCommitment>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BtcSignMessageResponse {
    /// 65 bytes (32 bytes big endian R, 32 bytes big endian S, 1 recid).
    #[prost(bytes = "vec", tag = "1")]
    pub signature: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BtcRequest {
    #[prost(oneof = "btc_request::Request", tags = "1, 2, 3, 4, 5, 6, 7")]
    pub request: ::core::option::Option<btc_request::Request>,
}
/// Nested message and enum types in `BTCRequest`.
pub mod btc_request {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Request {
        #[prost(message, tag = "1")]
        IsScriptConfigRegistered(super::BtcIsScriptConfigRegisteredRequest),
        #[prost(message, tag = "2")]
        RegisterScriptConfig(super::BtcRegisterScriptConfigRequest),
        #[prost(message, tag = "3")]
        PrevtxInit(super::BtcPrevTxInitRequest),
        #[prost(message, tag = "4")]
        PrevtxInput(super::BtcPrevTxInputRequest),
        #[prost(message, tag = "5")]
        PrevtxOutput(super::BtcPrevTxOutputRequest),
        #[prost(message, tag = "6")]
        SignMessage(super::BtcSignMessageRequest),
        #[prost(message, tag = "7")]
        AntikleptoSignature(super::AntiKleptoSignatureRequest),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BtcResponse {
    #[prost(oneof = "btc_response::Response", tags = "1, 2, 3, 4, 5")]
    pub response: ::core::option::Option<btc_response::Response>,
}
/// Nested message and enum types in `BTCResponse`.
pub mod btc_response {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Response {
        #[prost(message, tag = "1")]
        Success(super::BtcSuccess),
        #[prost(message, tag = "2")]
        IsScriptConfigRegistered(super::BtcIsScriptConfigRegisteredResponse),
        #[prost(message, tag = "3")]
        SignNext(super::BtcSignNextResponse),
        #[prost(message, tag = "4")]
        SignMessage(super::BtcSignMessageResponse),
        #[prost(message, tag = "5")]
        AntikleptoSignerCommitment(super::AntiKleptoSignerCommitment),
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum BtcCoin {
    Btc = 0,
    Tbtc = 1,
    Ltc = 2,
    Tltc = 3,
}
impl BtcCoin {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            BtcCoin::Btc => "BTC",
            BtcCoin::Tbtc => "TBTC",
            BtcCoin::Ltc => "LTC",
            BtcCoin::Tltc => "TLTC",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "BTC" => Some(Self::Btc),
            "TBTC" => Some(Self::Tbtc),
            "LTC" => Some(Self::Ltc),
            "TLTC" => Some(Self::Tltc),
            _ => None,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum BtcOutputType {
    Unknown = 0,
    P2pkh = 1,
    P2sh = 2,
    P2wpkh = 3,
    P2wsh = 4,
    P2tr = 5,
}
impl BtcOutputType {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            BtcOutputType::Unknown => "UNKNOWN",
            BtcOutputType::P2pkh => "P2PKH",
            BtcOutputType::P2sh => "P2SH",
            BtcOutputType::P2wpkh => "P2WPKH",
            BtcOutputType::P2wsh => "P2WSH",
            BtcOutputType::P2tr => "P2TR",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "UNKNOWN" => Some(Self::Unknown),
            "P2PKH" => Some(Self::P2pkh),
            "P2SH" => Some(Self::P2sh),
            "P2WPKH" => Some(Self::P2wpkh),
            "P2WSH" => Some(Self::P2wsh),
            "P2TR" => Some(Self::P2tr),
            _ => None,
        }
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CardanoXpubsRequest {
    #[prost(message, repeated, tag = "1")]
    pub keypaths: ::prost::alloc::vec::Vec<Keypath>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CardanoXpubsResponse {
    #[prost(bytes = "vec", repeated, tag = "1")]
    pub xpubs: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CardanoScriptConfig {
    /// Entries correspond to address types as described in:
    /// <https://github.com/cardano-foundation/CIPs/blob/6c249ef48f8f5b32efc0ec768fadf4321f3173f2/CIP-0019/CIP-0019.md>
    /// See also:
    /// <https://github.com/input-output-hk/cardano-ledger-specs/blob/d0aa86ded0b973b09b629e5aa62aa1e71364d088/eras/alonzo/test-suite/cddl-files/alonzo.cddl#L137>
    #[prost(oneof = "cardano_script_config::Config", tags = "1")]
    pub config: ::core::option::Option<cardano_script_config::Config>,
}
/// Nested message and enum types in `CardanoScriptConfig`.
pub mod cardano_script_config {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct PkhSkh {
        #[prost(uint32, repeated, tag = "1")]
        pub keypath_payment: ::prost::alloc::vec::Vec<u32>,
        #[prost(uint32, repeated, tag = "2")]
        pub keypath_stake: ::prost::alloc::vec::Vec<u32>,
    }
    /// Entries correspond to address types as described in:
    /// <https://github.com/cardano-foundation/CIPs/blob/6c249ef48f8f5b32efc0ec768fadf4321f3173f2/CIP-0019/CIP-0019.md>
    /// See also:
    /// <https://github.com/input-output-hk/cardano-ledger-specs/blob/d0aa86ded0b973b09b629e5aa62aa1e71364d088/eras/alonzo/test-suite/cddl-files/alonzo.cddl#L137>
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Config {
        /// Shelley PaymentKeyHash & StakeKeyHash
        #[prost(message, tag = "1")]
        PkhSkh(PkhSkh),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CardanoAddressRequest {
    #[prost(enumeration = "CardanoNetwork", tag = "1")]
    pub network: i32,
    #[prost(bool, tag = "2")]
    pub display: bool,
    #[prost(message, optional, tag = "3")]
    pub script_config: ::core::option::Option<CardanoScriptConfig>,
}
/// Max allowed transaction size is 16384 bytes according to
/// <https://github.com/cardano-foundation/CIPs/blob/master/CIP-0009/CIP-0009.md.> Unlike with BTC, we
/// can fit the whole request in RAM and don't need to stream.
///
/// See also: <https://github.com/input-output-hk/cardano-ledger-specs/blob/d0aa86ded0b973b09b629e5aa62aa1e71364d088/eras/alonzo/test-suite/cddl-files/alonzo.cddl#L50>
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CardanoSignTransactionRequest {
    #[prost(enumeration = "CardanoNetwork", tag = "1")]
    pub network: i32,
    #[prost(message, repeated, tag = "2")]
    pub inputs: ::prost::alloc::vec::Vec<cardano_sign_transaction_request::Input>,
    #[prost(message, repeated, tag = "3")]
    pub outputs: ::prost::alloc::vec::Vec<cardano_sign_transaction_request::Output>,
    #[prost(uint64, tag = "4")]
    pub fee: u64,
    #[prost(uint64, tag = "5")]
    pub ttl: u64,
    #[prost(message, repeated, tag = "6")]
    pub certificates: ::prost::alloc::vec::Vec<
        cardano_sign_transaction_request::Certificate,
    >,
    #[prost(message, repeated, tag = "7")]
    pub withdrawals: ::prost::alloc::vec::Vec<
        cardano_sign_transaction_request::Withdrawal,
    >,
    #[prost(uint64, tag = "8")]
    pub validity_interval_start: u64,
    /// include ttl even if it is zero
    #[prost(bool, tag = "9")]
    pub allow_zero_ttl: bool,
}
/// Nested message and enum types in `CardanoSignTransactionRequest`.
pub mod cardano_sign_transaction_request {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Input {
        #[prost(uint32, repeated, tag = "1")]
        pub keypath: ::prost::alloc::vec::Vec<u32>,
        #[prost(bytes = "vec", tag = "2")]
        pub prev_out_hash: ::prost::alloc::vec::Vec<u8>,
        #[prost(uint32, tag = "3")]
        pub prev_out_index: u32,
    }
    /// <https://github.com/input-output-hk/cardano-ledger/blob/d0aa86ded0b973b09b629e5aa62aa1e71364d088/eras/alonzo/test-suite/cddl-files/alonzo.cddl#L358>
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct AssetGroup {
        #[prost(bytes = "vec", tag = "1")]
        pub policy_id: ::prost::alloc::vec::Vec<u8>,
        #[prost(message, repeated, tag = "2")]
        pub tokens: ::prost::alloc::vec::Vec<asset_group::Token>,
    }
    /// Nested message and enum types in `AssetGroup`.
    pub mod asset_group {
        #[allow(clippy::derive_partial_eq_without_eq)]
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct Token {
            #[prost(bytes = "vec", tag = "1")]
            pub asset_name: ::prost::alloc::vec::Vec<u8>,
            /// Number of tokens transacted of this asset.
            #[prost(uint64, tag = "2")]
            pub value: u64,
        }
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Output {
        #[prost(string, tag = "1")]
        pub encoded_address: ::prost::alloc::string::String,
        #[prost(uint64, tag = "2")]
        pub value: u64,
        /// Optional. If provided, this is validated as a change output.
        #[prost(message, optional, tag = "3")]
        pub script_config: ::core::option::Option<super::CardanoScriptConfig>,
        #[prost(message, repeated, tag = "4")]
        pub asset_groups: ::prost::alloc::vec::Vec<AssetGroup>,
    }
    /// See <https://github.com/input-output-hk/cardano-ledger-specs/blob/d0aa86ded0b973b09b629e5aa62aa1e71364d088/eras/alonzo/test-suite/cddl-files/alonzo.cddl#L150>
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Certificate {
        #[prost(oneof = "certificate::Cert", tags = "1, 2, 3")]
        pub cert: ::core::option::Option<certificate::Cert>,
    }
    /// Nested message and enum types in `Certificate`.
    pub mod certificate {
        #[allow(clippy::derive_partial_eq_without_eq)]
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct StakeDelegation {
            #[prost(uint32, repeated, tag = "1")]
            pub keypath: ::prost::alloc::vec::Vec<u32>,
            #[prost(bytes = "vec", tag = "2")]
            pub pool_keyhash: ::prost::alloc::vec::Vec<u8>,
        }
        #[allow(clippy::derive_partial_eq_without_eq)]
        #[derive(Clone, PartialEq, ::prost::Oneof)]
        pub enum Cert {
            #[prost(message, tag = "1")]
            StakeRegistration(super::super::Keypath),
            #[prost(message, tag = "2")]
            StakeDeregistration(super::super::Keypath),
            #[prost(message, tag = "3")]
            StakeDelegation(StakeDelegation),
        }
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Withdrawal {
        #[prost(uint32, repeated, tag = "1")]
        pub keypath: ::prost::alloc::vec::Vec<u32>,
        #[prost(uint64, tag = "2")]
        pub value: u64,
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CardanoSignTransactionResponse {
    #[prost(message, repeated, tag = "1")]
    pub shelley_witnesses: ::prost::alloc::vec::Vec<
        cardano_sign_transaction_response::ShelleyWitness,
    >,
}
/// Nested message and enum types in `CardanoSignTransactionResponse`.
pub mod cardano_sign_transaction_response {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct ShelleyWitness {
        #[prost(bytes = "vec", tag = "1")]
        pub public_key: ::prost::alloc::vec::Vec<u8>,
        #[prost(bytes = "vec", tag = "2")]
        pub signature: ::prost::alloc::vec::Vec<u8>,
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CardanoRequest {
    #[prost(oneof = "cardano_request::Request", tags = "1, 2, 3")]
    pub request: ::core::option::Option<cardano_request::Request>,
}
/// Nested message and enum types in `CardanoRequest`.
pub mod cardano_request {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Request {
        #[prost(message, tag = "1")]
        Xpubs(super::CardanoXpubsRequest),
        #[prost(message, tag = "2")]
        Address(super::CardanoAddressRequest),
        #[prost(message, tag = "3")]
        SignTransaction(super::CardanoSignTransactionRequest),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CardanoResponse {
    #[prost(oneof = "cardano_response::Response", tags = "1, 2, 3")]
    pub response: ::core::option::Option<cardano_response::Response>,
}
/// Nested message and enum types in `CardanoResponse`.
pub mod cardano_response {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Response {
        #[prost(message, tag = "1")]
        Xpubs(super::CardanoXpubsResponse),
        #[prost(message, tag = "2")]
        Pub(super::PubResponse),
        #[prost(message, tag = "3")]
        SignTransaction(super::CardanoSignTransactionResponse),
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum CardanoNetwork {
    CardanoMainnet = 0,
    CardanoTestnet = 1,
}
impl CardanoNetwork {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            CardanoNetwork::CardanoMainnet => "CardanoMainnet",
            CardanoNetwork::CardanoTestnet => "CardanoTestnet",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "CardanoMainnet" => Some(Self::CardanoMainnet),
            "CardanoTestnet" => Some(Self::CardanoTestnet),
            _ => None,
        }
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EthPubRequest {
    #[prost(uint32, repeated, tag = "1")]
    pub keypath: ::prost::alloc::vec::Vec<u32>,
    /// Deprecated: use chain_id instead.
    #[prost(enumeration = "EthCoin", tag = "2")]
    pub coin: i32,
    #[prost(enumeration = "eth_pub_request::OutputType", tag = "3")]
    pub output_type: i32,
    #[prost(bool, tag = "4")]
    pub display: bool,
    #[prost(bytes = "vec", tag = "5")]
    pub contract_address: ::prost::alloc::vec::Vec<u8>,
    /// If non-zero, `coin` is ignored and `chain_id` is used to identify the network.
    #[prost(uint64, tag = "6")]
    pub chain_id: u64,
}
/// Nested message and enum types in `ETHPubRequest`.
pub mod eth_pub_request {
    #[derive(
        Clone,
        Copy,
        Debug,
        PartialEq,
        Eq,
        Hash,
        PartialOrd,
        Ord,
        ::prost::Enumeration
    )]
    #[repr(i32)]
    pub enum OutputType {
        Address = 0,
        Xpub = 1,
    }
    impl OutputType {
        /// String value of the enum field names used in the ProtoBuf definition.
        ///
        /// The values are not transformed in any way and thus are considered stable
        /// (if the ProtoBuf definition does not change) and safe for programmatic use.
        pub fn as_str_name(&self) -> &'static str {
            match self {
                OutputType::Address => "ADDRESS",
                OutputType::Xpub => "XPUB",
            }
        }
        /// Creates an enum from field names used in the ProtoBuf definition.
        pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
            match value {
                "ADDRESS" => Some(Self::Address),
                "XPUB" => Some(Self::Xpub),
                _ => None,
            }
        }
    }
}
/// TX payload for "legacy" (EIP-155) transactions: <https://eips.ethereum.org/EIPS/eip-155>
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EthSignRequest {
    /// Deprecated: use chain_id instead.
    #[prost(enumeration = "EthCoin", tag = "1")]
    pub coin: i32,
    #[prost(uint32, repeated, tag = "2")]
    pub keypath: ::prost::alloc::vec::Vec<u32>,
    /// smallest big endian serialization, max. 16 bytes
    #[prost(bytes = "vec", tag = "3")]
    pub nonce: ::prost::alloc::vec::Vec<u8>,
    /// smallest big endian serialization, max. 16 bytes
    #[prost(bytes = "vec", tag = "4")]
    pub gas_price: ::prost::alloc::vec::Vec<u8>,
    /// smallest big endian serialization, max. 16 bytes
    #[prost(bytes = "vec", tag = "5")]
    pub gas_limit: ::prost::alloc::vec::Vec<u8>,
    /// 20 byte recipient
    #[prost(bytes = "vec", tag = "6")]
    pub recipient: ::prost::alloc::vec::Vec<u8>,
    /// smallest big endian serialization, max. 32 bytes
    #[prost(bytes = "vec", tag = "7")]
    pub value: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "8")]
    pub data: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag = "9")]
    pub host_nonce_commitment: ::core::option::Option<AntiKleptoHostNonceCommitment>,
    /// If non-zero, `coin` is ignored and `chain_id` is used to identify the network.
    #[prost(uint64, tag = "10")]
    pub chain_id: u64,
    #[prost(string, tag = "11")]
    pub address: ::prost::alloc::string::String,
}
/// TX payload for an EIP-1559 (type 2) transaction: <https://eips.ethereum.org/EIPS/eip-1559>
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EthSignEip1559Request {
    #[prost(uint64, tag = "1")]
    pub chain_id: u64,
    #[prost(uint32, repeated, tag = "2")]
    pub keypath: ::prost::alloc::vec::Vec<u32>,
    /// smallest big endian serialization, max. 16 bytes
    #[prost(bytes = "vec", tag = "3")]
    pub nonce: ::prost::alloc::vec::Vec<u8>,
    /// smallest big endian serialization, max. 16 bytes
    #[prost(bytes = "vec", tag = "4")]
    pub max_priority_fee_per_gas: ::prost::alloc::vec::Vec<u8>,
    /// smallest big endian serialization, max. 16 bytes
    #[prost(bytes = "vec", tag = "5")]
    pub max_fee_per_gas: ::prost::alloc::vec::Vec<u8>,
    /// smallest big endian serialization, max. 16 bytes
    #[prost(bytes = "vec", tag = "6")]
    pub gas_limit: ::prost::alloc::vec::Vec<u8>,
    /// 20 byte recipient
    #[prost(bytes = "vec", tag = "7")]
    pub recipient: ::prost::alloc::vec::Vec<u8>,
    /// smallest big endian serialization, max. 32 bytes
    #[prost(bytes = "vec", tag = "8")]
    pub value: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "9")]
    pub data: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag = "10")]
    pub host_nonce_commitment: ::core::option::Option<AntiKleptoHostNonceCommitment>,
    #[prost(string, tag = "11")]
    pub address: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EthSignMessageRequest {
    /// Deprecated: use chain_id instead.
    #[prost(enumeration = "EthCoin", tag = "1")]
    pub coin: i32,
    #[prost(uint32, repeated, tag = "2")]
    pub keypath: ::prost::alloc::vec::Vec<u32>,
    #[prost(bytes = "vec", tag = "3")]
    pub msg: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag = "4")]
    pub host_nonce_commitment: ::core::option::Option<AntiKleptoHostNonceCommitment>,
    /// If non-zero, `coin` is ignored and `chain_id` is used to identify the network.
    #[prost(uint64, tag = "5")]
    pub chain_id: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EthSignResponse {
    /// 65 bytes, last byte is the recid
    #[prost(bytes = "vec", tag = "1")]
    pub signature: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EthSignTypedMessageRequest {
    #[prost(uint64, tag = "1")]
    pub chain_id: u64,
    #[prost(uint32, repeated, tag = "2")]
    pub keypath: ::prost::alloc::vec::Vec<u32>,
    #[prost(message, repeated, tag = "3")]
    pub types: ::prost::alloc::vec::Vec<eth_sign_typed_message_request::StructType>,
    #[prost(string, tag = "4")]
    pub primary_type: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "5")]
    pub host_nonce_commitment: ::core::option::Option<AntiKleptoHostNonceCommitment>,
}
/// Nested message and enum types in `ETHSignTypedMessageRequest`.
pub mod eth_sign_typed_message_request {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct MemberType {
        #[prost(enumeration = "DataType", tag = "1")]
        pub r#type: i32,
        #[prost(uint32, tag = "2")]
        pub size: u32,
        /// if type==STRUCT, name of struct type.
        #[prost(string, tag = "3")]
        pub struct_name: ::prost::alloc::string::String,
        /// if type==ARRAY, type of elements
        #[prost(message, optional, boxed, tag = "4")]
        pub array_type: ::core::option::Option<::prost::alloc::boxed::Box<MemberType>>,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Member {
        #[prost(string, tag = "1")]
        pub name: ::prost::alloc::string::String,
        #[prost(message, optional, tag = "2")]
        pub r#type: ::core::option::Option<MemberType>,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct StructType {
        #[prost(string, tag = "1")]
        pub name: ::prost::alloc::string::String,
        #[prost(message, repeated, tag = "2")]
        pub members: ::prost::alloc::vec::Vec<Member>,
    }
    #[derive(
        Clone,
        Copy,
        Debug,
        PartialEq,
        Eq,
        Hash,
        PartialOrd,
        Ord,
        ::prost::Enumeration
    )]
    #[repr(i32)]
    pub enum DataType {
        Unknown = 0,
        Bytes = 1,
        Uint = 2,
        Int = 3,
        Bool = 4,
        Address = 5,
        String = 6,
        Array = 7,
        Struct = 8,
    }
    impl DataType {
        /// String value of the enum field names used in the ProtoBuf definition.
        ///
        /// The values are not transformed in any way and thus are considered stable
        /// (if the ProtoBuf definition does not change) and safe for programmatic use.
        pub fn as_str_name(&self) -> &'static str {
            match self {
                DataType::Unknown => "UNKNOWN",
                DataType::Bytes => "BYTES",
                DataType::Uint => "UINT",
                DataType::Int => "INT",
                DataType::Bool => "BOOL",
                DataType::Address => "ADDRESS",
                DataType::String => "STRING",
                DataType::Array => "ARRAY",
                DataType::Struct => "STRUCT",
            }
        }
        /// Creates an enum from field names used in the ProtoBuf definition.
        pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
            match value {
                "UNKNOWN" => Some(Self::Unknown),
                "BYTES" => Some(Self::Bytes),
                "UINT" => Some(Self::Uint),
                "INT" => Some(Self::Int),
                "BOOL" => Some(Self::Bool),
                "ADDRESS" => Some(Self::Address),
                "STRING" => Some(Self::String),
                "ARRAY" => Some(Self::Array),
                "STRUCT" => Some(Self::Struct),
                _ => None,
            }
        }
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EthTypedMessageValueResponse {
    #[prost(enumeration = "eth_typed_message_value_response::RootObject", tag = "1")]
    pub root_object: i32,
    #[prost(uint32, repeated, tag = "2")]
    pub path: ::prost::alloc::vec::Vec<u32>,
}
/// Nested message and enum types in `ETHTypedMessageValueResponse`.
pub mod eth_typed_message_value_response {
    #[derive(
        Clone,
        Copy,
        Debug,
        PartialEq,
        Eq,
        Hash,
        PartialOrd,
        Ord,
        ::prost::Enumeration
    )]
    #[repr(i32)]
    pub enum RootObject {
        Unknown = 0,
        Domain = 1,
        Message = 2,
    }
    impl RootObject {
        /// String value of the enum field names used in the ProtoBuf definition.
        ///
        /// The values are not transformed in any way and thus are considered stable
        /// (if the ProtoBuf definition does not change) and safe for programmatic use.
        pub fn as_str_name(&self) -> &'static str {
            match self {
                RootObject::Unknown => "UNKNOWN",
                RootObject::Domain => "DOMAIN",
                RootObject::Message => "MESSAGE",
            }
        }
        /// Creates an enum from field names used in the ProtoBuf definition.
        pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
            match value {
                "UNKNOWN" => Some(Self::Unknown),
                "DOMAIN" => Some(Self::Domain),
                "MESSAGE" => Some(Self::Message),
                _ => None,
            }
        }
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EthTypedMessageValueRequest {
    #[prost(bytes = "vec", tag = "1")]
    pub value: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EthRequest {
    #[prost(oneof = "eth_request::Request", tags = "1, 2, 3, 4, 5, 6, 7")]
    pub request: ::core::option::Option<eth_request::Request>,
}
/// Nested message and enum types in `ETHRequest`.
pub mod eth_request {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Request {
        #[prost(message, tag = "1")]
        Pub(super::EthPubRequest),
        #[prost(message, tag = "2")]
        Sign(super::EthSignRequest),
        #[prost(message, tag = "3")]
        SignMsg(super::EthSignMessageRequest),
        #[prost(message, tag = "4")]
        AntikleptoSignature(super::AntiKleptoSignatureRequest),
        #[prost(message, tag = "5")]
        SignTypedMsg(super::EthSignTypedMessageRequest),
        #[prost(message, tag = "6")]
        TypedMsgValue(super::EthTypedMessageValueRequest),
        #[prost(message, tag = "7")]
        SignEip1559(super::EthSignEip1559Request),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EthResponse {
    #[prost(oneof = "eth_response::Response", tags = "1, 2, 3, 4")]
    pub response: ::core::option::Option<eth_response::Response>,
}
/// Nested message and enum types in `ETHResponse`.
pub mod eth_response {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Response {
        #[prost(message, tag = "1")]
        Pub(super::PubResponse),
        #[prost(message, tag = "2")]
        Sign(super::EthSignResponse),
        #[prost(message, tag = "3")]
        AntikleptoSignerCommitment(super::AntiKleptoSignerCommitment),
        #[prost(message, tag = "4")]
        TypedMsgValue(super::EthTypedMessageValueResponse),
    }
}
/// Kept for backwards compatibility. Use chain_id instead, introduced in v9.10.0.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum EthCoin {
    Eth = 0,
    /// Removed in v9.14.0 - deprecated
    RopstenEth = 1,
    /// Removed in v9.14.0 - deprecated
    RinkebyEth = 2,
}
impl EthCoin {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            EthCoin::Eth => "ETH",
            EthCoin::RopstenEth => "RopstenETH",
            EthCoin::RinkebyEth => "RinkebyETH",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "ETH" => Some(Self::Eth),
            "RopstenETH" => Some(Self::RopstenEth),
            "RinkebyETH" => Some(Self::RinkebyEth),
            _ => None,
        }
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ElectrumEncryptionKeyRequest {
    #[prost(uint32, repeated, tag = "1")]
    pub keypath: ::prost::alloc::vec::Vec<u32>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ElectrumEncryptionKeyResponse {
    #[prost(string, tag = "1")]
    pub key: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ShowMnemonicRequest {}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RestoreFromMnemonicRequest {
    #[prost(uint32, tag = "1")]
    pub timestamp: u32,
    #[prost(int32, tag = "2")]
    pub timezone_offset: i32,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SetMnemonicPassphraseEnabledRequest {
    #[prost(bool, tag = "1")]
    pub enabled: bool,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RebootRequest {
    #[prost(enumeration = "reboot_request::Purpose", tag = "1")]
    pub purpose: i32,
}
/// Nested message and enum types in `RebootRequest`.
pub mod reboot_request {
    #[derive(
        Clone,
        Copy,
        Debug,
        PartialEq,
        Eq,
        Hash,
        PartialOrd,
        Ord,
        ::prost::Enumeration
    )]
    #[repr(i32)]
    pub enum Purpose {
        Upgrade = 0,
        Settings = 1,
    }
    impl Purpose {
        /// String value of the enum field names used in the ProtoBuf definition.
        ///
        /// The values are not transformed in any way and thus are considered stable
        /// (if the ProtoBuf definition does not change) and safe for programmatic use.
        pub fn as_str_name(&self) -> &'static str {
            match self {
                Purpose::Upgrade => "UPGRADE",
                Purpose::Settings => "SETTINGS",
            }
        }
        /// Creates an enum from field names used in the ProtoBuf definition.
        pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
            match value {
                "UPGRADE" => Some(Self::Upgrade),
                "SETTINGS" => Some(Self::Settings),
                _ => None,
            }
        }
    }
}
/// Deprecated, last used in v1.0.0
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PerformAttestationRequest {
    /// 32 bytes challenge.
    #[prost(bytes = "vec", tag = "1")]
    pub challenge: ::prost::alloc::vec::Vec<u8>,
}
/// Deprecated, last used in v1.0.0
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PerformAttestationResponse {
    #[prost(bytes = "vec", tag = "1")]
    pub bootloader_hash: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub device_pubkey: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub certificate: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub root_pubkey_identifier: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    pub challenge_signature: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Error {
    #[prost(int32, tag = "1")]
    pub code: i32,
    #[prost(string, tag = "2")]
    pub message: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Success {}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Request {
    #[prost(
        oneof = "request::Request",
        tags = "2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 24, 25, 26, 27"
    )]
    pub request: ::core::option::Option<request::Request>,
}
/// Nested message and enum types in `Request`.
pub mod request {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Request {
        /// removed: RandomNumberRequest random_number = 1;
        #[prost(message, tag = "2")]
        DeviceName(super::SetDeviceNameRequest),
        #[prost(message, tag = "3")]
        DeviceLanguage(super::SetDeviceLanguageRequest),
        #[prost(message, tag = "4")]
        DeviceInfo(super::DeviceInfoRequest),
        #[prost(message, tag = "5")]
        SetPassword(super::SetPasswordRequest),
        #[prost(message, tag = "6")]
        CreateBackup(super::CreateBackupRequest),
        #[prost(message, tag = "7")]
        ShowMnemonic(super::ShowMnemonicRequest),
        #[prost(message, tag = "8")]
        BtcPub(super::BtcPubRequest),
        #[prost(message, tag = "9")]
        BtcSignInit(super::BtcSignInitRequest),
        #[prost(message, tag = "10")]
        BtcSignInput(super::BtcSignInputRequest),
        #[prost(message, tag = "11")]
        BtcSignOutput(super::BtcSignOutputRequest),
        #[prost(message, tag = "12")]
        InsertRemoveSdcard(super::InsertRemoveSdCardRequest),
        #[prost(message, tag = "13")]
        CheckSdcard(super::CheckSdCardRequest),
        #[prost(message, tag = "14")]
        SetMnemonicPassphraseEnabled(super::SetMnemonicPassphraseEnabledRequest),
        #[prost(message, tag = "15")]
        ListBackups(super::ListBackupsRequest),
        #[prost(message, tag = "16")]
        RestoreBackup(super::RestoreBackupRequest),
        #[prost(message, tag = "17")]
        PerformAttestation(super::PerformAttestationRequest),
        #[prost(message, tag = "18")]
        Reboot(super::RebootRequest),
        #[prost(message, tag = "19")]
        CheckBackup(super::CheckBackupRequest),
        #[prost(message, tag = "20")]
        Eth(super::EthRequest),
        #[prost(message, tag = "21")]
        Reset(super::ResetRequest),
        #[prost(message, tag = "22")]
        RestoreFromMnemonic(super::RestoreFromMnemonicRequest),
        /// removed: BitBoxBaseRequest bitboxbase = 23;
        #[prost(message, tag = "24")]
        Fingerprint(super::RootFingerprintRequest),
        #[prost(message, tag = "25")]
        Btc(super::BtcRequest),
        #[prost(message, tag = "26")]
        ElectrumEncryptionKey(super::ElectrumEncryptionKeyRequest),
        #[prost(message, tag = "27")]
        Cardano(super::CardanoRequest),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Response {
    #[prost(
        oneof = "response::Response",
        tags = "1, 2, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15"
    )]
    pub response: ::core::option::Option<response::Response>,
}
/// Nested message and enum types in `Response`.
pub mod response {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Response {
        #[prost(message, tag = "1")]
        Success(super::Success),
        #[prost(message, tag = "2")]
        Error(super::Error),
        /// removed: RandomNumberResponse random_number = 3;
        #[prost(message, tag = "4")]
        DeviceInfo(super::DeviceInfoResponse),
        #[prost(message, tag = "5")]
        Pub(super::PubResponse),
        #[prost(message, tag = "6")]
        BtcSignNext(super::BtcSignNextResponse),
        #[prost(message, tag = "7")]
        ListBackups(super::ListBackupsResponse),
        #[prost(message, tag = "8")]
        CheckBackup(super::CheckBackupResponse),
        #[prost(message, tag = "9")]
        PerformAttestation(super::PerformAttestationResponse),
        #[prost(message, tag = "10")]
        CheckSdcard(super::CheckSdCardResponse),
        #[prost(message, tag = "11")]
        Eth(super::EthResponse),
        #[prost(message, tag = "12")]
        Fingerprint(super::RootFingerprintResponse),
        #[prost(message, tag = "13")]
        Btc(super::BtcResponse),
        #[prost(message, tag = "14")]
        ElectrumEncryptionKey(super::ElectrumEncryptionKeyResponse),
        #[prost(message, tag = "15")]
        Cardano(super::CardanoResponse),
    }
}
