// Written by Clark Moody and the rust-bitcoin developers.
// SPDX-License-Identifier: MIT

//! Encoding and decoding of the Bech32 format.
//!
//! Bech32 is an encoding scheme that is easy to use for humans and efficient to encode in QR codes.
//!
//! A Bech32 string consists of a human-readable part (HRP), a separator (the character `'1'`), and
//! a data part. A checksum at the end of the string provides error detection to prevent mistakes
//! when the string is written off or read out loud.
//!
//! # Usage
//!
//! - If you are doing segwit stuff you likely want to use the [`segwit`] API.
//! - Non-segwit stuff and you have an allocator, use the top level API. For normal usage the
//!   [`encode`] and [`decode`] functions should suffice. There are also various other functions for
//!   explicit control of the checksum algorithm and the case used when encoding.
//! - Non-segwit stuff and you do *not* have an allocator, use the
//!   [`primitives::decode::CheckedHrpstring`] type for decoding. For encoding we provide various
//!   top level functions of the form `encode*_to_fmt`.
//! - To define your own checksum algorithm implement [`crate::Checksum`] (see example below).
//!
//! The original description in [BIP-0173](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki)
//! has more details. See also [BIP-0350](https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki).
//!
//! # Examples
//!
//! ## Encoding
//!
//! ```
//! # #[cfg(feature = "alloc")] {
//! use bech32::{hrp, segwit, Hrp, Bech32m};
//!
//! const DATA: [u8; 20] = [0xab; 20]; // Arbitrary data to be encoded.
//! const ADDR: &str = "abc14w46h2at4w46h2at4w46h2at4w46h2at958ngu";
//! const TAP_ADDR: &str = "bc1p4w46h2at4w46h2at4w46h2at4w46h2at5kreae";
//!
//! // Encode arbitrary data using "abc" as the human-readable part and append a bech32m checksum.
//! let hrp = Hrp::parse("abc").expect("valid hrp");
//! let address = bech32::encode::<Bech32m>(hrp, &DATA).expect("failed to encode address");
//! assert_eq!(address, ADDR);
//!
//! // Encode arbitrary data as a Bitcoin taproot address.
//! let taproot_address = segwit::encode(&hrp::BC, segwit::VERSION_1, &DATA).expect("valid witness version and program");
//! assert_eq!(taproot_address, TAP_ADDR);
//!
//! // No-alloc: Encode without allocating (ignoring that String::new() allocates :).
//! let mut buf = String::new();
//! bech32::encode_to_fmt::<Bech32m, String>(&mut buf, hrp, &DATA).expect("failed to encode to buffer");
//! assert_eq!(buf, ADDR);
//! # }
//! ```
//!
//! ## Decoding
//!
//! ```
//! # #[cfg(feature = "alloc")] {
//! use bech32::primitives::decode::{CheckedHrpstring, SegwitHrpstring};
//! use bech32::{hrp, segwit, Hrp, Bech32m};
//!
//! const DATA: [u8; 20] = [0xab; 20]; // Arbitrary data to be encoded.
//! const ADDR: &str = "abc14w46h2at4w46h2at4w46h2at4w46h2at958ngu";
//! const TAP_ADDR: &str = "bc1p4w46h2at4w46h2at4w46h2at4w46h2at5kreae";
//!
//! // Decode a bech32 encoded string that includes a bech32/bech32m checksum.
//! //
//! // The input address MUST include a valid bech32 or bech32m checksum, for individual specific
//! // checksum algorithms see [`decode_bech32`], [`decode_bech32m`], [`decode_no_checksum`] or use
//! // the [`primitives::decode::CheckedHrpstring`] type directly.
//! let (hrp, data) = bech32::decode(&ADDR).expect("failed to decode");
//! assert_eq!(hrp, Hrp::parse("abc").unwrap());
//! assert_eq!(data, DATA);
//!
//! // Decode a Bitcoin taproot address.
//! let (_hrp, _version, program) = segwit::decode(&TAP_ADDR).expect("valid address");
//! assert_eq!(program, DATA);
//!
//! // No-alloc: Decode a bech32m checksummed address without allocating.
//! let p = CheckedHrpstring::new::<Bech32m>(&ADDR).expect("failed to parse address");
//! assert_eq!(hrp, p.hrp());
//! assert!(p.byte_iter().eq(DATA.iter().map(|&b| b))); // We yield bytes not references.
//!
//! // No-alloc: Decode a taproot address without allocating.
//! let taproot = SegwitHrpstring::new(&TAP_ADDR).expect("valid address");
//! // Do something with the encoded data.
//! let _ = taproot.byte_iter();
//! # }
//! ```
//!
//! ## Custom Checksum
//!
//! ```
//! # #[cfg(feature = "alloc")] {
//! use bech32::Checksum;
//!
//! /// The codex32 checksum algorithm, defined in BIP-93.
//! #[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
//! pub enum Codex32 {}
//!
//! impl Checksum for Codex32 {
//!     type MidstateRepr = u128;
//!     const CHECKSUM_LENGTH: usize = 13;
//!     // Copied from BIP-93
//!     const GENERATOR_SH: [u128; 5] = [
//!         0x19dc500ce73fde210,
//!         0x1bfae00def77fe529,
//!         0x1fbd920fffe7bee52,
//!         0x1739640bdeee3fdad,
//!         0x07729a039cfc75f5a,
//!     ];
//!     const TARGET_RESIDUE: u128 = 0x10ce0795c2fd1e62a;
//! }
//!
//! # }
//! ```

#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
// Experimental features we need.
#![cfg_attr(bench, feature(test))]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
// Coding conventions
#![deny(missing_docs)]

#[cfg(bench)]
extern crate test;

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(any(test, feature = "std"))]
extern crate core;

#[cfg(all(feature = "alloc", not(feature = "std"), not(test)))]
use alloc::{string::String, vec::Vec};
use core::fmt;

use crate::error::write_err;
#[doc(inline)]
pub use crate::primitives::checksum::Checksum;
#[cfg(doc)]
use crate::primitives::decode::CheckedHrpstring;
#[cfg(feature = "alloc")]
use crate::primitives::decode::UncheckedHrpstringError;
#[cfg(feature = "alloc")]
use crate::primitives::decode::{ChecksumError, UncheckedHrpstring};
#[doc(inline)]
pub use crate::primitives::gf32::Fe32;
#[doc(inline)]
pub use crate::primitives::hrp::Hrp;
#[doc(inline)]
pub use crate::primitives::iter::{ByteIterExt, Fe32IterExt};
#[doc(inline)]
pub use crate::primitives::{Bech32, Bech32m, NoChecksum};

mod error;
/// Re-exports the hrp types from [`primitives::hrp`] to make importing ergonomic for the top level APIs.
pub mod hrp;
/// All the primitive types and functionality used in encoding and decoding.
pub mod primitives;
/// API for encoding and decoding segwit addresses.
pub mod segwit;

/// Decodes a bech32 encoded string.
///
/// If this function succeeds the input string was found to be well formed (hrp, separator, bech32
/// characters), and to have either a valid bech32m checksum or a valid bech32 checksum.
///
/// If your input string has no checksum use the [`CheckedHrpstring`] constructor, which allows selecting the checksum algorithm explicitly.
///
/// # Returns
///
/// The human-readable part and the encoded data with the checksum removed.
///
/// # Examples
/// ```
/// # #[cfg(feature = "alloc")] {
/// use bech32::{decode, Bech32, Bech32m, NoChecksum};
/// use bech32::primitives::decode::CheckedHrpstring;
///
/// const BECH32: &str = "abc14w46h2at4w46h2at4w46h2at4w46h2atsghld7";
/// const BECH32M: &str = "abc14w46h2at4w46h2at4w46h2at4w46h2at958ngu";
/// const NO_CHECKSUM: &str = "abc14w46h2at4w46h2at4w46h2at4w46h2at";
///
/// let (hrp, data) = decode(&BECH32).expect("valid address with valid bech32 checksum");
/// let (hrp, data) = decode(&BECH32M).expect("valid address with valid bech32m checksum");
/// assert!(decode(&NO_CHECKSUM).is_err());
///
/// // You can control the checksum algorithm directly by using the [`CheckedHrpstring`] type.
/// let p = CheckedHrpstring::new::<Bech32>(&BECH32).expect("valid address with valid bech32 checksum");
/// let p = CheckedHrpstring::new::<Bech32m>(&BECH32M).expect("valid address with valid bech32 checksum");
/// let p = CheckedHrpstring::new::<NoChecksum>(&NO_CHECKSUM).expect("valid address with no checksum");
/// # }
/// ```
#[cfg(feature = "alloc")]
#[inline]
pub fn decode(s: &str) -> Result<(Hrp, Vec<u8>), DecodeError> {
    let unchecked = UncheckedHrpstring::new(s)?;

    if let Err(e) = unchecked.validate_checksum::<Bech32m>() {
        if !unchecked.has_valid_checksum::<Bech32>() {
            return Err(DecodeError::Checksum(e));
        }
    };
    // One of the checksums was valid, Ck is only for length and since
    // they are both the same we can use either here.
    let checked = unchecked.remove_checksum::<Bech32m>();

    Ok((checked.hrp(), checked.byte_iter().collect()))
}

/// Encodes `data` as a lowercase bech32 encoded string.
///
/// Encoded string will be prefixed with the `hrp` and have a checksum appended as specified by the
/// `Ck` algorithm (`NoChecksum` to exclude checksum all together).
#[cfg(feature = "alloc")]
#[inline]
pub fn encode<Ck: Checksum>(hrp: Hrp, data: &[u8]) -> Result<String, fmt::Error> {
    encode_lower::<Ck>(hrp, data)
}

/// Encodes `data` as a lowercase bech32 encoded string.
///
/// Encoded string will be prefixed with the `hrp` and have a checksum appended as specified by the
/// `Ck` algorithm (`NoChecksum` to exclude checksum all together).
#[cfg(feature = "alloc")]
#[inline]
pub fn encode_lower<Ck: Checksum>(hrp: Hrp, data: &[u8]) -> Result<String, fmt::Error> {
    let mut buf = String::new();
    encode_lower_to_fmt::<Ck, String>(&mut buf, hrp, data)?;
    Ok(buf)
}

/// Encodes `data` as an uppercase bech32 encoded string.
///
/// Encoded string will be prefixed with the `hrp` and have a checksum appended as specified by the
/// `Ck` algorithm (`NoChecksum` to exclude checksum all together).
#[cfg(feature = "alloc")]
#[inline]
pub fn encode_upper<Ck: Checksum>(hrp: Hrp, data: &[u8]) -> Result<String, fmt::Error> {
    let mut buf = String::new();
    encode_upper_to_fmt::<Ck, String>(&mut buf, hrp, data)?;
    Ok(buf)
}

/// Encodes `data` to a writer ([`fmt::Write`]) as a lowercase bech32 encoded string.
///
/// Encoded string will be prefixed with the `hrp` and have a checksum appended as specified by the
/// `Ck` algorithm (`NoChecksum` to exclude checksum all together).
#[inline]
pub fn encode_to_fmt<Ck: Checksum, W: fmt::Write>(
    fmt: &mut W,
    hrp: Hrp,
    data: &[u8],
) -> Result<(), fmt::Error> {
    encode_lower_to_fmt::<Ck, W>(fmt, hrp, data)
}

/// Encodes `data` to a writer ([`fmt::Write`]) as a lowercase bech32 encoded string.
///
/// Encoded string will be prefixed with the `hrp` and have a checksum appended as specified by the
/// `Ck` algorithm (`NoChecksum` to exclude checksum all together).
#[inline]
pub fn encode_lower_to_fmt<Ck: Checksum, W: fmt::Write>(
    fmt: &mut W,
    hrp: Hrp,
    data: &[u8],
) -> Result<(), fmt::Error> {
    let iter = data.iter().copied().bytes_to_fes();
    let chars = iter.with_checksum::<Ck>(&hrp).chars();
    for c in chars {
        fmt.write_char(c)?;
    }
    Ok(())
}

/// Encodes `data` to a writer ([`fmt::Write`]) as a uppercase bech32 encoded string.
///
/// Encoded string will be prefixed with the `hrp` and have a checksum appended as specified by the
/// `Ck` algorithm (`NoChecksum` to exclude checksum all together).
#[inline]
pub fn encode_upper_to_fmt<Ck: Checksum, W: fmt::Write>(
    fmt: &mut W,
    hrp: Hrp,
    data: &[u8],
) -> Result<(), fmt::Error> {
    let iter = data.iter().copied().bytes_to_fes();
    let chars = iter.with_checksum::<Ck>(&hrp).chars();
    for c in chars {
        fmt.write_char(c.to_ascii_uppercase())?;
    }
    Ok(())
}

/// Encodes `data` to a writer ([`std::io::Write`]) as a lowercase bech32 encoded string.
///
/// Encoded string will be prefixed with the `hrp` and have a checksum appended as specified by the
/// `Ck` algorithm (`NoChecksum` to exclude checksum all together).
#[cfg(feature = "std")]
#[inline]
pub fn encode_to_writer<Ck: Checksum, W: std::io::Write>(
    w: &mut W,
    hrp: Hrp,
    data: &[u8],
) -> Result<(), std::io::Error> {
    encode_lower_to_writer::<Ck, W>(w, hrp, data)
}

/// Encodes `data` to a writer ([`std::io::Write`]) as a lowercase bech32 encoded string.
///
/// Encoded string will be prefixed with the `hrp` and have a checksum appended as specified by the
/// `Ck` algorithm (`NoChecksum` to exclude checksum all together).
#[cfg(feature = "std")]
#[inline]
pub fn encode_lower_to_writer<Ck: Checksum, W: std::io::Write>(
    w: &mut W,
    hrp: Hrp,
    data: &[u8],
) -> Result<(), std::io::Error> {
    let iter = data.iter().copied().bytes_to_fes();
    let chars = iter.with_checksum::<Ck>(&hrp).chars();
    for c in chars {
        w.write_all(&[c as u8])?;
    }
    Ok(())
}

/// Encodes `data` to a writer ([`std::io::Write`]) as a uppercase bech32 encoded string.
///
/// Encoded string will be prefixed with the `hrp` and have a checksum appended as specified by the
/// `Ck` algorithm (`NoChecksum` to exclude checksum all together).
#[cfg(feature = "std")]
#[inline]
pub fn encode_upper_to_writer<Ck: Checksum, W: std::io::Write>(
    w: &mut W,
    hrp: Hrp,
    data: &[u8],
) -> Result<(), std::io::Error> {
    let iter = data.iter().copied().bytes_to_fes();
    let chars = iter.with_checksum::<Ck>(&hrp).chars();
    for c in chars {
        w.write_all(&[c.to_ascii_uppercase() as u8])?;
    }
    Ok(())
}

/// An error while decoding an address.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DecodeError {
    /// Parsing failed.
    Parse(UncheckedHrpstringError),
    /// No valid bech32 or bech32m checksum.
    Checksum(ChecksumError),
}

#[cfg(feature = "alloc")]
impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use DecodeError::*;

        match *self {
            Parse(ref e) => write_err!(f, "parsing failed"; e),
            Checksum(ref e) => write_err!(f, "no valid bech32 or bech32m checksum"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use DecodeError::*;

        match *self {
            Parse(ref e) => Some(e),
            Checksum(ref e) => Some(e),
        }
    }
}

#[cfg(feature = "alloc")]
impl From<UncheckedHrpstringError> for DecodeError {
    #[inline]
    fn from(e: UncheckedHrpstringError) -> Self { Self::Parse(e) }
}

/// An error while decoding an address from a reader.
#[cfg(feature = "std")]
#[derive(Debug)]
#[non_exhaustive]
pub enum DecodeFromReaderError {
    /// Read error.
    Read(std::io::Error),
    /// Decode error.
    Decode(DecodeError),
}

#[cfg(feature = "std")]
impl fmt::Display for DecodeFromReaderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use DecodeFromReaderError::*;

        match *self {
            Read(ref e) => write_err!(f, "read failed"; e),
            Decode(ref e) => write_err!(f, "decoding failed"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DecodeFromReaderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use DecodeFromReaderError::*;

        match *self {
            Read(ref e) => Some(e),
            Decode(ref e) => Some(e),
        }
    }
}

#[cfg(feature = "std")]
impl From<std::io::Error> for DecodeFromReaderError {
    #[inline]
    fn from(e: std::io::Error) -> Self { Self::Read(e) }
}

#[cfg(feature = "std")]
impl From<DecodeError> for DecodeFromReaderError {
    #[inline]
    fn from(e: DecodeError) -> Self { Self::Decode(e) }
}

#[cfg(test)]
#[cfg(feature = "alloc")]
mod tests {
    use super::*;
    use crate::Bech32;

    // Tests below using this data, are based on the test vector (from BIP-173):
    // BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4: 0014751e76e8199196d454941c45d1b3a323f1433bd6
    #[rustfmt::skip]
    const DATA: [u8; 20] = [
        0xff, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4,
        0x54, 0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23,
        0xf1, 0x43, 0x3b, 0xd6,
    ];

    #[test]
    fn encode_bech32m() {
        let hrp = Hrp::parse_unchecked("test");
        let got = encode::<Bech32m>(hrp, &DATA).expect("failed to encode");
        let want = "test1lu08d6qejxtdg4y5r3zarvary0c5xw7kmz4lky";
        assert_eq!(got, want);
    }

    #[test]
    fn encode_bech32_lower() {
        let hrp = Hrp::parse_unchecked("test");
        let got = encode_lower::<Bech32>(hrp, &DATA).expect("failed to encode");
        let want = "test1lu08d6qejxtdg4y5r3zarvary0c5xw7kw79nnx";
        assert_eq!(got, want);
    }

    #[test]
    #[cfg(feature = "std")]
    fn encode_bech32_lower_to_writer() {
        let hrp = Hrp::parse_unchecked("test");
        let mut buf = Vec::new();
        encode_lower_to_writer::<Bech32, _>(&mut buf, hrp, &DATA).expect("failed to encode");

        let got = std::str::from_utf8(&buf).expect("ascii is valid utf8");
        let want = "test1lu08d6qejxtdg4y5r3zarvary0c5xw7kw79nnx";
        assert_eq!(got, want);
    }

    #[test]
    fn encode_bech32_upper() {
        let hrp = Hrp::parse_unchecked("test");
        let got = encode_upper::<Bech32>(hrp, &DATA).expect("failed to encode");
        let want = "TEST1LU08D6QEJXTDG4Y5R3ZARVARY0C5XW7KW79NNX";
        assert_eq!(got, want);
    }

    #[test]
    #[cfg(feature = "std")]
    fn encode_bech32_upper_to_writer() {
        let hrp = Hrp::parse_unchecked("test");
        let mut buf = Vec::new();
        encode_upper_to_writer::<Bech32, _>(&mut buf, hrp, &DATA).expect("failed to encode");

        let got = std::str::from_utf8(&buf).expect("ascii is valid utf8");
        let want = "TEST1LU08D6QEJXTDG4Y5R3ZARVARY0C5XW7KW79NNX";
        assert_eq!(got, want);
    }

    #[test]
    fn decode_bech32m() {
        let s = "test1lu08d6qejxtdg4y5r3zarvary0c5xw7kmz4lky";
        let (hrp, data) = decode(s).expect("failed to encode");

        assert_eq!(hrp, Hrp::parse_unchecked("test"));
        assert_eq!(data, DATA);
    }

    #[test]
    fn decode_bech32_lower() {
        let s = "test1lu08d6qejxtdg4y5r3zarvary0c5xw7kw79nnx";
        let (hrp, data) = decode(s).expect("failed to encode");

        assert_eq!(hrp, Hrp::parse_unchecked("test"));
        assert_eq!(data, DATA);
    }

    #[test]
    fn decode_bech32_upper() {
        let s = "TEST1LU08D6QEJXTDG4Y5R3ZARVARY0C5XW7KW79NNX";
        let (hrp, data) = decode(s).expect("failed to encode");

        assert_eq!(hrp, Hrp::parse_unchecked("TEST"));
        assert_eq!(data, DATA);
    }
}
