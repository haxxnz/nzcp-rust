#![warn(rust_2018_idioms)]

//! An implementation of [NZ COVID Pass](https://github.com/minhealthnz/nzcovidpass-spec) verification, New Zealand's proof of COVID-19 vaccination solution, written in Rust
//!
//! ## Usage
//!
//! Usage is very straight forward, simply call `verify_pass_uri` with the scanned QR Code URI. If the given pass is valid the function will return `Ok` with the pass details, otherwise it will return `Err` with details of the verification issue.
//!
//! ```ignore
//! use nzcp::{verify_pass_uri, PublicCovidPass};
//!
//! let barcode = "NZCP:/1/2KCEVIQEIVVWK6JNGEASNICZAEP2KALYDZSGSZB2O5SWEOTOPJRXALTDN53GSZBRHEXGQZLBNR2GQLTOPICRUYMBTIFAIGTUKBAAUYTWMOSGQQDDN5XHIZLYOSBHQJTIOR2HA4Z2F4XXO53XFZ3TGLTPOJTS6MRQGE4C6Y3SMVSGK3TUNFQWY4ZPOYYXQKTIOR2HA4Z2F4XW46TDOAXGG33WNFSDCOJONBSWC3DUNAXG46RPMNXW45DFPB2HGL3WGFTXMZLSONUW63TFGEXDALRQMR2HS4DFQJ2FMZLSNFTGSYLCNRSUG4TFMRSW45DJMFWG6UDVMJWGSY2DN53GSZCQMFZXG4LDOJSWIZLOORUWC3CTOVRGUZLDOSRWSZ3JOZSW4TTBNVSWISTBMNVWUZTBNVUWY6KOMFWWKZ2TOBQXE4TPO5RWI33CNIYTSNRQFUYDILJRGYDVAYFE6VGU4MCDGK7DHLLYWHVPUS2YIDJOA6Y524TD3AZRM263WTY2BE4DPKIF27WKF3UDNNVSVWRDYIYVJ65IRJJJ6Z25M2DO4YZLBHWFQGVQR5ZLIWEQJOZTS3IQ7JTNCFDX";
//! let pass: PublicCovidPass = verify_pass_uri(barcode).await?;
//! ```

pub use self::{
    decentralised_identifier::DecentralizedIdentifier,
    pass::{public_covid_pass::PublicCovidPass, verify_pass_uri, verify_pass_uri_with_trusted_issuers},
};

mod decentralised_identifier;
pub mod error;
mod pass;
mod payload;
