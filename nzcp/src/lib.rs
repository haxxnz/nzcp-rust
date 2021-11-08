#![warn(rust_2018_idioms)]

pub use self::{
    decentralised_identifier::DecentralizedIdentifier,
    pass::{public_covid_pass::PublicCovidPass, verify_pass_barcode, verify_pass_barcode_with_trusted_issuer},
};

mod decentralised_identifier;
pub mod error;
mod pass;
mod payload;
