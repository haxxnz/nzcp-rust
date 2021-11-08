use thiserror::Error;

pub use crate::{
    decentralised_identifier::DecentralizedIdentifierError,
    payload::{
        barcode::QrBarcodeError, cose::signature::verify::CoseVerificationError, cwt::validation::CwtValidationError,
    },
};

/// An error that occurred while verifying a pass barcode.
#[derive(Debug, Error)]
pub enum NzcpError {
    /// The barcode string was invalid.
    #[error("Invalid QR barcode: {0:?}")]
    QrBarcode(#[from] QrBarcodeError),
    /// The payload could not be deserialized correctly.
    #[error("Invalid payload: {0:?}")]
    InvalidPayload(#[from] serde_cbor::Error),
    /// The signature of the COSE payload was invalid, or the issuer was not trusted.
    #[error("Invalid signature: {0:?}")]
    InvalidSignature(#[from] CoseVerificationError),
    /// The CWT claims were not valid.
    #[error("Invalid CWT: {0:?}")]
    InvalidCWT(#[from] CwtValidationError),
}

impl PartialEq for NzcpError {
    fn eq(&self, other: &Self) -> bool {
        use NzcpError::*;
        match (self, other) {
            (QrBarcode(l0), QrBarcode(r0)) => l0 == r0,
            (InvalidPayload(l0), InvalidPayload(r0)) => l0.to_string() == r0.to_string(),
            (InvalidSignature(l0), InvalidSignature(r0)) => l0 == r0,
            (InvalidCWT(l0), InvalidCWT(r0)) => l0 == r0,
            _ => false,
        }
    }
}

impl Eq for NzcpError {}
