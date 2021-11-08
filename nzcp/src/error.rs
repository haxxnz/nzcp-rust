use thiserror::Error;

use crate::payload::{
    barcode::QrBarcodeError, cose::signature::verify::CoseVerificationError, cwt::validation::CwtValidationError,
};

#[derive(Debug, Error)]
pub enum NzcpError {
    #[error("Invalid QR barcode: {0:?}")]
    QrBarcode(#[from] QrBarcodeError),
    #[error("Invalid payload: {0:?}")]
    InvalidPayload(#[from] serde_cbor::Error),
    #[error("Invalid signature: {0:?}")]
    InvalidSignature(#[from] CoseVerificationError),
    #[error("Invalid CWT: {0:?}")]
    InvalidCWT(#[from] CwtValidationError),
}
