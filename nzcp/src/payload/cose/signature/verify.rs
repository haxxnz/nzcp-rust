use p256::ecdsa::{
    self,
    signature::{Signature, Verifier},
    VerifyingKey,
};
use serde::Serialize;
use thiserror::Error;

use super::{CoseSignStructure, CoseSignature};
use crate::{
    decentralised_identifier::DecentralizedIdentifierError,
    payload::{cose::CoseStructure, cwt::validation::CwtValidationError},
};

/// A deliberately opaque signature error
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CoseVerificationError {
    #[error("signature verification failed")]
    VerificationFailed,
    #[error("CWT validation failed: {0:?}")]
    CwtValidation(#[from] CwtValidationError),
    #[error("provided issuer is not trusted: {0}")]
    UntrustedIssuer(String),
    #[error("DID resolution failed: {0:?}")]
    DecentralizedIdentifierResolution(#[from] DecentralizedIdentifierError),
}

impl<'a, T> CoseStructure<'a, T> {
    pub fn verify_signature(&self, verifying_key: &VerifyingKey) -> Result<(), CoseVerificationError> {
        use CoseVerificationError::VerificationFailed;

        let sig_structure = self.signature.sig_structure();
        let to_be_signed = serde_cbor::to_vec(&sig_structure).map_err(|_| VerificationFailed)?;

        verifying_key
            .verify(
                &to_be_signed,
                &ecdsa::Signature::from_bytes(self.signature.bytes).map_err(|_| VerificationFailed)?,
            )
            .map_err(|_| VerificationFailed)?;

        Ok(())
    }
}

#[derive(Serialize, Debug)]
struct SignatureStructure<'a>(
    &'static str,
    #[serde(with = "serde_bytes")] &'a [u8],
    #[serde(with = "serde_bytes")] &'static [u8],
    #[serde(with = "serde_bytes")] &'a [u8],
);

impl<'a> CoseSignature<'a> {
    fn sig_structure(&self) -> SignatureStructure<'a> {
        match self.sign_structure {
            CoseSignStructure::Sign1 => {
                SignatureStructure("Signature1", self.protected_headers_raw, &[], self.cwt_payload_raw)
            }
        }
    }
}
