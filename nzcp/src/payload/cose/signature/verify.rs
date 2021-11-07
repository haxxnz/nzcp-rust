use p256::{
    ecdsa::{
        self,
        signature::{Signature, Verifier},
        VerifyingKey,
    },
    elliptic_curve::generic_array::GenericArray,
    EncodedPoint,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use super::CoseSignature;
use crate::{decentralised_identifier::PublicKey, payload::cose::CoseStructure};

/// A deliberately opaque signature error
#[derive(Debug, Error)]
pub enum CoseSignatureError {
    #[error("signature verification failed")]
    VerificationFailed,
}

impl<'a, T> CoseStructure<'a, T> {
    pub fn verify_signature(&self, public_key: &PublicKey) -> Result<(), CoseSignatureError> {
        use CoseSignatureError::VerificationFailed;
        let point = EncodedPoint::from_affine_coordinates(
            &GenericArray::from_slice(&public_key.x.0),
            &GenericArray::from_slice(&public_key.y.0),
            false,
        );
        let verify_key = VerifyingKey::from_encoded_point(&point).map_err(|_| VerificationFailed)?;

        let sig_structure = self.signature.sig_structure();
        let to_be_signed = serde_cbor::to_vec(&sig_structure).map_err(|_| VerificationFailed)?;
        let message_hash = Sha256::digest(&to_be_signed);

        verify_key
            .verify(
                &message_hash,
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
        SignatureStructure("Signature1", self.protected_headers_raw, &[], self.cwt_payload_raw)
    }
}
