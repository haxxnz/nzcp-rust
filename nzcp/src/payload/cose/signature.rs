use thiserror::Error;

pub mod verify;

#[derive(Debug, PartialEq, Eq)]
pub struct CoseSignature<'a> {
    pub bytes: &'a [u8],
    pub sign_structure: CoseSignStructure,
}

const SIGN1_TAG: u64 = 18;

#[derive(Debug, PartialEq, Eq)]
pub enum CoseSignStructure {
    Sign1,
}

#[derive(Debug, Error)]
pub enum CoseSignStructureError {
    #[error("missing CBOR tag (infering the sign structure)")]
    MissingTag,
    #[error("invalid CBOR sign structure (only COSE_Sign1 is permitted)")]
    InvalidSignStructure,
}

impl TryFrom<Option<u64>> for CoseSignStructure {
    type Error = CoseSignStructureError;

    fn try_from(value: Option<u64>) -> Result<Self, Self::Error> {
        match value {
            Some(SIGN1_TAG) => Ok(CoseSignStructure::Sign1),
            Some(..) => Err(CoseSignStructureError::InvalidSignStructure),
            None => Err(CoseSignStructureError::MissingTag),
        }
    }
}

const ES256_ID: i8 = -7;

#[derive(Debug, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    Es256,
}

#[derive(Debug, Error)]
pub enum SignatureAlgorithmError {
    #[error("invalid CBOR signature algorithm (must be ES256)")]
    SignatureAlgorithm,
}

impl TryFrom<i8> for SignatureAlgorithm {
    type Error = SignatureAlgorithmError;

    fn try_from(value: i8) -> Result<Self, Self::Error> {
        match value {
            ES256_ID => Ok(SignatureAlgorithm::Es256),
            _ => Err(SignatureAlgorithmError::SignatureAlgorithm),
        }
    }
}
