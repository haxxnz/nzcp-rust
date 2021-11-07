use thiserror::Error;

use crate::payload::cose::CoseStructure;

#[derive(Debug, Error)]
pub enum CoseSignatureError {}

impl<'a, T> CoseStructure<'a, T> {
    pub fn verify_signature(&self) -> Result<(), CoseSignatureError> {
        todo!()
    }
}
