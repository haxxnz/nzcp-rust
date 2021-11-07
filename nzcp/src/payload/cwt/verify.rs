use thiserror::Error;

use super::CwtPayload;

#[derive(Debug, Error)]
pub enum CwtVerificationError {}

impl<'a, T> CwtPayload<'a, T> {
    pub fn verify(&self) -> Result<(), CwtVerificationError> {
        todo!()
    }
}
