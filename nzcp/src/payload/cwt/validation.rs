use chrono::{DateTime, Utc};
use thiserror::Error;

use super::{CwtClaims, DecentralizedIdentifier, VerifiableCredential};
use crate::{pass::Pass, payload::cose::signature::verify::CoseVerificationError};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CwtValidationError {
    #[error("token not yet valid as the 'not before date' is in the future (not before: {0:?})")]
    NotYetActive(DateTime<Utc>),
    #[error("token has expired (expired: {0:?})")]
    Expired(DateTime<Utc>),
    #[error("credential uses an unsupported version: {0}")]
    UnsupportedVersion(String),
    #[error("credential uses invalid contexts: {0:?}")]
    InvalidContext(Vec<String>),
    #[error("credential uses invalid type: [{0:?}, {0:?}]")]
    InvalidType(String, String),
}

impl<'a, P: Pass> CwtClaims<'a, P> {
    /// Get the issuer of the payload, failing if it is not trusted.
    pub fn verify_issuer(
        &self,
        trusted_issuers: &[DecentralizedIdentifier<'_>],
    ) -> Result<DecentralizedIdentifier<'_>, CoseVerificationError> {
        if !trusted_issuers.contains(&self.issuer) {
            Err(CoseVerificationError::UntrustedIssuer(self.issuer.to_string()))
        }
        else {
            Ok(self.issuer)
        }
    }
    pub fn validate(&self) -> Result<(), CwtValidationError> {
        use CwtValidationError::*;

        self.verifiable_credential.validate()?;

        // issuer would already have been verified here
        let now = Utc::now();
        if now < self.not_before {
            Err(NotYetActive(self.not_before))
        }
        else if self.expiry <= now {
            Err(Expired(self.expiry))
        }
        else {
            Ok(())
        }
    }
}

const MANDATAORY_CONTEXT_URL: &'static str = "https://www.w3.org/2018/credentials/v1";
const MANDATAORY_TYPE: &'static str = "VerifiableCredential";

impl<'a, T> VerifiableCredential<'a, T>
where
    T: Pass,
{
    pub fn validate(&self) -> Result<(), CwtValidationError> {
        use CwtValidationError::*;

        if self.version != "1.0.0" {
            Err(UnsupportedVersion(self.version.to_owned()))
        }
        else if self.context.get(0) != Some(&MANDATAORY_CONTEXT_URL) || self.context.get(1) != Some(&T::CONTEXT_URL) {
            Err(InvalidContext(
                self.context.iter().map(|str| String::from(*str)).collect(),
            ))
        }
        else if self._type != (MANDATAORY_TYPE, &T::CREDENTIAL_TYPE) {
            Err(InvalidType(self._type.0.to_owned(), self._type.1.to_owned()))
        }
        else {
            Ok(())
        }
    }
}
