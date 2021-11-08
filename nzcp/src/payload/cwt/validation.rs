use chrono::{DateTime, Utc};
use thiserror::Error;

use super::{CwtClaims, DecentralizedIdentifier};
use crate::payload::cose::signature::verify::CoseVerificationError;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CwtValidationError {
    #[error("token not yet valid as the 'not before date' is in the future (not before: {0:?})")]
    NotYetActive(DateTime<Utc>),
    #[error("token has expired (expired: {0:?})")]
    Expired(DateTime<Utc>),
}

impl<'a, T> CwtClaims<'a, T> {
    /// Get the issuer of the payload, failing if it is not trusted.
    pub fn verify_issuer(
        &self,
        trusted_issuer: DecentralizedIdentifier<'_>,
    ) -> Result<DecentralizedIdentifier<'_>, CoseVerificationError> {
        if self.issuer != trusted_issuer {
            Err(CoseVerificationError::UntrustedIssuer(self.issuer.to_string()))
        }
        else {
            Ok(self.issuer)
        }
    }

    pub fn validate(&self) -> Result<(), CwtValidationError> {
        use CwtValidationError::*;

        // TODO: verify credential version >= 1.0.0

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
