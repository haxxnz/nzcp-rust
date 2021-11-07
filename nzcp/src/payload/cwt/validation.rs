use chrono::{DateTime, Utc};
use thiserror::Error;

use super::{CwtPayload, DecentralizedIdentifier};

const MINISTRY_OF_HEALTH_ISSUER: DecentralizedIdentifier = DecentralizedIdentifier::Web("nzcp.identity.health.nz");

#[derive(Debug, Error)]
pub enum CwtValidationError {
    #[error("token not yet valid as the 'not before date' is in the future (not before: {0:?})")]
    NotYetActive(DateTime<Utc>),
    #[error("token has expired (expired: {0:?})")]
    Expired(DateTime<Utc>),
    #[error("provided issuer is not trusted: {0}")]
    UntrustedIssuer(String),
}

impl<'a, T> CwtPayload<'a, T> {
    pub fn validate(&self) -> Result<(), CwtValidationError> {
        use CwtValidationError::*;

        let now = Utc::now();
        if self.not_before < now {
            Err(NotYetActive(self.not_before))
        }
        else if now <= self.expiry {
            Err(Expired(self.expiry))
        }
        else if self.issuer != MINISTRY_OF_HEALTH_ISSUER {
            Err(UntrustedIssuer(self.issuer.to_string()))
        }
        else {
            Ok(())
        }
    }
}
