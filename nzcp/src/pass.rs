use serde::de::DeserializeOwned;

use crate::{
    decentralised_identifier::DecentralizedIdentifier,
    error::NzcpError,
    payload::{barcode::QrBarcode, cose::CoseStructure},
};

pub(crate) mod public_covid_pass;

pub trait Pass: DeserializeOwned {
    /// The type ID of the pass, given in `vc.type[1]`. (e.g. 'PublicCovidPass')
    const CREDENTIAL_TYPE: &'static str;
}

const MINISTRY_OF_HEALTH_ISSUER: DecentralizedIdentifier<'static> =
    DecentralizedIdentifier::Web("nzcp.identity.health.nz");

/// Verify a pass barcode, returning the pass if verified or failing if not.
///
/// Trusts only the MoH `nzcp.identity.health.nz` issuer.
pub async fn verify_pass_uri<P: Pass>(uri: &str) -> Result<P, NzcpError> {
    verify_pass_uri_with_trusted_issuers(uri, &[MINISTRY_OF_HEALTH_ISSUER]).await
}

/// Verify a pass barcode, returning the pass if verified or failing if not.
///
/// Trusts only the provided issuer (should only be used for tests where the identifier is different).
#[doc(hidden)]
pub async fn verify_pass_uri_with_trusted_issuers<P: Pass>(
    barcode_str: &str,
    trusted_issuers: &[DecentralizedIdentifier<'_>],
) -> Result<P, NzcpError> {
    // extract the decoded data from the barcode string
    let barcode: QrBarcode = barcode_str.parse()?;

    // deserialize the barcode data to COSE
    let cose: CoseStructure<'_, P> = serde_cbor::from_slice(&barcode.0)?;

    // verify the COST signature and get the inner CWT
    let cwt = cose.verified_claims(trusted_issuers).await?;

    // validate the CWT and get the inner pass
    let pass = cwt.validated_credential_subject()?;

    Ok(pass)
}
