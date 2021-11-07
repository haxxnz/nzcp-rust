use serde::de::DeserializeOwned;

use crate::{
    error::NzcpError,
    payload::{barcode::QrBarcode, cose::CoseStructure},
};

pub mod public_covid_pass;

pub trait Pass: DeserializeOwned {
    /// The type ID of the pass, given in `vc.type[1]`. (e.g. 'PublicCovidPass')
    const CREDENTIAL_TYPE: &'static str;
}

pub fn verify_pass_barcode<P: Pass>(barcode_str: &str) -> Result<P, NzcpError> {
    // extract the decoded data from the barcode string
    let barcode: QrBarcode = barcode_str.parse()?;

    // deserialize the barcode data to COSE
    let cose: CoseStructure<'_, P> = serde_cbor::from_slice(&barcode.0)?;

    // verify the COST signature and get the inner CWT
    let cwt = cose.verified_payload()?;

    // verify the CWT and get the inner pass
    let pass = cwt.verified_credential_subject()?;

    Ok(pass)
}
