use nzcp::{
    error::{NzcpError, QrBarcodeError},
    verify_pass_uri_with_trusted_issuers, DecentralizedIdentifier, PublicCovidPass,
};

const EXAMPLE_ISSUER: DecentralizedIdentifier<'static> = DecentralizedIdentifier::Web("nzcp.covid19.health.nz");

#[tokio::test]
async fn invalid_barcode() {
    let barcode = "NZCP:/1/asdfghasSDFGHFDSADFGHFDSADFGHGFSDADFGBHFSADFGHFDSFGHFDDS0123456789";

    let error: NzcpError = verify_pass_uri_with_trusted_issuers::<PublicCovidPass>(barcode, &[EXAMPLE_ISSUER])
        .await
        .unwrap_err();

    assert_eq!(error, NzcpError::QrBarcode(QrBarcodeError::InvalidBase32))
}
