use nzcp::{
    error::{NzcpError, QrBarcodeError},
    verify_pass_barcode_with_trusted_issuer, DecentralizedIdentifier, PublicCovidPass,
};

const EXAMPLE_ISSUER: DecentralizedIdentifier<'static> = DecentralizedIdentifier::Web("nzcp.covid19.health.nz");

#[tokio::test]
async fn invalid_barcode() {
    let barcode = "NZCP:/1/asdfghasSDFGHFDSADFGHFDSADFGHGFSDADFGBHFSADFGHFDSFGHFDDS0123456789";

    let error: NzcpError = verify_pass_barcode_with_trusted_issuer::<PublicCovidPass>(barcode, EXAMPLE_ISSUER)
        .await
        .unwrap_err();

    assert_eq!(error, NzcpError::QrBarcode(QrBarcodeError::InvalidBase32))
}
