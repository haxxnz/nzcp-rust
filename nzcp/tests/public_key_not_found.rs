use nzcp::{
    error::{CoseVerificationError, DecentralizedIdentifierError, NzcpError},
    verify_pass_uri_with_trusted_issuers, DecentralizedIdentifier, PublicCovidPass,
};

const EXAMPLE_ISSUER: DecentralizedIdentifier<'static> = DecentralizedIdentifier::Web("nzcp.covid19.health.nz");

// https://nzcp.covid19.health.nz/#public-key-not-found
#[tokio::test]
async fn public_key_not_found() {
    let barcode = "NZCP:/1/2KCEVIQEIVVWK6JNGIASNICZAEP2KALYDZSGSZB2O5SWEOTOPJRXALTDN53GSZBRHEXGQZLBNR2GQLTOPICRUYMBTIFAIGTUKBAAUYTWMOSGQQDDN5XHIZLYOSBHQJTIOR2HA4Z2F4XXO53XFZ3TGLTPOJTS6MRQGE4C6Y3SMVSGK3TUNFQWY4ZPOYYXQKTIOR2HA4Z2F4XW46TDOAXGG33WNFSDCOJONBSWC3DUNAXG46RPMNXW45DFPB2HGL3WGFTXMZLSONUW63TFGEXDALRQMR2HS4DFQJ2FMZLSNFTGSYLCNRSUG4TFMRSW45DJMFWG6UDVMJWGSY2DN53GSZCQMFZXG4LDOJSWIZLOORUWC3CTOVRGUZLDOSRWSZ3JOZSW4TTBNVSWISTBMNVWUZTBNVUWY6KOMFWWKZ2TOBQXE4TPO5RWI33CNIYTSNRQFUYDILJRGYDVBMP3LEDMB4CLBS2I7IOYJZW46U2YIBCSOFZMQADVQGM3JKJBLCY7ATASDTUYWIP4RX3SH3IFBJ3QWPQ7FJE6RNT5MU3JHCCGKJISOLIMY3OWH5H5JFUEZKBF27OMB37H5AHF";

    let error: NzcpError = verify_pass_uri_with_trusted_issuers::<PublicCovidPass>(barcode, &[EXAMPLE_ISSUER])
        .await
        .unwrap_err();

    assert_eq!(
        error,
        NzcpError::InvalidSignature(CoseVerificationError::DecentralizedIdentifierResolution(
            DecentralizedIdentifierError::MissingAssertionMethod(String::from("did:web:nzcp.covid19.health.nz#key-2"))
        ))
    )
}
