use nzcp::{
    error::{CoseVerificationError, NzcpError},
    verify_pass_barcode_with_trusted_issuer, DecentralizedIdentifier, PublicCovidPass,
};

const EXAMPLE_ISSUER: DecentralizedIdentifier<'static> = DecentralizedIdentifier::Web("nzcp.covid19.health.nz");

// https://nzcp.covid19.health.nz/#modified-signature
#[tokio::test]
async fn modified_signature() {
    let barcode = "NZCP:/1/2KCEVIQEIVVWK6JNGEASNICZAEP2KALYDZSGSZB2O5SWEOTOPJRXALTDN53GSZBRHEXGQZLBNR2GQLTOPICRUYMBTIFAIGTUKBAAUYTWMOSGQQDDN5XHIZLYOSBHQJTIOR2HA4Z2F4XXO53XFZ3TGLTPOJTS6MRQGE4C6Y3SMVSGK3TUNFQWY4ZPOYYXQKTIOR2HA4Z2F4XW46TDOAXGG33WNFSDCOJONBSWC3DUNAXG46RPMNXW45DFPB2HGL3WGFTXMZLSONUW63TFGEXDALRQMR2HS4DFQJ2FMZLSNFTGSYLCNRSUG4TFMRSW45DJMFWG6UDVMJWGSY2DN53GSZCQMFZXG4LDOJSWIZLOORUWC3CTOVRGUZLDOSRWSZ3JOZSW4TTBNVSWISTBMNVWUZTBNVUWY6KOMFWWKZ2TOBQXE4TPO5RWI33CNIYTSNRQFUYDILJRGYDVAYFE6VGU4MCDGK7DHLLYWHVPUS2YIAAAAAAAAAAAAAAAAC63WTY2BE4DPKIF27WKF3UDNNVSVWRDYIYVJ65IRJJJ6Z25M2DO4YZLBHWFQGVQR5ZLIWEQJOZTS3IQ7JTNCFDX";

    let error: NzcpError = verify_pass_barcode_with_trusted_issuer::<PublicCovidPass>(barcode, EXAMPLE_ISSUER)
        .await
        .unwrap_err();

    assert_eq!(
        error,
        NzcpError::InvalidSignature(CoseVerificationError::VerificationFailed)
    )
}
