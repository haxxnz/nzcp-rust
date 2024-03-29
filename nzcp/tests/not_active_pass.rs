use chrono::{DateTime, NaiveDateTime, Utc};
use nzcp::{
    error::{CwtValidationError, NzcpError},
    verify_pass_uri_with_trusted_issuers, DecentralizedIdentifier, PublicCovidPass,
};

const EXAMPLE_ISSUER: DecentralizedIdentifier<'static> = DecentralizedIdentifier::Web("nzcp.covid19.health.nz");

// https://nzcp.covid19.health.nz/#not-active-pass
#[tokio::test]
async fn not_active_pass() {
    let barcode = "NZCP:/1/2KCEVIQEIVVWK6JNGEASNICZAEP2KALYDZSGSZB2O5SWEOTOPJRXALTDN53GSZBRHEXGQZLBNR2GQLTOPICRU2XI5UFQIGTMZIQIWYTWMOSGQQDDN5XHIZLYOSBHQJTIOR2HA4Z2F4XXO53XFZ3TGLTPOJTS6MRQGE4C6Y3SMVSGK3TUNFQWY4ZPOYYXQKTIOR2HA4Z2F4XW46TDOAXGG33WNFSDCOJONBSWC3DUNAXG46RPMNXW45DFPB2HGL3WGFTXMZLSONUW63TFGEXDALRQMR2HS4DFQJ2FMZLSNFTGSYLCNRSUG4TFMRSW45DJMFWG6UDVMJWGSY2DN53GSZCQMFZXG4LDOJSWIZLOORUWC3CTOVRGUZLDOSRWSZ3JOZSW4TTBNVSWISTBMNVWUZTBNVUWY6KOMFWWKZ2TOBQXE4TPO5RWI33CNIYTSNRQFUYDILJRGYDVA27NR3GFF4CCGWF66QGMJSJIF3KYID3KTKCBUOIKIC6VZ3SEGTGM3N2JTWKGDBAPLSG76Q3MXIDJRMNLETOKAUTSBOPVQEQAX25MF77RV6QVTTSCV2ZY2VMN7FATRGO3JATR";

    let error: NzcpError = verify_pass_uri_with_trusted_issuers::<PublicCovidPass>(barcode, &[EXAMPLE_ISSUER])
        .await
        .unwrap_err();

    assert_eq!(
        error,
        NzcpError::InvalidCWT(CwtValidationError::NotYetActive(DateTime::from_utc(
            NaiveDateTime::from_timestamp(1793649931, 0),
            Utc
        )))
    )
}
