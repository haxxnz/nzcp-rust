use chrono::{DateTime, NaiveDateTime, Utc};
use nzcp::{
    error::{CwtValidationError, NzcpError},
    verify_pass_barcode_with_trusted_issuer, DecentralizedIdentifier, PublicCovidPass,
};

const EXAMPLE_ISSUER: DecentralizedIdentifier<'static> = DecentralizedIdentifier::Web("nzcp.covid19.health.nz");

// https://nzcp.covid19.health.nz/#expired-pass
#[tokio::test]
async fn expired_pass() {
    let barcode = "NZCP:/1/2KCEVIQEIVVWK6JNGEASNICZAEP2KALYDZSGSZB2O5SWEOTOPJRXALTDN53GSZBRHEXGQZLBNR2GQLTOPICRUX5AM2FQIGTBPBPYWYTWMOSGQQDDN5XHIZLYOSBHQJTIOR2HA4Z2F4XXO53XFZ3TGLTPOJTS6MRQGE4C6Y3SMVSGK3TUNFQWY4ZPOYYXQKTIOR2HA4Z2F4XW46TDOAXGG33WNFSDCOJONBSWC3DUNAXG46RPMNXW45DFPB2HGL3WGFTXMZLSONUW63TFGEXDALRQMR2HS4DFQJ2FMZLSNFTGSYLCNRSUG4TFMRSW45DJMFWG6UDVMJWGSY2DN53GSZCQMFZXG4LDOJSWIZLOORUWC3CTOVRGUZLDOSRWSZ3JOZSW4TTBNVSWISTBMNVWUZTBNVUWY6KOMFWWKZ2TOBQXE4TPO5RWI33CNIYTSNRQFUYDILJRGYDVA56TNJCCUN2NVK5NGAYOZ6VIWACYIBM3QXW7SLCMD2WTJ3GSEI5JH7RXAEURGATOHAHXC2O6BEJKBSVI25ICTBR5SFYUDSVLB2F6SJ63LWJ6Z3FWNHOXF6A2QLJNUFRQNTRU";

    let error: NzcpError = verify_pass_barcode_with_trusted_issuer::<PublicCovidPass>(barcode, EXAMPLE_ISSUER)
        .await
        .unwrap_err();

    assert_eq!(
        error,
        NzcpError::InvalidCWT(CwtValidationError::Expired(DateTime::from_utc(
            NaiveDateTime::from_timestamp(1635278731, 0),
            Utc
        )))
    )
}
