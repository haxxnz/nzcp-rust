use std::{fmt, marker::PhantomData};

use chrono::{DateTime, NaiveDateTime, Utc};
use serde::{
    de::{self, Error, Visitor},
    Deserialize, Deserializer,
};
use uuid::Uuid;

use self::validation::CwtValidationError;
use crate::decentralised_identifier::DecentralizedIdentifier;

pub mod validation;

const CWT_TOKEN_CLAIM_KEY: i128 = 7;
const ISSUER_CLAIM_KEY: i128 = 1;
const NOT_BEFORE_CLAIM_KEY: i128 = 5;
const EXPIRY_CLAIM_KEY: i128 = 4;
const VERIFIABLE_CREDENTIAL_KEY: &'static str = "vc";
const EXPECTED_KEYS: [&'static str; 5] = ["7 (cwt)", "1 (iss)", "5 (nbf)", "4 (exp)", "vc"];

#[derive(Debug, PartialEq, Eq)]
pub struct CwtPayload<'a, T> {
    cwt_token_id: Uuid,
    issuer: DecentralizedIdentifier<'a>,
    not_before: DateTime<Utc>,
    expiry: DateTime<Utc>,
    verifiable_credential: VerifiableCredential<'a, T>,
}

impl<'a, T> CwtPayload<'a, T> {
    pub fn validated_credential_subject(self) -> Result<T, CwtValidationError> {
        self.validate()?;
        Ok(self.verifiable_credential.credential_subject)
    }
}

fn utc_from_timestamp(epoch_seconds: i64) -> DateTime<Utc> {
    DateTime::from_utc(NaiveDateTime::from_timestamp(epoch_seconds, 0), Utc)
}

/// CWT payload contains integer keys, so we need to manually deserialize.
struct CwtPayloadVisitor<T>(PhantomData<fn() -> T>);

impl<'de, T> Visitor<'de> for CwtPayloadVisitor<T>
where
    T: Deserialize<'de>,
{
    type Value = CwtPayload<'de, T>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("COSE protected headers")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: de::MapAccess<'de>,
    {
        let mut cwt_token_id = None;
        let mut issuer = None;
        let mut not_before = None;
        let mut expiry = None;
        let mut verifiable_credential = None;

        while let Some(key) = map.next_key()? {
            use serde_cbor::Value::{Integer, Text};
            match key {
                Integer(CWT_TOKEN_CLAIM_KEY) => cwt_token_id = Some(map.next_value()?),
                Integer(ISSUER_CLAIM_KEY) => issuer = Some(map.next_value()?),
                Integer(NOT_BEFORE_CLAIM_KEY) => not_before = Some(utc_from_timestamp(map.next_value()?)),
                Integer(EXPIRY_CLAIM_KEY) => expiry = Some(utc_from_timestamp(map.next_value()?)),
                Text(text_key) => {
                    if text_key == VERIFIABLE_CREDENTIAL_KEY {
                        verifiable_credential = Some(map.next_value()?);
                    }
                    else {
                        return Err(A::Error::unknown_field(&text_key, &EXPECTED_KEYS));
                    }
                }
                _ => return Err(A::Error::unknown_field(&format!("{:?}", key), &EXPECTED_KEYS)),
            }
        }

        match (cwt_token_id, issuer, not_before, expiry, verifiable_credential) {
            (Some(cwt_token_id), Some(issuer), Some(not_before), Some(expiry), Some(verifiable_credential)) => {
                Ok(CwtPayload {
                    cwt_token_id,
                    issuer,
                    not_before,
                    expiry,
                    verifiable_credential,
                })
            }
            (None, ..) => Err(A::Error::missing_field("7 (cwt)")),
            (_, None, ..) => Err(A::Error::missing_field("1 (iss)")),
            (_, _, None, ..) => Err(A::Error::missing_field("5 (nbf)")),
            (_, _, _, None, ..) => Err(A::Error::missing_field("4 (exp)")),
            (.., None) => Err(A::Error::missing_field("vc")),
        }
    }
}

impl<'de: 'a, 'a, T> Deserialize<'de> for CwtPayload<'a, T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(CwtPayloadVisitor::<T>(PhantomData))
    }
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct VerifiableCredential<'a, T> {
    /// JSON-LD Context property for conformance to the W3C VC standard. This property MUST be present and its value MUST be an array of strings where the first value MUST equal https://www.w3.org/2018/credentials/v1.
    ///
    /// The following is an example including an additional JSON-LD context entry that defines the additional vocabulary specific to the New Zealand COVID Pass.
    /// ```
    /// ["https://www.w3.org/2018/credentials/v1", "https://nzcp.covid19.health.nz/contexts/v1"]
    /// ```
    #[serde(rename = "@context")]
    context: Vec<&'a str>,

    /// Type property for conformance to the W3C VC standard. This property MUST be present and its value MUST be an array of two string values, whose first element is VerifiableCredential and second element corresponds to one defined in the pass types section.
    ///
    /// Example
    /// ```
    /// ["VerifiableCredential", "PublicCovidPass"]
    /// ```
    #[serde(rename = "type")]
    _type: (&'a str, &'a str),

    /// Version property of the New Zealand Covid Pass. This property MUST be present and its value MUST be a string who’s value corresponds to a valid version identifier as defined by semver. For the purposes of this version of the specification this value MUST be 1.0.0.
    version: &'a str,

    /// Credential Subject property MUST be present and its value MUST be a JSON object with properties determined by the declared pass type for the pass.
    #[serde(rename = "credentialSubject")]
    credential_subject: T,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_cbor() {
        let bytes = hex::decode("a501781e6469643a7765623a6e7a63702e636f76696431392e6865616c74682e6e7a051a61819a0a041a7450400a627663a46840636f6e7465787482782668747470733a2f2f7777772e77332e6f72672f323031382f63726564656e7469616c732f7631782a68747470733a2f2f6e7a63702e636f76696431392e6865616c74682e6e7a2f636f6e74657874732f76316776657273696f6e65312e302e306474797065827456657269666961626c6543726564656e7469616c6f5075626c6963436f766964506173737163726564656e7469616c5375626a6563746A68656C6C6F776F726C64075060A4F54D4E304332BE33AD78B1EAFA4B").unwrap();

        let value: serde_cbor::Value = serde_cbor::from_slice(&bytes).unwrap();
        dbg!(value);
        let payload: CwtPayload<'_, &'_ str> = serde_cbor::from_slice(&bytes).unwrap();

        assert_eq!(
            payload,
            CwtPayload {
                cwt_token_id: Uuid::parse_str("urn:uuid:60a4f54d-4e30-4332-be33-ad78b1eafa4b").unwrap(),
                issuer: DecentralizedIdentifier::Web("nzcp.covid19.health.nz"),
                not_before: utc_from_timestamp(1635883530),
                expiry: utc_from_timestamp(1951416330),
                verifiable_credential: VerifiableCredential {
                    context: vec![
                        "https://www.w3.org/2018/credentials/v1",
                        "https://nzcp.covid19.health.nz/contexts/v1"
                    ],
                    _type: ("VerifiableCredential", "PublicCovidPass"),
                    version: "1.0.0",
                    credential_subject: "helloworld",
                }
            }
        )
    }
}
