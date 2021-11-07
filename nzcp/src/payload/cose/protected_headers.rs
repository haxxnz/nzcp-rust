use std::fmt;

use serde::{
    de::{self, Error, Visitor},
    Deserialize, Deserializer,
};

use super::signature::SignatureAlgorithm;

const KID_KEY: u8 = 4;
const ALG_KEY: u8 = 1;

#[derive(Debug, PartialEq, Eq)]
pub struct ProtectedHeaders<'a> {
    pub kid: &'a str,
    pub algorithm: SignatureAlgorithm,
}

struct ProtectedHeadersVisitor;

impl<'de> Visitor<'de> for ProtectedHeadersVisitor {
    type Value = ProtectedHeaders<'de>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("COSE protected headers")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: de::MapAccess<'de>,
    {
        let mut kid = None;
        let mut algorithm = None;

        while let Some(key) = map.next_key()? {
            match key {
                KID_KEY => kid = Some(map.next_value()?),
                ALG_KEY => algorithm = Some(map.next_value::<i8>()?.try_into().map_err(A::Error::custom)?),
                _ => return Err(A::Error::unknown_field(&format!("{}", key), &["4 (kid)", "1 (alg)"])),
            }
        }

        match (kid, algorithm) {
            (Some(kid), Some(algorithm)) => Ok(ProtectedHeaders { kid, algorithm }),
            (_, None) => Err(A::Error::missing_field("1 (alg)")),
            (None, _) => Err(A::Error::missing_field("4 (kid)")),
        }
    }
}

impl<'de: 'a, 'a> Deserialize<'de> for ProtectedHeaders<'a> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(ProtectedHeadersVisitor)
    }
}
