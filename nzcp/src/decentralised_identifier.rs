use std::fmt;

use serde::{
    de::{self, Visitor},
    Deserialize, Deserializer,
};

const DID_WEB: &'static str = "did:web:";

#[derive(Debug, PartialEq, Eq)]
pub enum DecentralizedIdentifier<'a> {
    Web(&'a str),
}

impl<'a> fmt::Display for DecentralizedIdentifier<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecentralizedIdentifier::Web(id) => write!(f, "{}{}", DID_WEB, id),
        }
    }
}

struct DecentralizedIdentifierVisitor;

impl<'de> Visitor<'de> for DecentralizedIdentifierVisitor {
    type Value = DecentralizedIdentifier<'de>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter
            .write_str("a Decentralized Identifier who’s DID Method MUST correspond to web (starting with 'did:web:')")
    }

    fn visit_borrowed_str<E>(self, string: &'de str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if let Some(identifier) = string.strip_prefix(DID_WEB) {
            Ok(DecentralizedIdentifier::Web(identifier))
        }
        else {
            Err(E::custom("invalid DID"))
        }
    }
}

impl<'de: 'a, 'a> Deserialize<'de> for DecentralizedIdentifier<'a> {
    fn deserialize<D>(deserializer: D) -> Result<DecentralizedIdentifier<'a>, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(DecentralizedIdentifierVisitor)
    }
}
