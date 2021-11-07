use std::{fmt, str::FromStr};

use did_web::DIDWeb;
use serde::{
    de::{self, Visitor},
    Deserialize, Deserializer,
};
use ssi::{
    did::{Document, VerificationMethod, DIDURL},
    did_resolve::{DIDResolver, ResolutionInputMetadata},
    jwk::{self, Base64urlUInt},
};
use thiserror::Error;
const DID_WEB: &'static str = "did:web:";

#[derive(Debug, PartialEq, Eq)]
pub enum DecentralizedIdentifier<'a> {
    Web(&'a str),
}

impl<'a> fmt::Display for DecentralizedIdentifier<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.did())
    }
}

struct DecentralizedIdentifierVisitor;

impl<'de> Visitor<'de> for DecentralizedIdentifierVisitor {
    type Value = DecentralizedIdentifier<'de>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter
            .write_str("a Decentralized Identifier who’s DID Method MUST correspond to web (starting with 'did:web:')")
    }

    fn visit_borrowed_str<E>(self, did: &'de str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if did.starts_with(DID_WEB) {
            Ok(DecentralizedIdentifier::Web(did))
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

#[derive(Debug, Error)]
pub enum DecentralizedIdentifierError {
    #[error("DID resolution error: {0}")]
    ResolutionError(String),
    #[error("an empty DID resolution document was returned")]
    EmptyDocument,
    #[error("assertionMethod array was missing from the DID document")]
    MissingAssertionMethods,
    #[error("assertionMethod with absolute key '' was missing from the DID document")]
    MissingAssertionMethod(String),
    #[error("verificationMethod was missing from the DID document")]
    MissingVerificationMethods,
    #[error("verificationMethod with the absolute key '' was missing from the DID document")]
    MissingVerificationMethod(String),
    #[error("verificationMethod type was not 'JsonWebKey2020'")]
    NotJsonWebKey2020,
    #[error("verificationMethod was missing publicKeyJwk")]
    MissingJWK,
    #[error("publicKeyJwk was not elliptic curve")]
    JWKNotEllipticCurve,
    #[error("publicKeyJwk was missing x coordinate")]
    JWKMissingX,
    #[error("publicKeyJwk was missing y coordinate")]
    JWKMissingY,
    #[error("publicKeyJwk 'crv' was not 'P-256'")]
    JWKWrongCurve,
}

impl<'a> DecentralizedIdentifier<'a> {
    fn did(&self) -> &'a str {
        match self {
            DecentralizedIdentifier::Web(did) => did,
        }
    }

    async fn resolve_document(&self) -> Result<Document, DecentralizedIdentifierError> {
        let (metadata, document, _) = DIDWeb.resolve(self.did(), &ResolutionInputMetadata::default()).await;

        if let Some(error) = metadata.error {
            Err(DecentralizedIdentifierError::ResolutionError(error))
        }
        else if let Some(document) = document {
            Ok(document)
        }
        else {
            Err(DecentralizedIdentifierError::EmptyDocument)
        }
    }

    async fn resolve_public_key(&self, kid: &str) -> Result<PublicKey, DecentralizedIdentifierError> {
        let document = self.resolve_document().await?;

        let absolute_key = format!("{}#{}", self.did(), kid);
        let absolute_key_url = DIDURL::from_str(&absolute_key).expect("invalid iss/kid DID");


        use DecentralizedIdentifierError::*;
        let assertion_methods = document.assertion_method.ok_or(MissingAssertionMethods)?;
        if !assertion_methods.contains(&VerificationMethod::DIDURL(absolute_key_url)) {
            return Err(MissingAssertionMethod(absolute_key));
        }

        let verification_method = document
            .verification_method
            .ok_or(MissingVerificationMethods)?
            .into_iter()
            .find_map(|method| match method {
                VerificationMethod::Map(map) => (&map.id == &absolute_key).then(|| map),
                _ => None,
            })
            .ok_or(MissingVerificationMethod(absolute_key))?;

        if verification_method.type_ != "JsonWebKey2020" {
            Err(NotJsonWebKey2020)
        }
        else if let Some(jwk) = verification_method.public_key_jwk {
            let ec = match jwk.params {
                jwk::Params::EC(ec) => ec,
                _ => return Err(JWKNotEllipticCurve),
            };

            if ec.curve.as_deref() != Some("P-256") {
                return Err(JWKWrongCurve);
            }

            let x = ec.x_coordinate.ok_or(JWKMissingX)?;
            let y = ec.y_coordinate.ok_or(JWKMissingY)?;

            Ok(PublicKey { x, y })
        }
        else {
            Err(MissingJWK)
        }
    }
}

pub struct PublicKey {
    pub x: Base64urlUInt,
    pub y: Base64urlUInt,
}
