use std::{fmt, marker::PhantomData};

use self::protected_headers::ProtectedHeaders;
use serde::{
    de::{self, Error, IgnoredAny, Visitor},
    Deserialize, Deserializer,
};

use super::cwt::CwtPayload;

mod protected_headers;

#[derive(Debug)]
pub struct CoseStructure<'a, T> {
    protected_headers: ProtectedHeaders<'a>,
    // unprotected headers are empty in spec
    cwt_payload: CwtPayload<'a, T>,
    signature: serde_cbor::Value,
}

struct CoseStructureVisitor<T>(PhantomData<fn() -> T>);

impl<'de, T> Visitor<'de> for CoseStructureVisitor<T>
where
    T: Deserialize<'de>,
{
    type Value = CoseStructure<'de, T>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("COSE structure")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        let bytes = |name, seq: &mut A| {
            seq.next_element()?
                .ok_or_else(|| A::Error::custom(format!("missing COSE segment: {}", name)))
        };

        let protected_headers = serde_cbor::from_slice(bytes("protected headers", &mut seq)?).unwrap();
        let _: IgnoredAny = seq
            .next_element()?
            .ok_or_else(|| A::Error::custom("missing COSE segment: unprotected headers"))?;
        let cwt_payload = serde_cbor::from_slice(bytes("CWT payload", &mut seq)?).unwrap();
        let signature = serde_cbor::from_slice(bytes("signature", &mut seq)?).unwrap();

        Ok(CoseStructure {
            protected_headers,
            cwt_payload,
            signature,
        })
    }
}

impl<'de: 'a, 'a, T> Deserialize<'de> for CoseStructure<'a, T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(CoseStructureVisitor::<T>(PhantomData))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_cose() {
        let bytes = hex::decode("d2844aa204456b65792d310126a059011fa501781e6469643a7765623a6e7a63702e636f76696431392e6865616c74682e6e7a051a61819a0a041a7450400a627663a46840636f6e7465787482782668747470733a2f2f7777772e77332e6f72672f323031382f63726564656e7469616c732f7631782a68747470733a2f2f6e7a63702e636f76696431392e6865616c74682e6e7a2f636f6e74657874732f76316776657273696f6e65312e302e306474797065827456657269666961626c6543726564656e7469616c6f5075626c6963436f766964506173737163726564656e7469616c5375626a656374a369676976656e4e616d65644a61636b6a66616d696c794e616d656753706172726f7763646f626a313936302d30342d3136075060a4f54d4e304332be33ad78b1eafa4b5840d2e07b1dd7263d833166bdbb4f1a093837a905d7eca2ee836b6b2ada23c23154fba88a529f675d6686ee632b09ec581ab08f72b458904bb3396d10fa66d11477").unwrap();

        let value: CoseStructure<'_, serde_cbor::Value> = serde_cbor::from_slice(&bytes).unwrap();

        println!("value {:?}", value);

        // CoseStructure::read(bytes);
        // assert_eq!(&hex_str,)
    }
}