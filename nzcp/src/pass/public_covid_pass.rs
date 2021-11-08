use chrono::NaiveDate;
use serde::{de::Error, Deserialize, Deserializer};
use thiserror::Error;

use super::Pass;

#[derive(Debug, Error)]
pub enum PublicCovidPassError {
    #[error("The given date of birth was invalid.")]
    InvalidDateOfBirth,
}

/// See: https://nzcp.covid19.health.nz/#publiccovidpass
#[derive(Debug, Deserialize, PartialEq, Eq)]
pub struct PublicCovidPass {
    /// Given name(s) of the subject of the pass.
    #[serde(rename = "givenName")]
    pub given_name: String,

    /// Family name(s) of the subject of the pass.
    #[serde(rename = "familyName")]
    pub family_name: Option<String>,

    /// Date of birth of the subject of the pass.
    #[serde(rename = "dob", deserialize_with = "deserialize_iso_8601_date")]
    pub date_of_birth: NaiveDate,
}

impl Pass for PublicCovidPass {
    const CREDENTIAL_TYPE: &'static str = "PublicCovidPass";
}

fn deserialize_iso_8601_date<'de, D>(deserializer: D) -> Result<NaiveDate, D::Error>
where
    D: Deserializer<'de>,
{
    let string: &str = Deserialize::deserialize(deserializer)?;
    NaiveDate::parse_from_str(string, "%Y-%m-%d")
        .map_err(|_| D::Error::custom(PublicCovidPassError::InvalidDateOfBirth))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_json() {
        let json = r#"{
            "givenName": "John Andrew",
            "familyName": "Doe",
            "dob": "1979-04-14"
        }"#;

        let pass: PublicCovidPass = serde_json::from_str(json).unwrap();
        assert_eq!(
            pass,
            PublicCovidPass {
                given_name: String::from("John Andrew"),
                family_name: Some(String::from("Doe")),
                date_of_birth: NaiveDate::from_ymd(1979, 04, 14),
            }
        )
    }
}
