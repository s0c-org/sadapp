use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::io;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WindowsConfig {
    pub version: u8,
    pub endpoint: String,
    pub invite_token: Option<String>,
    pub key_id: Option<String>,
    pub key_secret: Option<String>,
    pub interval_seconds: u64,
}

impl WindowsConfig {
    pub fn validate(&self) -> io::Result<()> {
        let invalid = |message| io::Error::new(io::ErrorKind::InvalidInput, message);
        if self.version != 1 {
            return Err(invalid("Unsupported Windows configuration version"));
        }
        let url = Url::parse(&self.endpoint)
            .map_err(|_| invalid("Endpoint must be an absolute HTTPS URL"))?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(invalid(
                "Endpoint must use HTTPS without user credentials, query or fragment",
            ));
        }
        let present = |value: &Option<String>| {
            value.as_ref().is_some_and(|value| {
                !value.is_empty()
                    && value.len() <= 4096
                    && value.bytes().all(|byte| byte.is_ascii_graphic())
            })
        };
        let valid_auth = match (&self.invite_token, &self.key_id, &self.key_secret) {
            (Some(_), None, None) => present(&self.invite_token),
            (None, Some(_), Some(_)) => present(&self.key_id) && present(&self.key_secret),
            _ => false,
        };
        if !valid_auth {
            return Err(invalid(
                "Provide an invitation token OR a complete key pair",
            ));
        }
        if !(5..=3600).contains(&self.interval_seconds) {
            return Err(invalid("Interval must be between 5 and 3600 seconds"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> WindowsConfig {
        WindowsConfig {
            version: 1,
            endpoint: "https://sadapp.org/api/v1/agent".into(),
            invite_token: Some("synthetic-token".into()),
            key_id: None,
            key_secret: None,
            interval_seconds: 30,
        }
    }

    #[test]
    fn accepts_invite_or_complete_key_pair() {
        let mut config = config();
        config.validate().unwrap();
        config.invite_token = None;
        config.key_id = Some("synthetic-id".into());
        config.key_secret = Some("synthetic-secret".into());
        config.validate().unwrap();
    }

    #[test]
    fn rejects_insecure_or_credential_bearing_endpoints() {
        for endpoint in [
            "http://localhost/agent",
            "https://user:password@host/agent",
            "https://host/agent?invite_token=secret",
            "https://host/agent#secret",
            "not-a-url",
        ] {
            let mut config = config();
            config.endpoint = endpoint.into();
            assert!(config.validate().is_err(), "{endpoint}");
        }
    }

    #[test]
    fn rejects_ambiguous_authentication_versions_and_invalid_intervals() {
        let mut config = config();
        config.key_id = Some("id".into());
        assert!(config.validate().is_err());
        config.key_id = None;
        config.interval_seconds = 0;
        assert!(config.validate().is_err());
        config.interval_seconds = 30;
        config.version = 2;
        assert!(config.validate().is_err());
        config.version = 1;
        config.invite_token = Some("\n".into());
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_credentials_that_cannot_be_sent_as_safe_headers() {
        for secret in ["contains space", "tab\tsecret", "non-ascii-\u{00e9}", ""] {
            let mut config = config();
            config.invite_token = None;
            config.key_id = Some("synthetic-id".into());
            config.key_secret = Some(secret.into());
            assert!(config.validate().is_err());
        }
    }
}
