use std::{
    fmt::Write,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, Context, Result};
use hmac::{Hmac, Mac};
use reqwest::{Client, StatusCode};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;
use url::Url;

use crate::model::{
    Credentials, EnrollmentResponse, HeartbeatRequest, HeartbeatResponse, TaskResult,
};

type HmacSha256 = Hmac<sha2::Sha256>;

fn signature(
    secret: &str,
    timestamp: &str,
    nonce: &str,
    method: &str,
    pathname: &str,
    body: &[u8],
) -> String {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts keys of any size");
    mac.update(timestamp.as_bytes());
    mac.update(b"\n");
    mac.update(nonce.as_bytes());
    mac.update(b"\n");
    mac.update(method.as_bytes());
    mac.update(b"\n");
    mac.update(pathname.as_bytes());
    mac.update(b"\n");
    mac.update(body);
    let mut encoded = String::with_capacity(64);
    for byte in mac.finalize().into_bytes() {
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

#[derive(Clone)]
pub struct ApiClient {
    base_url: Url,
    client: Client,
}

impl ApiClient {
    pub fn new(base_url: Url) -> Result<Self> {
        let client = Client::builder()
            .https_only(base_url.scheme() == "https")
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self { base_url, client })
    }

    pub async fn enroll(&self, enrollment_token: &str) -> Result<EnrollmentResponse> {
        self.post_json(
            "api/v1/local-network-collectors/enrollment",
            &serde_json::json!({ "enrollmentToken": enrollment_token }),
            None,
        )
        .await
    }

    pub async fn heartbeat(
        &self,
        credentials: &Credentials,
        heartbeat: &HeartbeatRequest<'_>,
    ) -> Result<HeartbeatResponse> {
        self.post_json(
            "api/v1/local-network-collectors/heartbeat",
            heartbeat,
            Some(credentials),
        )
        .await
    }

    pub async fn submit_result(
        &self,
        credentials: &Credentials,
        result: &TaskResult,
    ) -> Result<()> {
        let path = format!(
            "api/v1/local-network-collectors/tasks/{}/result",
            result.task_id
        );
        let _: Value = self.post_json(&path, result, Some(credentials)).await?;
        Ok(())
    }

    pub async fn submit_candidates(
        &self,
        credentials: &Credentials,
        candidates: &[Value],
    ) -> Result<()> {
        let _: Value = self
            .post_json(
                "api/v1/local-network-collectors/discovery/candidates",
                &serde_json::json!({ "candidates": candidates }),
                Some(credentials),
            )
            .await?;
        Ok(())
    }

    pub async fn submit_telemetry(&self, credentials: &Credentials, batch: &Value) -> Result<()> {
        let _: Value = self
            .post_json(
                "api/v1/local-network-collectors/metrics/batch",
                batch,
                Some(credentials),
            )
            .await?;
        Ok(())
    }

    async fn post_json<B: Serialize + ?Sized, R: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
        credentials: Option<&Credentials>,
    ) -> Result<R> {
        let url = self
            .base_url
            .join(path)
            .context("construct control-plane endpoint")?;
        let body_bytes = serde_json::to_vec(body).context("encode control-plane request")?;
        let mut request = self
            .client
            .post(url.clone())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body_bytes.clone());
        if let Some(credentials) = credentials {
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .context("system clock is before Unix epoch")?
                .as_millis()
                .to_string();
            let nonce = uuid::Uuid::new_v4().to_string();
            let request_signature = signature(
                &credentials.collector_secret,
                &timestamp,
                &nonce,
                "POST",
                url.path(),
                &body_bytes,
            );
            request = request
                .bearer_auth(format!(
                    "{}.{}",
                    credentials.collector_id, credentials.collector_secret
                ))
                .header("x-sadapp-timestamp", timestamp)
                .header("x-sadapp-nonce", nonce)
                .header("x-sadapp-signature", request_signature);
        }
        let response = request
            .send()
            .await
            .context("control-plane request failed")?;
        let status = response.status();
        if !status.is_success() {
            let message = response.text().await.unwrap_or_default();
            bail!(
                "control-plane returned {}: {}",
                status,
                sanitize_error(&message)
            );
        }
        response
            .json()
            .await
            .context("decode control-plane response")
    }
}

fn sanitize_error(message: &str) -> String {
    let compact = message
        .chars()
        .filter(|character| !character.is_control())
        .take(500)
        .collect::<String>();
    if compact.is_empty() {
        StatusCode::INTERNAL_SERVER_ERROR
            .canonical_reason()
            .unwrap_or("request failed")
            .to_owned()
    } else {
        compact
    }
}

#[cfg(test)]
mod tests {
    use super::signature;

    #[test]
    fn canonical_signature_matches_shared_fixture() {
        let body = br#"{"protocolVersion":1,"collectorVersion":"0.1.0"}"#;
        assert_eq!(
            signature(
                "fixture-collector-secret",
                "1790251200000",
                "123e4567-e89b-42d3-a456-426614174000",
                "POST",
                "/api/v1/local-network-collectors/heartbeat",
                body,
            ),
            "bdf3b97864dde12c260805f95a0cfbde541d45b9c5bdf2366c2ffd9ab94d3bf8",
        );
    }
}
