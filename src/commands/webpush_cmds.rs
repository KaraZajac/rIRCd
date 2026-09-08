//! WEBPUSH command (draft/webpush): manage a client's Web Push subscriptions.

use super::reply::reply_to_client;
use crate::config::Config;
use crate::persist::{self, WebpushSubscription};
use crate::protocol::Message;
use crate::user::ServerState;
use crate::webpush::{self, EndpointError};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

/// `WEBPUSH REGISTER <endpoint> <keys>` / `WEBPUSH UNREGISTER <endpoint>`.
pub async fn handle_webpush(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    senders: Arc<RwLock<HashMap<String, mpsc::Sender<Message>>>>,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let subcommand = msg
        .params
        .first()
        .map(|s| s.to_uppercase())
        .unwrap_or_default();
    let endpoint = msg.params.get(1).cloned().unwrap_or_else(|| "*".into());

    let fail = |code: &str, text: &str| {
        Message::new(
            "FAIL",
            vec![
                "WEBPUSH".into(),
                code.into(),
                if subcommand.is_empty() {
                    "*".into()
                } else {
                    subcommand.clone()
                },
                endpoint.clone(),
                text.into(),
            ],
        )
        .with_prefix(&cfg.server.name)
    };

    let (Some(runtime), Some(pool)) = (cfg.webpush_runtime.as_ref(), cfg.db.as_ref()) else {
        reply_to_client(
            &senders,
            client_id,
            fail("INVALID_PARAMS", "Web Push is not enabled on this server"),
            label,
        )
        .await;
        return Ok(());
    };

    // Subscriptions belong to an account: they have to outlive the connection that
    // registered them, and delivery is looked up by account.
    let account = {
        let state_r = state.read().await;
        match state_r.clients.get(client_id) {
            Some(c) => c.read().await.account.clone(),
            None => None,
        }
    };
    let Some(account) = account else {
        reply_to_client(
            &senders,
            client_id,
            fail(
                "ACCOUNT_REQUIRED",
                "You must be logged in to register push endpoints",
            ),
            label,
        )
        .await;
        return Ok(());
    };

    match subcommand.as_str() {
        "REGISTER" => {
            let keys = msg.params.get(2).map(|s| s.as_str()).unwrap_or("");
            if endpoint == "*" || keys.is_empty() {
                reply_to_client(
                    &senders,
                    client_id,
                    fail(
                        "INVALID_PARAMS",
                        "Usage: WEBPUSH REGISTER <endpoint> <keys>",
                    ),
                    label,
                )
                .await;
                return Ok(());
            }

            if let Err(e) =
                webpush::check_endpoint(&endpoint, runtime.allow_private_endpoints).await
            {
                let text = match e {
                    EndpointError::NotHttps => "Push endpoints must use https",
                    EndpointError::Unparseable => "Push endpoint is not a valid URL",
                    EndpointError::PrivateAddress => {
                        "Push endpoint resolves to a non-public address"
                    }
                    EndpointError::Unresolvable => "Push endpoint host does not resolve",
                };
                tracing::info!(client_id, account = %account, endpoint = %endpoint, "WEBPUSH REGISTER rejected: {}", text);
                reply_to_client(&senders, client_id, fail("INVALID_PARAMS", text), label).await;
                return Ok(());
            }

            let parsed = parse_keys(keys);
            let (Some(p256dh), Some(auth)) = (parsed.get("p256dh"), parsed.get("auth")) else {
                reply_to_client(
                    &senders,
                    client_id,
                    fail("INVALID_PARAMS", "Keys must include p256dh and auth"),
                    label,
                )
                .await;
                return Ok(());
            };

            if let Err(e) = webpush::validate_keys(p256dh, auth) {
                reply_to_client(&senders, client_id, fail("INVALID_PARAMS", &e), label).await;
                return Ok(());
            }

            let subscription = WebpushSubscription {
                endpoint: endpoint.clone(),
                p256dh: p256dh.clone(),
                auth: auth.clone(),
            };

            match persist::save_webpush_subscription(
                pool,
                &account,
                &subscription,
                runtime.max_subscriptions,
            )
            .await
            {
                Ok(true) => {
                    tracing::info!(client_id, account = %account, endpoint = %endpoint, "Web Push subscription registered");
                    reply_to_client(
                        &senders,
                        client_id,
                        Message::new("WEBPUSH", vec!["REGISTER".into(), endpoint])
                            .with_prefix(&cfg.server.name),
                        label,
                    )
                    .await;
                }
                Ok(false) => {
                    reply_to_client(
                        &senders,
                        client_id,
                        fail(
                            "MAX_REGISTRATIONS",
                            &format!(
                                "At most {} push endpoints per account",
                                runtime.max_subscriptions
                            ),
                        ),
                        label,
                    )
                    .await;
                }
                Err(e) => {
                    tracing::error!(client_id, account = %account, error = %e, "WEBPUSH REGISTER: database error");
                    reply_to_client(
                        &senders,
                        client_id,
                        fail("INTERNAL_ERROR", "Could not store the subscription"),
                        label,
                    )
                    .await;
                }
            }
        }
        "UNREGISTER" => {
            if endpoint == "*" {
                reply_to_client(
                    &senders,
                    client_id,
                    fail("INVALID_PARAMS", "Usage: WEBPUSH UNREGISTER <endpoint>"),
                    label,
                )
                .await;
                return Ok(());
            }
            // Unregistering something that isn't there is not an error.
            let removed = persist::delete_webpush_subscription(pool, &endpoint).await;
            tracing::info!(client_id, account = %account, endpoint = %endpoint, removed, "Web Push unregister");
            reply_to_client(
                &senders,
                client_id,
                Message::new("WEBPUSH", vec!["UNREGISTER".into(), endpoint])
                    .with_prefix(&cfg.server.name),
                label,
            )
            .await;
        }
        _ => {
            reply_to_client(
                &senders,
                client_id,
                fail("INVALID_PARAMS", "Unknown WEBPUSH subcommand"),
                label,
            )
            .await;
        }
    }
    Ok(())
}

/// Parse the `<keys>` parameter, which uses the message-tag format
/// (`p256dh=<key>;auth=<secret>`). Values are base64url, so no tag unescaping is
/// needed, but a stray escape must not turn into a different key.
fn parse_keys(keys: &str) -> HashMap<String, String> {
    keys.split(';')
        .filter_map(|part| {
            let (k, v) = part.split_once('=')?;
            let (k, v) = (k.trim(), v.trim());
            if k.is_empty() || v.is_empty() {
                None
            } else {
                Some((k.to_string(), v.to_string()))
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_parameter_is_message_tag_format() {
        let parsed = parse_keys("p256dh=BExample_Key;auth=c2VjcmV0");
        assert_eq!(parsed.get("p256dh").unwrap(), "BExample_Key");
        assert_eq!(parsed.get("auth").unwrap(), "c2VjcmV0");

        // Order is irrelevant and unknown keys are ignored, per the spec's
        // "at least" wording about p256dh and auth.
        let parsed = parse_keys("auth=abc;p256dh=def;future=xyz");
        assert_eq!(parsed.get("auth").unwrap(), "abc");
        assert_eq!(parsed.get("p256dh").unwrap(), "def");
        assert_eq!(parsed.get("future").unwrap(), "xyz");

        assert!(parse_keys("").is_empty());
        assert!(parse_keys("p256dh=").is_empty());
        assert!(parse_keys("garbage").is_empty());
    }
}
