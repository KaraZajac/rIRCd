//! Outgoing mail: verification codes for draft/account-registration VERIFY.
//!
//! Enabled by the `[email]` config section. Sending is done over SMTP with
//! rustls, so no system TLS libraries are required.

use crate::config::EmailConfig;
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message as Mail, Tokio1Executor};
use rand::Rng;
use std::time::Duration;

/// Alphabet for verification codes: digits and uppercase letters minus the
/// visually ambiguous ones (0/O, 1/I), so a code survives being read off a screen.
const CODE_ALPHABET: &[u8] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
const CODE_LEN: usize = 8;

/// How long to wait on the SMTP server before giving up.
const SMTP_TIMEOUT: Duration = Duration::from_secs(20);

/// Generate a verification code.
pub fn generate_code() -> String {
    let mut rng = rand::thread_rng();
    (0..CODE_LEN)
        .map(|_| CODE_ALPHABET[rng.gen_range(0..CODE_ALPHABET.len())] as char)
        .collect()
}

/// Whether `addr` is a usable email address. Rejects the `*` placeholder that
/// REGISTER accepts when verification is off.
pub fn is_valid_email(addr: &str) -> bool {
    !addr.is_empty() && addr != "*" && addr.parse::<lettre::Address>().is_ok()
}

/// Render the verification mail body.
fn verification_body(network: &str, account: &str, code: &str, expiry_secs: i64) -> String {
    let hours = (expiry_secs as f64 / 3600.0).round() as i64;
    let validity = if hours >= 1 {
        format!("{} hour{}", hours, if hours == 1 { "" } else { "s" })
    } else {
        let minutes = (expiry_secs / 60).max(1);
        format!("{} minute{}", minutes, if minutes == 1 { "" } else { "s" })
    };

    format!(
        "Someone registered the account \"{account}\" on {network} with this address.\n\
         \n\
         To finish registering, send this command from your IRC client:\n\
         \n\
         \x20   VERIFY {account} {code}\n\
         \n\
         The code is valid for {validity}. If you did not request this, ignore\n\
         this message — the account is not usable until it is verified, and it\n\
         will be removed once the code expires.\n"
    )
}

/// Send a verification code. Returns an error if the address is unusable or the
/// SMTP conversation fails.
pub async fn send_verification(
    cfg: &EmailConfig,
    network: &str,
    to: &str,
    account: &str,
    code: &str,
) -> anyhow::Result<()> {
    let mail = Mail::builder()
        .from(
            cfg.from
                .parse()
                .map_err(|e| anyhow::anyhow!("invalid [email] from address: {}", e))?,
        )
        .to(to
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid recipient address: {}", e))?)
        .subject(cfg.subject.clone())
        .header(ContentType::TEXT_PLAIN)
        .body(verification_body(
            network,
            account,
            code,
            cfg.code_expiry_secs,
        ))?;

    let mut builder = match cfg.encryption.to_lowercase().as_str() {
        "none" => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&cfg.smtp_host),
        "tls" | "implicit" | "smtps" => {
            AsyncSmtpTransport::<Tokio1Executor>::relay(&cfg.smtp_host)?
        }
        _ => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&cfg.smtp_host)?,
    }
    .port(cfg.smtp_port)
    .timeout(Some(SMTP_TIMEOUT));

    if let (Some(user), Some(password)) = (&cfg.smtp_user, &cfg.smtp_password) {
        builder = builder.credentials(Credentials::new(user.clone(), password.clone()));
    }

    builder.build().send(mail).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_contains_a_command_the_user_can_copy() {
        let body = verification_body("ExampleNet", "alice", "K7M2QJ4T", 86_400);

        assert!(body.contains("VERIFY alice K7M2QJ4T"), "body was:\n{body}");
        assert!(body.contains("ExampleNet"));
        assert!(body.contains("valid for 24 hours"));
    }

    #[test]
    fn body_states_short_validity_in_minutes() {
        let body = verification_body("ExampleNet", "alice", "K7M2QJ4T", 900);
        assert!(body.contains("valid for 15 minutes"), "body was:\n{body}");

        let body = verification_body("ExampleNet", "alice", "K7M2QJ4T", 3600);
        assert!(body.contains("valid for 1 hour."), "body was:\n{body}");
    }
}
