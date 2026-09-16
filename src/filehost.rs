use axum::{
    body::Body,
    extract::{DefaultBodyLimit, Path, State},
    http::{
        header::{self, HeaderMap, HeaderValue},
        Method, Request, StatusCode,
    },
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, head, post},
    Router,
};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs;
use tower_http::cors::{Any, CorsLayer};
use tracing::{error, info, warn};

/// The address a request came from, put there by whichever accept loop took
/// it. The plain listener carries it as `ConnectInfo`; the TLS one runs its
/// own accept loop, so it puts it here instead.
#[derive(Clone, Debug)]
pub struct PeerAddr(pub String);

/// The account a request proved it holds, put there by the auth middleware
/// so the upload handler knows whose file it is.
#[derive(Clone, Debug)]
pub struct Uploader(pub String);

/// Shared state for the filehost HTTP handlers.
#[derive(Clone)]
pub struct FilehostState {
    pub upload_dir: PathBuf,
    pub public_url: String,
    pub max_size: usize,
    pub max_uploads_per_hour: usize,
    pub db_pool: sqlx::MySqlPool,
    /// The same state the IRC side uses, for the same reason: these are the
    /// same passwords, so guessing at them here has to cost what guessing at
    /// them there costs.
    pub state: Arc<tokio::sync::RwLock<crate::user::ServerState>>,
    /// Addresses the operator says are their own proxies. Only a request
    /// arriving from one of these may say whose it really is.
    pub trusted_proxies: Arc<Vec<String>>,
}

/// Where a request came from, however its listener recorded it.
///
/// Behind a reverse proxy the socket says the proxy, which is one address for
/// everybody who came through it — so one failed-login budget for everybody,
/// and whoever is guessing spends the allowance of every real user sharing
/// that door. `X-Forwarded-For` is how the proxy says whose request it is
/// passing on, and it is believed only when the connection carrying it came
/// from an address the operator named as a proxy. Anybody may send the header;
/// only a proxy is taken at its word.
fn peer_of(req: &Request<Body>, trusted: &[String]) -> String {
    let actual = socket_peer_of(req);
    crate::server::forwarded_for_ip(req.headers(), &actual, trusted)
}

/// The address the connection itself came from, before any header is read.
fn socket_peer_of(req: &Request<Body>) -> String {
    if let Some(PeerAddr(ip)) = req.extensions().get::<PeerAddr>() {
        return ip.clone();
    }
    if let Some(info) = req
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
    {
        return info.0.ip().to_string();
    }
    // Nothing recorded it, so everything shares one allowance rather than
    // none: an unknown address must not be the way around the budget.
    "unknown".to_string()
}

/// Build the axum router for the filehost.
/// Routes are nested under the path component of `public_url` so that requests
/// arriving at e.g. `/uploads` or `/uploads/<file>` match correctly regardless
/// of reverse-proxy configuration.
pub fn router(fh_state: Arc<FilehostState>) -> Router {
    let max_size = fh_state.max_size;

    // Extract the path prefix from public_url (e.g. "https://example.com/uploads" → "/uploads")
    let prefix = extract_url_path(&fh_state.public_url);
    info!(prefix = %prefix, "Filehost routes mounted");

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::HEAD, Method::POST, Method::OPTIONS])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            header::CONTENT_LENGTH,
            header::CONTENT_DISPOSITION,
        ])
        .expose_headers([header::LOCATION, header::CONTENT_LENGTH]);

    let filehost_routes = Router::new()
        .route("/", post(upload_file))
        .route("/{filename}", get(download_file))
        .route("/{filename}", head(head_file));

    Router::new()
        .nest(&prefix, filehost_routes)
        .layer(DefaultBodyLimit::max(max_size))
        .layer(middleware::from_fn_with_state(
            fh_state.clone(),
            auth_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            fh_state.clone(),
            request_logging,
        ))
        .layer(cors)
        .with_state(fh_state)
}

/// Let go of uploads older than `cutoff`, and say how many went.
///
/// Kept by age rather than by whether anybody still wants them: nothing here
/// knows who has a link. An operator who sets `uploads_days` is saying how
/// long a link is good for, which is a thing people can be told in advance —
/// unlike "until the disk fills", which is what no setting at all means.
///
/// Only regular files directly in the directory are touched: not a symbolic
/// link, not a directory, and not a dotfile, so nothing here reaches outside
/// the place the operator named.
pub async fn sweep_uploads(dir: &std::path::Path, cutoff: i64) -> usize {
    let mut entries = match fs::read_dir(dir).await {
        Ok(e) => e,
        Err(e) => {
            warn!(dir = %dir.display(), "Cannot look over the uploads: {e}");
            return 0;
        }
    };
    let mut gone = 0usize;
    loop {
        let entry = match entries.next_entry().await {
            Ok(Some(e)) => e,
            Ok(None) => break,
            Err(e) => {
                warn!(dir = %dir.display(), "Stopped looking over the uploads: {e}");
                break;
            }
        };
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with('.') {
            continue;
        }
        // `file_type` does not follow a symbolic link, so a link is simply
        // not a regular file and is left alone.
        match entry.file_type().await {
            Ok(kind) if kind.is_file() => {}
            _ => continue,
        }
        let Ok(meta) = entry.metadata().await else {
            continue;
        };
        let Ok(modified) = meta.modified() else {
            continue;
        };
        // A clock that says a file predates the epoch is a clock to disbelieve,
        // so such a file is treated as new and left alone.
        let modified_at = modified
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(i64::MAX);
        if modified_at >= cutoff {
            continue;
        }
        match fs::remove_file(entry.path()).await {
            Ok(()) => {
                info!(file = %name, "Upload expired");
                gone += 1;
            }
            Err(e) => warn!(file = %name, "Could not let go of an expired upload: {e}"),
        }
    }
    gone
}

/// Log every incoming request, with whose it is.
///
/// The address is the one the proxy vouched for where there is a proxy, which
/// is the one an operator reading these lines is looking for: behind one, the
/// socket address is the same for everybody and says nothing.
async fn request_logging(
    State(fh_state): State<Arc<FilehostState>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let peer = peer_of(&req, &fh_state.trusted_proxies);
    info!(method = %method, uri = %uri, %peer, "Filehost request");
    let resp = next.run(req).await;
    let status = resp.status();
    if status.is_client_error() || status.is_server_error() {
        warn!(method = %method, uri = %uri, %peer, status = %status, "Filehost response error");
    }
    resp
}

/// HTTP Basic auth middleware — verifies credentials against the IRC user database.
async fn auth_middleware(
    State(fh_state): State<Arc<FilehostState>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    // GET/HEAD/OPTIONS don't require auth
    match *req.method() {
        Method::GET | Method::HEAD | Method::OPTIONS => return next.run(req).await,
        _ => {}
    }

    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let peer = peer_of(&req, &fh_state.trusted_proxies);

    let Some(auth_str) = auth_header else {
        warn!("Filehost upload rejected: no Authorization header");
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Basic realm=\"rIRCd filehost\"")],
            "Authentication required",
        )
            .into_response();
    };

    let Some(credentials) = auth_str.strip_prefix("Basic ") else {
        warn!("Filehost upload rejected: non-Basic auth scheme");
        return (StatusCode::BAD_REQUEST, "Invalid Authorization header").into_response();
    };

    let decoded =
        match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, credentials) {
            Ok(d) => d,
            Err(_) => {
                warn!("Filehost upload rejected: invalid base64 in credentials");
                return (StatusCode::BAD_REQUEST, "Invalid base64").into_response();
            }
        };

    let decoded_str = match String::from_utf8(decoded) {
        Ok(s) => s,
        Err(_) => {
            warn!("Filehost upload rejected: non-UTF-8 credentials");
            return (StatusCode::BAD_REQUEST, "Invalid UTF-8").into_response();
        }
    };

    let Some((user, pass)) = decoded_str.split_once(':') else {
        warn!("Filehost upload rejected: no colon in credentials");
        return (StatusCode::BAD_REQUEST, "Invalid credentials format").into_response();
    };

    // These are the same passwords the IRC side takes such care over, and
    // checking one costs the same bcrypt. Whoever keeps getting it wrong is
    // told to wait rather than having another check run for them — otherwise
    // every bit of that care is one HTTP request away from being beside the
    // point. Charged here, where what is about to happen is a credential
    // check: a request with no credentials in it costs nobody an allowance.
    //
    // Both the address and the account, because behind a proxy or a hidden
    // service the address is everybody's and the account is what is being
    // guessed at.
    let wait = {
        let mut state = fh_state.state.write().await;
        state.auth_cost.spend_for(&peer, user)
    };
    if !wait.is_zero() {
        warn!(peer = %peer, account = %user, "Filehost upload rejected: too many failed credentials");
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(
                header::RETRY_AFTER,
                HeaderValue::from_str(&wait.as_secs().max(1).to_string())
                    .unwrap_or(HeaderValue::from_static("5")),
            )],
            "Too many credential checks just now; try again in a moment",
        )
            .into_response();
    }

    if !crate::persist::verify_user(&fh_state.db_pool, user, pass).await {
        warn!(user = %user, peer = %peer, "Filehost upload rejected: bad credentials");
        return (StatusCode::FORBIDDEN, "Invalid username or password").into_response();
    }
    // Right first time is not guessing, so it is given back.
    fh_state
        .state
        .write()
        .await
        .auth_cost
        .refund_for(&peer, user);

    info!(user = %user, "Filehost auth OK");
    let mut req = req;
    req.extensions_mut().insert(Uploader(user.to_string()));
    next.run(req).await
}

/// POST / — upload a file, return the download URL in Location header.
async fn upload_file(
    State(fh_state): State<Arc<FilehostState>>,
    axum::Extension(Uploader(account)): axum::Extension<Uploader>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    info!(size = body.len(), account = %account, "Filehost upload body received");

    if body.len() > fh_state.max_size {
        warn!(
            size = body.len(),
            max = fh_state.max_size,
            "Filehost upload rejected: too large"
        );
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("File exceeds maximum size of {} bytes", fh_state.max_size),
        )
            .into_response();
    }

    if body.is_empty() {
        warn!("Filehost upload rejected: empty body");
        return (StatusCode::BAD_REQUEST, "Empty upload").into_response();
    }

    // Determine filename: use Content-Disposition filename if provided, else generate one.
    let original_name = headers
        .get(header::CONTENT_DISPOSITION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.split(';').find_map(|part| {
                let part = part.trim();
                if part.starts_with("filename=") {
                    Some(
                        part.trim_start_matches("filename=")
                            .trim_matches('"')
                            .to_string(),
                    )
                } else {
                    None
                }
            })
        });

    // Also try Content-Type to derive extension if no filename given.
    let ext = match original_name {
        Some(ref name) => sanitize_extension(name),
        None => headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .and_then(|ct| {
                let mime: mime_guess::mime::Mime = ct.parse().ok()?;
                mime_guess::get_mime_extensions(&mime)
                    .and_then(|exts| exts.first())
                    .map(|e| sanitize_extension(&format!("x.{}", e)))
            })
            .unwrap_or_default(),
    };

    // Disk is the one thing here nothing reclaims, so an account that keeps
    // uploading is asked to stop for a while. Counted per account rather than
    // per address: the account is what was proved.
    if fh_state.max_uploads_per_hour > 0 {
        let allowed = fh_state.state.write().await.upload_rate.allow(
            &account.to_lowercase(),
            fh_state.max_uploads_per_hour,
            std::time::Duration::from_secs(3600),
        );
        if !allowed {
            warn!(account = %account, "Filehost upload rejected: too many lately");
            return (
                StatusCode::TOO_MANY_REQUESTS,
                [(header::RETRY_AFTER, HeaderValue::from_static("3600"))],
                format!(
                    "That account has uploaded {} files in the last hour, which is all it may",
                    fh_state.max_uploads_per_hour
                ),
            )
                .into_response();
        }
    }

    let unique_id = uuid::Uuid::new_v4();
    let stored_name = format!("{}{}", unique_id, ext);
    let file_path = fh_state.upload_dir.join(&stored_name);

    if let Err(e) = fs::write(&file_path, &body).await {
        error!("Failed to write upload to {}: {}", file_path.display(), e);
        return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to store file").into_response();
    }

    let url = format!(
        "{}/{}",
        fh_state.public_url.trim_end_matches('/'),
        stored_name
    );
    info!(
        file = %stored_name,
        size = body.len(),
        account = %account,
        "File uploaded successfully"
    );

    let mut resp = (StatusCode::CREATED, url.clone()).into_response();
    match HeaderValue::from_str(&url) {
        Ok(v) => {
            resp.headers_mut().insert(header::LOCATION, v);
        }
        // public_url comes from the config file; a stray non-ASCII character in
        // it is the operator's problem, not a reason to drop the upload.
        Err(_) => warn!(url = %url, "Upload URL is not a valid header value; Location omitted"),
    }
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/uri-list"),
    );
    resp
}

/// GET /:filename — serve the file.
async fn download_file(
    State(fh_state): State<Arc<FilehostState>>,
    Path(filename): Path<String>,
) -> Response {
    let safe_name = sanitize_filename(&filename);
    let file_path = fh_state.upload_dir.join(&safe_name);

    let data = match fs::read(&file_path).await {
        Ok(d) => d,
        Err(_) => return (StatusCode::NOT_FOUND, "File not found").into_response(),
    };

    let mut headers = serving_headers(&safe_name);
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(data.len()));

    (StatusCode::OK, headers, data).into_response()
}

/// HEAD /:filename — return headers without body.
async fn head_file(
    State(fh_state): State<Arc<FilehostState>>,
    Path(filename): Path<String>,
) -> Response {
    let safe_name = sanitize_filename(&filename);
    let file_path = fh_state.upload_dir.join(&safe_name);

    let meta = match fs::metadata(&file_path).await {
        Ok(m) => m,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };

    let mut headers = serving_headers(&safe_name);
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(meta.len()));

    (StatusCode::OK, headers).into_response()
}

/// Types we are willing to hand back for the browser to render in place.
/// Everything else is served as a download: a file this server stores on
/// behalf of a user must never be able to become script on this origin.
/// SVG and HTML are absent deliberately — both can carry script.
const INLINE_TYPES: &[(&str, &str)] = &[
    ("png", "image/png"),
    ("jpg", "image/jpeg"),
    ("jpeg", "image/jpeg"),
    ("gif", "image/gif"),
    ("webp", "image/webp"),
    ("avif", "image/avif"),
    ("bmp", "image/bmp"),
    ("ico", "image/x-icon"),
    ("mp3", "audio/mpeg"),
    ("ogg", "audio/ogg"),
    ("oga", "audio/ogg"),
    ("opus", "audio/ogg"),
    ("wav", "audio/wav"),
    ("flac", "audio/flac"),
    ("m4a", "audio/mp4"),
    ("mp4", "video/mp4"),
    ("m4v", "video/mp4"),
    ("webm", "video/webm"),
    ("mov", "video/quicktime"),
    ("txt", "text/plain; charset=utf-8"),
    ("log", "text/plain; charset=utf-8"),
];

/// The extension an upload is stored under. The client names the file, so the
/// name is a hint and nothing more: ASCII letters and digits, lowercased and
/// short. Anything else is stored without an extension rather than trusted —
/// it is what decides the content type on the way back out.
fn sanitize_extension(name: &str) -> String {
    let Some((_, ext)) = name.rsplit_once('.') else {
        return String::new();
    };
    if ext.is_empty() || ext.len() > 16 || !ext.chars().all(|c| c.is_ascii_alphanumeric()) {
        return String::new();
    }
    format!(".{}", ext.to_ascii_lowercase())
}

/// The content type a stored file is served with, and whether the browser may
/// render it in place.
fn serving_type(stored_name: &str) -> (&'static str, bool) {
    let ext = stored_name
        .rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase())
        .unwrap_or_default();
    match INLINE_TYPES.iter().find(|(e, _)| *e == ext) {
        Some((_, ct)) => (ct, true),
        None => ("application/octet-stream", false),
    }
}

/// Response headers for serving a stored file, on both GET and HEAD.
fn serving_headers(stored_name: &str) -> HeaderMap {
    let (content_type, inline) = serving_type(stored_name);
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    // The type above is the whole answer; the browser must not go looking for
    // a more interesting one in the bytes.
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; sandbox"),
    );
    if !inline {
        headers.insert(
            header::CONTENT_DISPOSITION,
            HeaderValue::from_static("attachment"),
        );
    }
    headers
}

/// Strip path traversal from filename.
fn sanitize_filename(name: &str) -> String {
    let name = name.replace(['/', '\\'], "");
    if name.is_empty() || name == "." || name == ".." {
        "invalid".to_string()
    } else {
        name
    }
}

/// Extract the path component from a URL string.
/// e.g. "https://example.com/uploads" → "/uploads"
/// e.g. "https://example.com" → "/"
pub fn extract_url_path(url: &str) -> String {
    // Find the start of the path after "://host"
    if let Some(after_scheme) = url.find("://") {
        let rest = &url[after_scheme + 3..];
        if let Some(slash_pos) = rest.find('/') {
            let path = &rest[slash_pos..];
            let path = path.trim_end_matches('/');
            if path.is_empty() {
                "/".to_string()
            } else {
                path.to_string()
            }
        } else {
            "/".to_string()
        }
    } else {
        "/".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extension_comes_from_the_name_but_is_not_trusted() {
        assert_eq!(sanitize_extension("holiday.PNG"), ".png");
        assert_eq!(sanitize_extension("notes.txt"), ".txt");
        // No dot, nothing to take.
        assert_eq!(sanitize_extension("passwd"), "");
        // A path in the extension would put the file somewhere of the
        // uploader's choosing.
        assert_eq!(sanitize_extension("a./../../etc/cron.d/evil"), "");
        assert_eq!(sanitize_extension("x.png/../../y"), "");
        // Trailing dot, and an extension long enough to be a payload.
        assert_eq!(sanitize_extension("x."), "");
        assert_eq!(sanitize_extension(&format!("x.{}", "a".repeat(17))), "");
        assert_eq!(
            sanitize_extension(&format!("x.{}", "a".repeat(16))),
            format!(".{}", "a".repeat(16))
        );
    }

    #[test]
    fn uploads_are_never_served_as_script_on_this_origin() {
        for name in ["evil.html", "evil.htm", "evil.svg", "evil.xhtml", "evil.js"] {
            let (ct, inline) = serving_type(name);
            assert_eq!(ct, "application/octet-stream", "{name}");
            assert!(!inline, "{name} must not render in place");
        }
        let headers = serving_headers("evil.html");
        assert_eq!(headers[header::CONTENT_DISPOSITION], "attachment");
        assert_eq!(headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
    }

    #[test]
    fn images_still_display_in_place() {
        let (ct, inline) = serving_type("cat.jpg");
        assert_eq!(ct, "image/jpeg");
        assert!(inline);
        let headers = serving_headers("cat.jpg");
        assert!(!headers.contains_key(header::CONTENT_DISPOSITION));
        assert_eq!(headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
    }

    #[test]
    fn download_names_cannot_walk_out_of_the_upload_directory() {
        assert_eq!(sanitize_filename("../../etc/passwd"), "....etcpasswd");
        assert_eq!(sanitize_filename("..\\..\\windows"), "....windows");
        assert_eq!(sanitize_filename(".."), "invalid");
        assert_eq!(sanitize_filename("/"), "invalid");
    }
}
