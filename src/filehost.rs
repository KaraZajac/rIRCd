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

/// Shared state for the filehost HTTP handlers.
#[derive(Clone)]
pub struct FilehostState {
    pub upload_dir: PathBuf,
    pub public_url: String,
    pub max_size: usize,
    pub db_pool: sqlx::MySqlPool,
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
        .layer(middleware::from_fn(request_logging))
        .layer(cors)
        .with_state(fh_state)
}

/// Log every incoming request.
async fn request_logging(req: Request<Body>, next: Next) -> Response {
    let method = req.method().clone();
    let uri = req.uri().clone();
    info!(method = %method, uri = %uri, "Filehost request");
    let resp = next.run(req).await;
    let status = resp.status();
    if status.is_client_error() || status.is_server_error() {
        warn!(method = %method, uri = %uri, status = %status, "Filehost response error");
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

    if !crate::persist::verify_user(&fh_state.db_pool, user, pass).await {
        warn!(user = %user, "Filehost upload rejected: bad credentials");
        return (StatusCode::FORBIDDEN, "Invalid username or password").into_response();
    }

    info!(user = %user, "Filehost auth OK");
    next.run(req).await
}

/// POST / — upload a file, return the download URL in Location header.
async fn upload_file(
    State(fh_state): State<Arc<FilehostState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    info!(size = body.len(), "Filehost upload body received");

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
fn extract_url_path(url: &str) -> String {
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
