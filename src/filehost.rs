use axum::{
    body::Body,
    extract::{Path, State},
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
use tracing::{error, info};

/// Shared state for the filehost HTTP handlers.
#[derive(Clone)]
pub struct FilehostState {
    pub upload_dir: PathBuf,
    pub public_url: String,
    pub max_size: usize,
    pub db_pool: sqlx::MySqlPool,
}

/// Build the axum router for the filehost.
pub fn router(fh_state: Arc<FilehostState>) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::HEAD, Method::POST, Method::OPTIONS])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            header::CONTENT_LENGTH,
        ])
        .expose_headers([header::LOCATION, header::CONTENT_LENGTH]);

    Router::new()
        .route("/", post(upload_file))
        .route("/{filename}", get(download_file))
        .route("/{filename}", head(head_file))
        .layer(middleware::from_fn_with_state(
            fh_state.clone(),
            auth_middleware,
        ))
        .layer(cors)
        .with_state(fh_state)
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
        .and_then(|v| v.to_str().ok());

    let Some(auth_str) = auth_header else {
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Basic realm=\"rIRCd filehost\"")],
            "Authentication required",
        )
            .into_response();
    };

    let Some(credentials) = auth_str.strip_prefix("Basic ") else {
        return (StatusCode::BAD_REQUEST, "Invalid Authorization header").into_response();
    };

    let decoded =
        match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, credentials) {
            Ok(d) => d,
            Err(_) => return (StatusCode::BAD_REQUEST, "Invalid base64").into_response(),
        };

    let decoded_str = match String::from_utf8(decoded) {
        Ok(s) => s,
        Err(_) => return (StatusCode::BAD_REQUEST, "Invalid UTF-8").into_response(),
    };

    let Some((user, pass)) = decoded_str.split_once(':') else {
        return (StatusCode::BAD_REQUEST, "Invalid credentials format").into_response();
    };

    if !crate::persist::verify_user(&fh_state.db_pool, user, pass).await {
        return (StatusCode::FORBIDDEN, "Invalid username or password").into_response();
    }

    next.run(req).await
}

/// POST / — upload a file, return the download URL in Location header.
async fn upload_file(
    State(fh_state): State<Arc<FilehostState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if body.len() > fh_state.max_size {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("File exceeds maximum size of {} bytes", fh_state.max_size),
        )
            .into_response();
    }

    if body.is_empty() {
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

    let ext = original_name
        .as_deref()
        .and_then(|n| n.rsplit('.').next())
        .map(|e| format!(".{}", e))
        .unwrap_or_default();

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
        "File uploaded"
    );

    let mut resp = (StatusCode::CREATED, url.clone()).into_response();
    resp.headers_mut()
        .insert(header::LOCATION, HeaderValue::from_str(&url).unwrap());
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

    let content_type = mime_guess::from_path(&safe_name)
        .first_or_octet_stream()
        .to_string();

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(&content_type)
            .unwrap_or(HeaderValue::from_static("application/octet-stream")),
    );
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

    let content_type = mime_guess::from_path(&safe_name)
        .first_or_octet_stream()
        .to_string();

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(&content_type)
            .unwrap_or(HeaderValue::from_static("application/octet-stream")),
    );
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(meta.len()));

    (StatusCode::OK, headers).into_response()
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
