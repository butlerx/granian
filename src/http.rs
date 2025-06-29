use http_body_util::BodyExt;
use hyper::{
    Response,
    body::Bytes,
    header::{AUTHORIZATION, HeaderValue, SERVER as HK_SERVER, WWW_AUTHENTICATE},
};

pub(crate) type HTTPRequest = hyper::Request<hyper::body::Incoming>;
pub(crate) type HTTPResponseBody = http_body_util::combinators::BoxBody<Bytes, anyhow::Error>;
pub(crate) type HTTPResponse = hyper::Response<HTTPResponseBody>;

pub(crate) const HV_SERVER: HeaderValue = HeaderValue::from_static("granian");

pub(crate) fn response_404() -> HTTPResponse {
    let mut builder = Response::builder().status(404);
    let headers = builder.headers_mut().unwrap();
    headers.insert(HK_SERVER, HV_SERVER);
    builder
        .body(
            http_body_util::Full::new("Not found".into())
                .map_err(|e| match e {})
                .boxed(),
        )
        .unwrap()
}

pub(crate) fn response_500() -> HTTPResponse {
    let mut builder = Response::builder().status(500);
    let headers = builder.headers_mut().unwrap();
    headers.insert(HK_SERVER, HV_SERVER);
    builder
        .body(
            http_body_util::Full::new("Internal server error".into())
                .map_err(|e| match e {})
                .boxed(),
        )
        .unwrap()
}

pub(crate) fn response_401(realm: &str) -> HTTPResponse {
    let mut builder = Response::builder().status(401);
    let headers = builder.headers_mut().unwrap();
    headers.insert(HK_SERVER, HV_SERVER);
    headers.insert(WWW_AUTHENTICATE, format!("Basic realm=\"{}\"", realm).parse().unwrap());
    builder
        .body(
            http_body_util::Full::new("Unauthorized".into())
                .map_err(|e| match e {})
                .boxed(),
        )
        .unwrap()
}

#[inline(always)]
pub(crate) fn empty_body() -> HTTPResponseBody {
    http_body_util::Empty::<Bytes>::new().map_err(|e| match e {}).boxed()
}

pub(crate) fn extract_auth_header(req: &HTTPRequest) -> Option<String> {
    req.headers()
        .get(AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string())
}

pub(crate) fn validate_basic_auth(
    auth_header: Option<String>,
    expected_username: &str,
    expected_password: &str,
) -> bool {
    match auth_header {
        Some(header) if header.starts_with("Basic ") => {
            let encoded = &header[6..]; // Remove "Basic " prefix
            if let Ok(decoded) = base64::decode(encoded) {
                if let Ok(credentials) = String::from_utf8(decoded) {
                    if let Some((username, password)) = credentials.split_once(':') {
                        return username == expected_username && password == expected_password;
                    }
                }
            }
            false
        }
        _ => false,
    }
}
