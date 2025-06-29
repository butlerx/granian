use hyper::Response;
use std::{net::SocketAddr, sync::Arc};
use tokio::sync::Notify;

use super::callbacks::call_http;
use crate::{
    callbacks::ArcCBScheduler,
    http::{
        HTTPRequest, HTTPResponse, HTTPResponseBody, extract_auth_header, response_401, response_500,
        validate_basic_auth,
    },
    runtime::RuntimeRef,
};

#[inline(always)]
fn build_response(status: u16, pyheaders: hyper::HeaderMap, body: HTTPResponseBody) -> HTTPResponse {
    let mut res = Response::new(body);
    *res.status_mut() = hyper::StatusCode::from_u16(status).unwrap();
    *res.headers_mut() = pyheaders;
    res
}

#[inline]
pub(crate) async fn handle(
    rt: RuntimeRef,
    _disconnect_guard: Arc<Notify>,
    callback: ArcCBScheduler,
    server_addr: SocketAddr,
    client_addr: SocketAddr,
    req: HTTPRequest,
    scheme: &str,
) -> HTTPResponse {
    let (parts, body) = req.into_parts();
    if let Ok((status, headers, body)) =
        call_http(rt, callback, server_addr, client_addr, scheme.into(), parts, body).await
    {
        return build_response(status, headers, body);
    }

    log::error!("WSGI protocol failure");
    response_500()
}

// Export authentication-aware handler (this will be used when auth is enabled)
pub(crate) async fn handle_with_auth(
    rt: RuntimeRef,
    disconnect_guard: Arc<Notify>,
    callback: ArcCBScheduler,
    server_addr: SocketAddr,
    client_addr: SocketAddr,
    req: HTTPRequest,
    scheme: &str,
    auth_username: Option<&str>,
    auth_password: Option<&str>,
    auth_realm: &str,
) -> HTTPResponse {
    // Check authentication if credentials are provided
    if let (Some(username), Some(password)) = (auth_username, auth_password) {
        let auth_header = extract_auth_header(&req);
        if !validate_basic_auth(auth_header, username, password) {
            return response_401(auth_realm);
        }
    }

    let (parts, body) = req.into_parts();
    if let Ok((status, headers, body)) =
        call_http(rt, callback, server_addr, client_addr, scheme.into(), parts, body).await
    {
        return build_response(status, headers, body);
    }

    log::error!("WSGI protocol failure");
    response_500()
}
