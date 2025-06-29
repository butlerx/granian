use futures::sink::SinkExt;
use http_body_util::BodyExt;
use hyper::{StatusCode, header::SERVER as HK_SERVER, http::response::Builder as ResponseBuilder};
use std::{net::SocketAddr, sync::Arc};
use tokio::sync::{Notify, mpsc};

use super::{
    callbacks::{call_http, call_ws},
    types::{PyResponse, RSGIHTTPScope as HTTPScope, RSGIWebsocketScope as WebsocketScope},
};
use crate::{
    callbacks::ArcCBScheduler,
    http::{
        HTTPRequest, HTTPResponse, HV_SERVER, empty_body, extract_auth_header, response_401, response_500,
        validate_basic_auth,
    },
    runtime::RuntimeRef,
    ws::{UpgradeData, is_upgrade_request as is_ws_upgrade, upgrade_intent as ws_upgrade},
};

macro_rules! build_scope {
    ($cls:ty, $server_addr:expr, $client_addr:expr, $req:expr, $scheme:expr) => {
        <$cls>::new(
            $req.version,
            $scheme,
            $req.uri,
            $req.method,
            $server_addr,
            $client_addr,
            $req.headers,
        )
    };
}

macro_rules! handle_http_response {
    ($handler:expr, $rt:expr, $disconnect_guard:expr, $callback:expr, $body:expr, $scope:expr) => {
        match $handler($callback, $rt, $disconnect_guard, $body, $scope).await {
            Ok(PyResponse::Body(pyres)) => pyres.to_response(),
            Ok(PyResponse::File(pyres)) => pyres.to_response().await,
            _ => {
                log::error!("RSGI protocol failure");
                response_500()
            }
        }
    };
}

macro_rules! handle_request {
    ($func_name:ident, $handler:expr) => {
        #[inline]
        pub(crate) async fn $func_name(
            rt: RuntimeRef,
            disconnect_guard: Arc<Notify>,
            callback: ArcCBScheduler,
            server_addr: SocketAddr,
            client_addr: SocketAddr,
            req: HTTPRequest,
            scheme: &str,
        ) -> HTTPResponse {
            let (parts, body) = req.into_parts();
            let scope = build_scope!(HTTPScope, server_addr, client_addr, parts, scheme);
            handle_http_response!($handler, rt, disconnect_guard, callback, body, scope)
        }
    };
}

macro_rules! handle_request_with_ws {
    ($func_name:ident, $handler_req:expr, $handler_ws:expr) => {
        #[inline]
        pub(crate) async fn $func_name(
            rt: RuntimeRef,
            disconnect_guard: Arc<Notify>,
            callback: ArcCBScheduler,
            server_addr: SocketAddr,
            client_addr: SocketAddr,
            mut req: HTTPRequest,
            scheme: &str,
        ) -> HTTPResponse {
            if is_ws_upgrade(&req) {
                return match ws_upgrade(&mut req, None) {
                    Ok((res, ws)) => {
                        let (restx, mut resrx) = mpsc::channel(1);
                        let (parts, _) = req.into_parts();
                        let scheme: Box<str> = match scheme {
                            "https" => "wss",
                            _ => "ws",
                        }
                        .into();

                        tokio::task::spawn(async move {
                            let tx_ref = restx.clone();
                            let scope = build_scope!(WebsocketScope, server_addr, client_addr, parts, &scheme);

                            match $handler_ws(callback, rt, ws, UpgradeData::new(res, restx), scope).await {
                                Ok((status, consumed, stream)) => match (consumed, stream) {
                                    (false, _) => {
                                        let _ = tx_ref
                                            .send(
                                                ResponseBuilder::new()
                                                    .status(status as u16)
                                                    .header(HK_SERVER, HV_SERVER)
                                                    .body(empty_body())
                                                    .unwrap(),
                                            )
                                            .await;
                                    }
                                    (true, Some(mut stream)) => {
                                        let _ = stream.close().await;
                                    }
                                    _ => {}
                                },
                                _ => {
                                    log::error!("RSGI protocol failure");
                                    let _ = tx_ref.send(response_500()).await;
                                }
                            }
                        });

                        match resrx.recv().await {
                            Some(res) => {
                                resrx.close();
                                res
                            }
                            _ => response_500(),
                        };
                    }
                    Err(err) => {
                        log::info!("Websocket handshake failed with {:?}", err);
                        return ResponseBuilder::new()
                            .status(StatusCode::BAD_REQUEST)
                            .header(HK_SERVER, HV_SERVER)
                            .body(
                                http_body_util::Full::new(format!("{}", err).into())
                                    .map_err(|e| match e {})
                                    .boxed(),
                            )
                            .unwrap();
                    }
                };
            }

            let (parts, body) = req.into_parts();
            let scope = build_scope!(HTTPScope, server_addr, client_addr, parts, scheme);
            handle_http_response!($handler_req, rt, disconnect_guard, callback, body, scope)
        }
    };
}

// Default handlers without authentication
handle_request!(handle, call_http);
handle_request_with_ws!(handle_ws, call_http, call_ws);

// Export authentication-aware handlers (these will be used when auth is enabled)
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
    let scope = build_scope!(HTTPScope, server_addr, client_addr, parts, scheme);
    handle_http_response!(call_http, rt, disconnect_guard, callback, body, scope)
}

pub(crate) async fn handle_ws_with_auth(
    rt: RuntimeRef,
    disconnect_guard: Arc<Notify>,
    callback: ArcCBScheduler,
    server_addr: SocketAddr,
    client_addr: SocketAddr,
    mut req: HTTPRequest,
    scheme: &str,
    auth_username: Option<&str>,
    auth_password: Option<&str>,
    auth_realm: &str,
) -> HTTPResponse {
    if is_ws_upgrade(&req) {
        // Check authentication for WebSocket upgrade requests
        if let (Some(username), Some(password)) = (auth_username, auth_password) {
            let auth_header = extract_auth_header(&req);
            if !validate_basic_auth(auth_header, username, password) {
                return response_401(auth_realm);
            }
        }

        return match ws_upgrade(&mut req, None) {
            Ok((res, ws)) => {
                let (restx, mut resrx) = mpsc::channel(1);
                let (parts, _) = req.into_parts();
                let scheme: Box<str> = match scheme {
                    "https" => "wss",
                    _ => "ws",
                }
                .into();

                tokio::task::spawn(async move {
                    let tx_ref = restx.clone();
                    let scope = build_scope!(WebsocketScope, server_addr, client_addr, parts, &scheme);

                    match call_ws(callback, rt, ws, UpgradeData::new(res, restx), scope).await {
                        Ok((status, consumed, stream)) => match (consumed, stream) {
                            (false, _) => {
                                let _ = tx_ref
                                    .send(
                                        ResponseBuilder::new()
                                            .status(status as u16)
                                            .header(HK_SERVER, HV_SERVER)
                                            .body(empty_body())
                                            .unwrap(),
                                    )
                                    .await;
                            }
                            (true, Some(mut stream)) => {
                                let _ = stream.close().await;
                            }
                            _ => {}
                        },
                        _ => {
                            log::error!("RSGI protocol failure");
                            let _ = tx_ref.send(response_500()).await;
                        }
                    }
                });

                match resrx.recv().await {
                    Some(res) => {
                        resrx.close();
                        res
                    }
                    _ => response_500(),
                }
            }
            Err(err) => {
                log::info!("Websocket handshake failed with {:?}", err);
                return ResponseBuilder::new()
                    .status(StatusCode::BAD_REQUEST)
                    .header(HK_SERVER, HV_SERVER)
                    .body(
                        http_body_util::Full::new(format!("{}", err).into())
                            .map_err(|e| match e {})
                            .boxed(),
                    )
                    .unwrap();
            }
        };
    }

    // Check authentication for regular HTTP requests
    if let (Some(username), Some(password)) = (auth_username, auth_password) {
        let auth_header = extract_auth_header(&req);
        if !validate_basic_auth(auth_header, username, password) {
            return response_401(auth_realm);
        }
    }

    let (parts, body) = req.into_parts();
    let scope = build_scope!(HTTPScope, server_addr, client_addr, parts, scheme);
    handle_http_response!(call_http, rt, disconnect_guard, callback, body, scope)
}
