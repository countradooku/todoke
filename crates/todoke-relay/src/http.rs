//! The operator's HTTP endpoint: `/metrics` (Prometheus text, totals only)
//! and `/healthz`. Off unless an address is given; bind it to loopback or
//! a private network.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::Notify;

use crate::server::Metrics;

/// Serves `metrics` on `address` until `stop` is notified.
///
/// # Errors
///
/// If the address cannot be bound.
pub async fn serve_metrics(
    address: SocketAddr,
    metrics: Arc<Metrics>,
    stop: Arc<Notify>,
) -> std::io::Result<()> {
    let app = axum::Router::new()
        .route(
            "/metrics",
            axum::routing::get(move || {
                let metrics = Arc::clone(&metrics);
                async move { metrics.render() }
            }),
        )
        .route("/healthz", axum::routing::get(|| async { "ok" }));
    let listener = tokio::net::TcpListener::bind(address).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(async move { stop.notified().await })
        .await
}
