//! Native HighWall data-plane prototype.

pub mod audit;
pub mod config;
pub mod error;
pub mod gateway;
pub mod h1;
pub mod h1_server;
pub mod h2_server;
pub mod h3_server;
pub mod http;
pub mod inspect;
pub mod io_util;
pub mod limits;
pub mod policy;
pub mod proxy_protocol;
pub mod server;
pub mod state;
pub mod tls;
pub mod upstream;
pub mod ws;

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
