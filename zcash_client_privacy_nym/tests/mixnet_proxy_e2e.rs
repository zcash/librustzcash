//! In-process end-to-end test for the mixnet-proxy backend.
//!
//! This test uses the **live, free Nym mixnet**. It is `#[ignore]`d so it never runs in
//! CI; run it explicitly with:
//!
//! ```text
//! cargo test -p zcash_client_privacy_nym --features mixnet-proxy --test mixnet_proxy_e2e -- --ignored --nocapture
//! ```
//!
//! It spawns a local TCP echo server, fronts it with a [`ProxyListener`] backed by one
//! ephemeral mixnet client, then connects to it through a [`MixnetProxyNetwork`] backed by
//! a second ephemeral mixnet client and round-trips bytes end to end.

#![cfg(feature = "mixnet-proxy")]

use std::time::{Duration, Instant};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

use zcash_client_backend::privacy::PrivateNetwork;
use zcash_client_privacy_nym::mixnet_proxy::{
    proxy_listener::ProxyListener, MixnetProxyConfig, MixnetProxyNetwork,
};

/// Spawns a local TCP echo server and returns its address.
async fn spawn_echo_server() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let addr = listener.local_addr().expect("echo addr");
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a live connection to the Nym mixnet"]
async fn mixnet_proxy_round_trips_bytes() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .try_init();

    let t0 = Instant::now();
    let elapsed = || t0.elapsed().as_secs_f64();

    // 1. Local echo server that the proxy will forward to.
    let echo_addr = spawn_echo_server().await;
    eprintln!("[{:.1}s] echo server at {echo_addr}", elapsed());

    // 2. Proxy listener (mixnet client #1) fronting the echo server.
    let proxy = ProxyListener::new_ephemeral(echo_addr.to_string())
        .await
        .expect("build proxy listener");
    let recipient = *proxy.nym_address();
    eprintln!(
        "[{:.1}s] proxy listener up; nym_address={recipient}",
        elapsed()
    );
    tokio::spawn(async move {
        if let Err(e) = proxy.run().await {
            eprintln!("proxy run error: {e}");
        }
    });

    // 3. Wallet-side backend (mixnet client #2) routing a logical endpoint to the proxy.
    let config = MixnetProxyConfig::new()
        .route("lightwalletd.test", 443, recipient)
        .stream_idle_timeout(Some(Duration::from_secs(60)));
    let net = MixnetProxyNetwork::new(config);

    eprintln!("[{:.1}s] opening mixnet stream to proxy...", elapsed());
    let mut stream = tokio::time::timeout(
        Duration::from_secs(120),
        net.connect("lightwalletd.test", 443),
    )
    .await
    .expect("connect timed out")
    .expect("connect failed");
    eprintln!("[{:.1}s] stream open; round-tripping bytes", elapsed());

    // 4. Round-trip bytes through: wallet -> mixnet -> proxy -> echo -> proxy -> mixnet.
    let payload = b"hello over the nym mixnet";
    stream.write_all(payload).await.expect("write");
    stream.flush().await.expect("flush");

    let mut received = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(120), stream.read_exact(&mut received))
        .await
        .expect("read timed out")
        .expect("read failed");

    assert_eq!(&received, payload, "echoed payload must match");
    eprintln!(
        "[{:.1}s] SUCCESS: round-tripped {} bytes",
        elapsed(),
        payload.len()
    );
}
