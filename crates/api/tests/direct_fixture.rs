//! Opt-in, disposable server for the matching real-chatd call probe. Never uses real sessions.
mod common;

use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use api::{Limits, Live};
use common::{first_owner, join, run, session};
use serde_json::json;

#[tokio::test]
#[ignore = "owned disposable client/server fixture; explicitly provide DB URLs and output path"]
async fn direct_calls_fixture_for_client() {
    for name in [
        "TEST_DATABASE_URL_MIGRATE",
        "TEST_DATABASE_URL",
        "DIRECT_CALL_FIXTURE_FILE",
    ] {
        assert!(
            !std::env::var(name).unwrap_or_default().is_empty(),
            "set {name}"
        );
    }
    let output = std::env::var("DIRECT_CALL_FIXTURE_FILE").expect("private fixture output path");
    let bind = std::env::var("DIRECT_CALL_FIXTURE_BIND").unwrap_or_else(|_| "127.0.0.1:0".into());
    let media_bind: SocketAddr = std::env::var("DIRECT_CALL_FIXTURE_MEDIA_BIND")
        .unwrap_or_else(|_| "127.0.0.1:0".into())
        .parse()
        .expect("fixture media bind");
    let seconds: u64 = std::env::var("DIRECT_CALL_FIXTURE_SECONDS")
        .unwrap_or_else(|_| "1800".into())
        .parse()
        .expect("fixture duration");
    assert!(
        (1..=7200).contains(&seconds),
        "fixture lifetime must be 1..7200 seconds"
    );
    run(|db| async move {
        let owner = first_owner(&db).await;
        let owner_token = session(&db, &owner.user_id).await;
        let (peer, peer_token) = join(&db, &owner, "peer@tinyserver.test", "member").await;
        let config = sfu::Config::new(media_bind, Ipv4Addr::LOCALHOST.into());
        let (media, events) = sfu::start(config).expect("fixture SFU");
        let live = Live::with_media(db.runtime.clone(), Limits::default(), media, events);
        let listener = tokio::net::TcpListener::bind(&bind).await.expect("fixture listener");
        let addr = listener.local_addr().expect("fixture address");
        let base_url = std::env::var("DIRECT_CALL_FIXTURE_URL")
            .unwrap_or_else(|_| format!("http://{addr}"));
        let app = api::app(db.runtime.clone(), live.clone(), None);
        let serving = tokio::spawn(async move { axum::serve(listener, app).await });
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&output).expect("private fixture output");
        let fixture = json!({
            "base_url": base_url,
            "direct_id": null,
            "owner": {"user_id": owner.user_id, "token": owner_token, "display_name": "Owner"},
            "peer": {"user_id": peer.user_id, "token": peer_token, "display_name": "Peer"},
            "transport": "forward the advertised ICE-TCP media port as well as the API through an SSH tunnel"
        });
        file.write_all(fixture.to_string().as_bytes()).expect("write fixture");
        file.sync_all().expect("flush fixture");
        println!("Disposable two-member fixture ready; session values are only in the private output file.");
        tokio::time::sleep(Duration::from_secs(seconds)).await;
        live.close();
        serving.abort();
        std::fs::remove_file(output).expect("remove expired fixture sessions");
    })
    .await;
}
