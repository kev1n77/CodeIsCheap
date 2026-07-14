use std::env;
use std::net::SocketAddr;

use codeischeap_gateway::Gateway;
use tokio::net::TcpListener;
use url::Url;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listen: SocketAddr = env::var("CIC_GATEWAY_LISTEN")
        .unwrap_or_else(|_| "127.0.0.1:3210".to_owned())
        .parse()?;
    let upstream = Url::parse(&env::var("CIC_GATEWAY_UPSTREAM")?)?;
    let gateway = Gateway::new(upstream.clone())?;
    let listener = TcpListener::bind(listen).await?;

    eprintln!("CodeIsCheap gateway listening on http://{listen} -> {upstream}");
    gateway
        .serve(listener, async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
