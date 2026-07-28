//! Running port forwards for a live session.
//!
//! Both directions come down to the same shape once a socket exists: pair it
//! with an SSH channel and copy bytes until one end stops. What differs is who
//! opens the socket.
//!
//! - **local** — we bind a `TcpListener` here. Each accepted connection opens a
//!   `direct-tcpip` channel, which the server connects onward. This is the same
//!   primitive the jump-host code uses to tunnel to the next hop.
//! - **remote** — we ask the server to listen (`tcpip_forward`). Connections
//!   arrive as channels the *server* opens, which is why they are picked up in
//!   [`crate::ssh::Client`]'s handler rather than here.
//!
//! Everything runs on the tokio runtime, never on the render thread, and keeps
//! running while the session is detached — a tunnel you have to stay attached to
//! would be useless, since staying attached is what you detached to avoid.

use std::sync::Arc;

use russh::client::Handle;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::UnboundedSender;

use crate::config::{Direction, Forward};
use crate::ssh::{Client, SshEvent};

/// A running forward. Dropping this does nothing; the session aborts the task
/// when it ends, so the listeners die exactly when the connection carrying them
/// does rather than lingering on a port.
pub struct Running {
    pub task: tokio::task::JoinHandle<()>,
}

/// Everything that happened while raising a session's forwards.
#[derive(Default)]
pub struct Started {
    pub running: Vec<Running>,
    /// Forwards that could not be raised, phrased for the status line.
    ///
    /// Collected rather than fatal, matching `ssh`, which reports a failed bind
    /// and carries on. Losing an otherwise good shell because a port is busy is
    /// the worse of the two failures — but staying *silent* is worse than
    /// either: you would connect to `localhost:8080` expecting the tunnel and
    /// reach whatever else already had the port.
    pub failures: Vec<String>,
}

/// Raise every forward for a session.
///
/// `handle` is the connection to the final hop, shared because each accepted
/// connection opens a channel on it. It is an `Arc` rather than a clone because
/// russh's `Handle` owns the transport task and cannot be cloned — and must not
/// be, or the connection would outlive the session that owns it.
pub async fn start(
    forwards: &[Forward],
    handle: Arc<Handle<Client>>,
    tx: &UnboundedSender<SshEvent>,
) -> Started {
    let mut started = Started::default();

    for forward in forwards {
        match forward.direction {
            Direction::Local => match bind_local(forward).await {
                Ok(listener) => {
                    let _ = tx.send(SshEvent::Progress(format!(
                        "forwarding {}",
                        forward.describe()
                    )));
                    started.running.push(Running {
                        task: tokio::spawn(serve_local(
                            forward.clone(),
                            Arc::clone(&handle),
                            listener,
                        )),
                    });
                }
                Err(message) => started.failures.push(message),
            },

            // Nothing to spawn: the server does the listening, and the channels
            // it opens are picked up by the connection's own handler.
            Direction::Remote => {
                match handle
                    .tcpip_forward(forward.listen_host.clone(), u32::from(forward.listen_port))
                    .await
                {
                    Ok(_) => {
                        let _ = tx.send(SshEvent::Progress(format!(
                            "forwarding {}",
                            forward.describe()
                        )));
                    }
                    // Overwhelmingly this is the server's `GatewayPorts`/
                    // `AllowTcpForwarding` policy rather than anything we did,
                    // so the message points there rather than at a bug.
                    Err(_) => started.failures.push(format!(
                        "{} refused to listen on {} — check AllowTcpForwarding and GatewayPorts",
                        "the server",
                        forward.listen_addr()
                    )),
                }
            }
        }
    }

    started
}

/// Open the listening socket for a local forward.
///
/// Split out so it can be tested for real. The failure message names the
/// address: "address already in use" on its own is useless when a host has
/// several forwards and one of them is the problem.
async fn bind_local(forward: &Forward) -> Result<TcpListener, String> {
    TcpListener::bind(forward.listen_addr())
        .await
        .map_err(|err| format!("could not listen on {}: {err}", forward.listen_addr()))
}

/// Accept connections for one local forward until the listener dies.
///
/// One failed connection must never take the listener down with it: a database
/// that refuses a single connection would otherwise silently disable the tunnel
/// for the rest of the session.
async fn serve_local(forward: Forward, handle: Arc<Handle<Client>>, listener: TcpListener) {
    loop {
        let Ok((socket, peer)) = listener.accept().await else {
            // The listener itself failed — out of descriptors, or shutting
            // down. Nothing here can recover it.
            return;
        };

        let handle = Arc::clone(&handle);
        let forward = forward.clone();
        tokio::spawn(async move {
            // The originator is reported to the server as-is. It is
            // informational — it lands in the server's logs — and lying about
            // it would make a forwarded connection impossible to trace.
            let opened = handle
                .channel_open_direct_tcpip(
                    forward.to_host.clone(),
                    u32::from(forward.to_port),
                    peer.ip().to_string(),
                    u32::from(peer.port()),
                )
                .await;

            if let Ok(channel) = opened {
                let mut socket = socket;
                let mut stream = channel.into_stream();
                // Ends when either side closes. The result is deliberately
                // dropped: a peer hanging up mid-transfer is ordinary, and
                // there is nowhere useful to report it to.
                let _ = tokio::io::copy_bidirectional(&mut socket, &mut stream).await;
            }
        });
    }
}

/// Handle one connection the server opened for a remote forward.
///
/// Called from the connection handler, which is the only place server-opened
/// channels arrive.
pub fn serve_remote(forward: Forward, channel: russh::Channel<russh::client::Msg>) {
    tokio::spawn(async move {
        let target = format!("{}:{}", forward.to_host, forward.to_port);
        if let Ok(mut socket) = TcpStream::connect(&target).await {
            let mut stream = channel.into_stream();
            let _ = tokio::io::copy_bidirectional(&mut socket, &mut stream).await;
        }
        // A refused local connection closes the channel when `channel` drops,
        // which is what the far end needs to see.
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The security property, checked by binding for real and asking the OS
    /// what it gave us rather than by inspecting the string we passed it. A
    /// forward that quietly lands on `0.0.0.0` publishes whatever is on the far
    /// end to the whole network.
    #[tokio::test]
    async fn a_default_forward_binds_loopback_only() {
        let forward = Forward::parse("L 45871:example.internal:80").unwrap();
        let listener = bind_local(&forward).await.unwrap();
        let addr = listener.local_addr().unwrap();

        assert!(
            addr.ip().is_loopback(),
            "bound {addr}, which is reachable from the network"
        );
    }

    /// And an explicit wildcard is honoured, because a forward you deliberately
    /// widened has to actually widen.
    #[tokio::test]
    async fn an_explicit_wildcard_bind_is_honoured() {
        let forward = Forward::parse("L 0.0.0.0:45872:example.internal:80").unwrap();
        let listener = bind_local(&forward).await.unwrap();
        let addr = listener.local_addr().unwrap();

        assert!(addr.ip().is_unspecified(), "bound {addr}, expected 0.0.0.0");
    }

    /// A busy port is reported, not swallowed. Silence here is the dangerous
    /// outcome: you would connect to the port expecting the tunnel and reach
    /// whatever already had it.
    #[tokio::test]
    async fn a_busy_port_is_reported_and_names_itself() {
        let squatter = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = squatter.local_addr().unwrap().port();

        let forward = Forward::parse(&format!("L {port}:example.internal:80")).unwrap();
        let message = bind_local(&forward).await.unwrap_err();

        assert!(
            message.contains(&port.to_string()),
            "the message does not say which port: {message}"
        );
    }
}
