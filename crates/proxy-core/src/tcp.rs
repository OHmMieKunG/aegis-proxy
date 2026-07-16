use std::{io, sync::Arc, time::Duration};

use aegisproxy_config::LimitsConfig;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Semaphore,
};
use tokio_util::sync::CancellationToken;

use super::{RuntimeHandle, endpoint_key};

const CLIENT_HELLO_MAX_BYTES: usize = 16 * 1024;
const RELAY_BUFFER_BYTES: usize = 16 * 1024;

#[derive(Clone)]
pub(crate) struct TcpListenerContext {
    pub(crate) listener_id: String,
    pub(crate) tls_passthrough: bool,
    pub(crate) runtime: RuntimeHandle,
    pub(crate) limits: LimitsConfig,
    pub(crate) handshake_permits: Arc<Semaphore>,
    pub(crate) shutdown: CancellationToken,
}

pub(crate) async fn accept_loop(listener: TcpListener, context: TcpListenerContext) {
    let permits = Arc::new(Semaphore::new(context.limits.max_connections));
    let mut connections = tokio::task::JoinSet::new();
    loop {
        let accepted = tokio::select! {
            biased;
            _ = context.shutdown.cancelled() => break,
            completed = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(error)) = completed {
                    tracing::debug!(%error, "TCP connection task failed");
                }
                continue;
            }
            result = listener.accept() => result,
        };
        let Ok((stream, peer)) = accepted else {
            continue;
        };
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            tracing::debug!(%peer, "TCP connection limit reached");
            continue;
        };
        let handshake_permit = if context.tls_passthrough {
            let Ok(permit) = context.handshake_permits.clone().try_acquire_owned() else {
                tracing::debug!(%peer, "TLS ClientHello limit reached");
                continue;
            };
            Some(permit)
        } else {
            None
        };
        let connection = context.clone();
        connections.spawn(async move {
            let _permit = permit;
            let result = proxy_connection(stream, &connection, handshake_permit).await;
            if let Err(error) = result {
                tracing::debug!(%peer, %error, "TCP connection ended");
            }
        });
    }
    drop(listener);
    let deadline = Duration::from_secs(context.runtime.load().config.runtime.shutdown_grace_secs);
    if tokio::time::timeout(deadline, async {
        while connections.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        connections.abort_all();
        while connections.join_next().await.is_some() {}
    }
}

async fn proxy_connection(
    mut client: TcpStream,
    context: &TcpListenerContext,
    handshake_permit: Option<tokio::sync::OwnedSemaphorePermit>,
) -> io::Result<()> {
    let snapshot = context.runtime.load();
    let (prefix, server_name) = if context.tls_passthrough {
        let result = tokio::time::timeout(
            Duration::from_secs(snapshot.config.tls.handshake_timeout_secs),
            read_client_hello(&mut client),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TLS ClientHello timed out"))??;
        drop(handshake_permit);
        result
    } else {
        drop(handshake_permit);
        (Vec::new(), None)
    };
    let route = snapshot
        .route_index
        .select_sni(
            &snapshot.config,
            &context.listener_id,
            server_name.as_deref(),
        )
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no matching TCP route"))?;
    let group_id = route
        .upstream_group
        .as_deref()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "TCP route has no upstream"))?
        .to_owned();
    let pool = snapshot
        .upstream_pools
        .get(&group_id)
        .cloned()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "TCP upstream group is missing"))?;
    let selected = pool
        .select()
        .map_err(|_| io::Error::new(io::ErrorKind::NotConnected, "TCP upstream unavailable"))?;
    let dns = snapshot
        .dns_endpoints
        .get(&endpoint_key(&group_id, &selected.config().id))
        .cloned()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "TCP DNS endpoint is missing"))?;
    let connect_timeout = Duration::from_secs(snapshot.config.limits.tcp_connect_timeout_secs);
    let idle_timeout = Duration::from_secs(snapshot.config.limits.tcp_idle_timeout_secs);
    let lifetime = Duration::from_secs(snapshot.config.limits.tcp_connection_lifetime_secs);
    drop(snapshot);
    let mut upstream = match connect_upstream(&dns, connect_timeout).await {
        Ok(stream) => stream,
        Err(error) => {
            selected.record_failure();
            return Err(error);
        }
    };
    if !prefix.is_empty() {
        if let Err(error) = tokio::time::timeout(connect_timeout, upstream.write_all(&prefix))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TCP prefix write timed out"))?
        {
            selected.record_failure();
            return Err(error);
        }
    }
    selected.record_success();
    let drain = selected.drain_token();
    tokio::select! {
        result = relay(&mut client, &mut upstream, idle_timeout, lifetime) => result,
        () = drain.cancelled() => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "upstream drain deadline reached",
        )),
    }
}

async fn read_client_hello(client: &mut TcpStream) -> io::Result<(Vec<u8>, Option<String>)> {
    let mut acceptor = rustls::server::Acceptor::default();
    let mut prefix = Vec::with_capacity(CLIENT_HELLO_MAX_BYTES);
    let mut chunk = [0_u8; 4096];
    loop {
        let remaining = CLIENT_HELLO_MAX_BYTES.saturating_sub(prefix.len());
        if remaining == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "TLS ClientHello exceeds configured bound",
            ));
        }
        let read_limit = remaining.min(chunk.len());
        let count = client.read(&mut chunk[..read_limit]).await?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed before TLS ClientHello",
            ));
        }
        prefix.extend_from_slice(&chunk[..count]);
        let mut input = io::Cursor::new(&chunk[..count]);
        let consumed = acceptor.read_tls(&mut input)?;
        if consumed != count {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "TLS ClientHello parser did not consume captured bytes",
            ));
        }
        match acceptor.accept() {
            Ok(Some(accepted)) => {
                let server_name = accepted.client_hello().server_name().map(str::to_owned);
                return Ok((prefix, server_name));
            }
            Ok(None) => {}
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "malformed TLS ClientHello",
                ));
            }
        }
    }
}

async fn connect_upstream(
    endpoint: &super::DnsEndpoint,
    timeout: Duration,
) -> io::Result<TcpStream> {
    let addresses = endpoint.connection_addresses()?;
    let deadline = tokio::time::Instant::now() + timeout;
    let mut last_error = None;
    for address in addresses {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, TcpStream::connect(address)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(error)) => last_error = Some(error),
            Err(_) => break,
        }
    }
    Err(last_error.unwrap_or_else(|| {
        io::Error::new(io::ErrorKind::TimedOut, "TCP upstream connect timed out")
    }))
}

async fn relay(
    client: &mut TcpStream,
    upstream: &mut TcpStream,
    idle_timeout: Duration,
    lifetime: Duration,
) -> io::Result<()> {
    let (client_read, client_write) = client.split();
    let (upstream_read, upstream_write) = upstream.split();
    let copying = async {
        tokio::try_join!(
            copy_direction(client_read, upstream_write, idle_timeout),
            copy_direction(upstream_read, client_write, idle_timeout)
        )?;
        Ok(())
    };
    tokio::time::timeout(lifetime, copying)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TCP connection lifetime exceeded"))?
}

async fn copy_direction<R, W>(
    mut reader: R,
    mut writer: W,
    idle_timeout: Duration,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = [0_u8; RELAY_BUFFER_BYTES];
    loop {
        let count = tokio::time::timeout(idle_timeout, reader.read(&mut buffer))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TCP relay read timed out"))??;
        if count == 0 {
            writer.shutdown().await?;
            return Ok(());
        }
        tokio::time::timeout(idle_timeout, writer.write_all(&buffer[..count]))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TCP relay write timed out"))??;
    }
}
