use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use tokio::{io::AsyncReadExt, net::TcpStream, time::timeout};

use crate::config::{ProxyProtocolConfig, ProxyProtocolMode};

const SIGNATURE: &[u8; 12] = b"\r\n\r\n\0\r\nQUIT\n";
const PROXY_COMMAND: u8 = 0x21;
const TCP_OVER_IPV4: u8 = 0x11;
const TCP_OVER_IPV6: u8 = 0x21;
const MIN_TCP4_ADDRESS_BYTES: usize = 12;
const MIN_TCP6_ADDRESS_BYTES: usize = 36;
const MAX_HEADER_BYTES: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedPeer {
    pub peer: SocketAddr,
    pub used_proxy_header: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum ProxyProtocolError {
    #[error("timed out while waiting for the PROXY v2 header")]
    Timeout,
    #[error("I/O error while reading the PROXY v2 header: {0}")]
    Io(#[from] io::Error),
    #[error("the trusted proxy did not send a PROXY v2 header")]
    MissingHeader,
    #[error("peer is not in proxy_protocol.trusted_proxy_networks")]
    UntrustedPeer,
    #[error("invalid PROXY v2 header: {0}")]
    Invalid(&'static str),
}

pub async fn resolve_peer(
    stream: &mut TcpStream,
    raw_peer: SocketAddr,
    config: &ProxyProtocolConfig,
    header_timeout: Duration,
) -> Result<ResolvedPeer, ProxyProtocolError> {
    if config.mode == ProxyProtocolMode::Off {
        return Ok(ResolvedPeer {
            peer: raw_peer,
            used_proxy_header: false,
        });
    }

    if !config.trusts(raw_peer.ip()) {
        return if config.mode == ProxyProtocolMode::Required {
            Err(ProxyProtocolError::UntrustedPeer)
        } else {
            Ok(ResolvedPeer {
                peer: raw_peer,
                used_proxy_header: false,
            })
        };
    }

    let mut first = [0_u8; 1];
    let peeked = timeout(header_timeout, stream.peek(&mut first))
        .await
        .map_err(|_| ProxyProtocolError::Timeout)??;
    if peeked == 0 || first[0] != SIGNATURE[0] {
        return if config.mode == ProxyProtocolMode::Required {
            Err(ProxyProtocolError::MissingHeader)
        } else {
            Ok(ResolvedPeer {
                peer: raw_peer,
                used_proxy_header: false,
            })
        };
    }

    let frame = timeout(header_timeout, read_frame(stream))
        .await
        .map_err(|_| ProxyProtocolError::Timeout)??;
    let source = parse_v2_header(&frame)?;
    Ok(ResolvedPeer {
        peer: source,
        used_proxy_header: true,
    })
}

async fn read_frame(stream: &mut TcpStream) -> Result<Vec<u8>, ProxyProtocolError> {
    let mut fixed = [0_u8; 16];
    stream.read_exact(&mut fixed).await?;
    if &fixed[..SIGNATURE.len()] != SIGNATURE {
        return Err(ProxyProtocolError::Invalid("signature mismatch"));
    }
    let payload_length = u16::from_be_bytes([fixed[14], fixed[15]]) as usize;
    if payload_length > MAX_HEADER_BYTES {
        return Err(ProxyProtocolError::Invalid("header exceeds the size limit"));
    }
    let mut frame = vec![0_u8; 16 + payload_length];
    frame[..16].copy_from_slice(&fixed);
    stream.read_exact(&mut frame[16..]).await?;
    Ok(frame)
}

pub fn parse_v2_header(frame: &[u8]) -> Result<SocketAddr, ProxyProtocolError> {
    if frame.len() < 16 {
        return Err(ProxyProtocolError::Invalid("truncated fixed header"));
    }
    if &frame[..SIGNATURE.len()] != SIGNATURE {
        return Err(ProxyProtocolError::Invalid("signature mismatch"));
    }
    if frame[12] != PROXY_COMMAND {
        return Err(ProxyProtocolError::Invalid(
            "only the PROXY command of version 2 is accepted",
        ));
    }

    let payload_length = u16::from_be_bytes([frame[14], frame[15]]) as usize;
    if payload_length > MAX_HEADER_BYTES {
        return Err(ProxyProtocolError::Invalid("header exceeds the size limit"));
    }
    if frame.len() != 16 + payload_length {
        return Err(ProxyProtocolError::Invalid(
            "header length does not match payload",
        ));
    }
    let payload = &frame[16..];

    let (source, source_port) = match frame[13] {
        TCP_OVER_IPV4 => {
            if payload.len() < MIN_TCP4_ADDRESS_BYTES {
                return Err(ProxyProtocolError::Invalid(
                    "truncated TCP/IPv4 address block",
                ));
            }
            let source = Ipv4Addr::new(payload[0], payload[1], payload[2], payload[3]);
            let source_port = u16::from_be_bytes([payload[8], payload[9]]);
            (IpAddr::V4(source), source_port)
        }
        TCP_OVER_IPV6 => {
            if payload.len() < MIN_TCP6_ADDRESS_BYTES {
                return Err(ProxyProtocolError::Invalid(
                    "truncated TCP/IPv6 address block",
                ));
            }
            let source = Ipv6Addr::from(
                <[u8; 16]>::try_from(&payload[..16])
                    .expect("the IPv6 source length was checked above"),
            );
            let source_port = u16::from_be_bytes([payload[32], payload[33]]);
            (IpAddr::V6(source), source_port)
        }
        _ => {
            return Err(ProxyProtocolError::Invalid(
                "only TCP over IPv4 or IPv6 is accepted",
            ))
        }
    };

    if source_port == 0 {
        return Err(ProxyProtocolError::Invalid("source port must be non-zero"));
    }
    if source.is_unspecified() || source.is_multicast() {
        return Err(ProxyProtocolError::Invalid(
            "source address must be a concrete unicast address",
        ));
    }
    if source == IpAddr::V4(Ipv4Addr::BROADCAST) {
        return Err(ProxyProtocolError::Invalid(
            "source address must not be limited broadcast",
        ));
    }

    Ok(SocketAddr::new(source, source_port))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4_header(
        source: Ipv4Addr,
        source_port: u16,
        destination: Ipv4Addr,
        destination_port: u16,
        tlv: &[u8],
    ) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(SIGNATURE);
        frame.push(PROXY_COMMAND);
        frame.push(TCP_OVER_IPV4);
        let length = 12 + tlv.len();
        frame.extend_from_slice(&(length as u16).to_be_bytes());
        frame.extend_from_slice(&source.octets());
        frame.extend_from_slice(&destination.octets());
        frame.extend_from_slice(&source_port.to_be_bytes());
        frame.extend_from_slice(&destination_port.to_be_bytes());
        frame.extend_from_slice(tlv);
        frame
    }

    fn v6_header(source: Ipv6Addr, source_port: u16) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(SIGNATURE);
        frame.push(PROXY_COMMAND);
        frame.push(TCP_OVER_IPV6);
        frame.extend_from_slice(&36_u16.to_be_bytes());
        frame.extend_from_slice(&source.octets());
        frame.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        frame.extend_from_slice(&source_port.to_be_bytes());
        frame.extend_from_slice(&443_u16.to_be_bytes());
        frame
    }

    #[test]
    fn parses_ipv4_source_and_ignores_tlvs() {
        let frame = v4_header(
            Ipv4Addr::new(203, 0, 113, 9),
            51_234,
            Ipv4Addr::new(192, 0, 2, 10),
            443,
            b"\x04\x00\x01\x00",
        );
        assert_eq!(
            parse_v2_header(&frame).unwrap(),
            SocketAddr::from(([203, 0, 113, 9], 51_234))
        );
    }

    #[test]
    fn parses_ipv6_source() {
        let source = "2001:db8::9".parse::<Ipv6Addr>().unwrap();
        assert_eq!(
            parse_v2_header(&v6_header(source, 51_234)).unwrap(),
            SocketAddr::new(IpAddr::V6(source), 51_234)
        );
    }

    #[test]
    fn rejects_local_command_and_datagram_protocol() {
        let mut local = v4_header(Ipv4Addr::LOCALHOST, 1234, Ipv4Addr::LOCALHOST, 80, b"");
        local[12] = 0x20;
        assert!(parse_v2_header(&local).is_err());

        let mut datagram = v4_header(Ipv4Addr::LOCALHOST, 1234, Ipv4Addr::LOCALHOST, 80, b"");
        datagram[13] = 0x12;
        assert!(parse_v2_header(&datagram).is_err());
    }

    #[test]
    fn rejects_bad_signature_and_truncated_payload() {
        let mut signature = v4_header(Ipv4Addr::LOCALHOST, 1234, Ipv4Addr::LOCALHOST, 80, b"");
        signature[0] = b'X';
        assert!(parse_v2_header(&signature).is_err());

        let mut truncated = v4_header(Ipv4Addr::LOCALHOST, 1234, Ipv4Addr::LOCALHOST, 80, b"");
        truncated.pop();
        assert!(parse_v2_header(&truncated).is_err());
    }

    #[test]
    fn rejects_non_concrete_source_and_zero_port() {
        let unspecified = v4_header(Ipv4Addr::UNSPECIFIED, 1234, Ipv4Addr::LOCALHOST, 80, b"");
        assert!(parse_v2_header(&unspecified).is_err());

        let zero_port = v4_header(Ipv4Addr::LOCALHOST, 0, Ipv4Addr::LOCALHOST, 80, b"");
        assert!(parse_v2_header(&zero_port).is_err());
    }

    #[test]
    fn rejects_oversized_header_before_allocating_payload() {
        let mut frame = v4_header(Ipv4Addr::LOCALHOST, 1234, Ipv4Addr::LOCALHOST, 80, b"");
        frame[14..16].copy_from_slice(&((MAX_HEADER_BYTES + 1) as u16).to_be_bytes());
        assert!(parse_v2_header(&frame).is_err());
    }
}
