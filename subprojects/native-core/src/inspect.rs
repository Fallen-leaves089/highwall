use std::io::Read;

use flate2::read::{DeflateDecoder, GzDecoder, ZlibDecoder};

use crate::{config::LimitsConfig, http::HeaderField};

pub const RULE_ENCODING: &str = "HW-NATIVE-INSPECT-001";
pub const RULE_DECODE: &str = "HW-NATIVE-INSPECT-002";
pub const RULE_LIMIT: &str = "HW-NATIVE-INSPECT-003";
pub const RULE_GRPC_FRAME: &str = "HW-NATIVE-GRPC-002";
pub const RULE_GRPC_ENCODING: &str = "HW-NATIVE-GRPC-003";

#[derive(Debug, Clone)]
pub struct InspectFailure {
    pub rule: &'static str,
    pub status: u16,
    pub detail: String,
}

impl InspectFailure {
    fn new(rule: &'static str, status: u16, detail: impl Into<String>) -> Self {
        Self {
            rule,
            status,
            detail: detail.into(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct InspectedBody {
    pub blobs: Vec<Vec<u8>>,
    pub grpc_messages: usize,
    pub compressed: bool,
}

pub fn inspect_body(
    headers: &[HeaderField],
    body: &[u8],
    is_grpc: bool,
    limits: &LimitsConfig,
    compressed_transfer: bool,
) -> Result<InspectedBody, InspectFailure> {
    if body.len() > limits.max_inspect_decoded_bytes {
        return Err(InspectFailure::new(
            RULE_LIMIT,
            413,
            "body exceeds the bounded inspection budget",
        ));
    }
    let decoded = decode_transfer(
        headers,
        body,
        limits.max_inspect_decoded_bytes,
        compressed_transfer,
    )?;
    if is_grpc {
        let messages = decode_grpc(headers, &decoded, limits)?;
        return Ok(InspectedBody {
            grpc_messages: messages.len(),
            blobs: messages,
            compressed: decoded.len() != body.len() || grpc_uses_compression(headers),
        });
    }
    Ok(InspectedBody {
        blobs: vec![decoded.clone()],
        grpc_messages: 0,
        compressed: decoded.len() != body.len(),
    })
}

fn decode_transfer(
    headers: &[HeaderField],
    body: &[u8],
    max_decoded: usize,
    compressed_transfer: bool,
) -> Result<Vec<u8>, InspectFailure> {
    let encodings = header_values(headers, "content-encoding")
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>();
    if encodings.len() > 3 {
        return Err(InspectFailure::new(
            RULE_ENCODING,
            415,
            "too many nested content encodings",
        ));
    }
    if encodings.is_empty() || encodings.iter().all(|value| value == "identity") {
        if body.len() > max_decoded {
            return Err(InspectFailure::new(
                RULE_LIMIT,
                413,
                "decoded body exceeds the inspection limit",
            ));
        }
        return Ok(body.to_vec());
    }
    if !compressed_transfer {
        return Err(InspectFailure::new(
            RULE_ENCODING,
            415,
            "compressed content inspection is disabled",
        ));
    }
    let mut current = body.to_vec();
    for encoding in encodings.iter().rev() {
        if encoding == "identity" {
            continue;
        }
        current = decode_one(encoding, &current, max_decoded)?;
    }
    Ok(current)
}

fn decode_one(encoding: &str, input: &[u8], max_decoded: usize) -> Result<Vec<u8>, InspectFailure> {
    let mut output = Vec::new();
    match encoding {
        "gzip" | "x-gzip" => {
            let mut decoder = GzDecoder::new(input).take(max_decoded.saturating_add(1) as u64);
            decoder.read_to_end(&mut output).map_err(|error| {
                InspectFailure::new(RULE_DECODE, 400, format!("invalid gzip body: {error}"))
            })?;
        }
        "deflate" => {
            let mut decoder = ZlibDecoder::new(input).take(max_decoded.saturating_add(1) as u64);
            if decoder.read_to_end(&mut output).is_err() || output.len() > max_decoded {
                output.clear();
                let mut raw = DeflateDecoder::new(input).take(max_decoded.saturating_add(1) as u64);
                raw.read_to_end(&mut output).map_err(|error| {
                    InspectFailure::new(RULE_DECODE, 400, format!("invalid deflate body: {error}"))
                })?;
            }
        }
        other => {
            return Err(InspectFailure::new(
                RULE_ENCODING,
                415,
                format!("unsupported content encoding: {other}"),
            ));
        }
    }
    if output.len() > max_decoded {
        return Err(InspectFailure::new(
            RULE_LIMIT,
            413,
            "decompressed body exceeds the inspection limit",
        ));
    }
    Ok(output)
}

fn decode_grpc(
    headers: &[HeaderField],
    body: &[u8],
    limits: &LimitsConfig,
) -> Result<Vec<Vec<u8>>, InspectFailure> {
    if body.len() > limits.max_grpc_total_bytes {
        return Err(InspectFailure::new(
            RULE_LIMIT,
            413,
            "gRPC body exceeds the configured total budget",
        ));
    }
    let grpc_encoding =
        single_header(headers, "grpc-encoding").map(|value| value.trim().to_ascii_lowercase());
    if let Some(encoding) = &grpc_encoding {
        if !matches!(encoding.as_str(), "identity" | "gzip" | "deflate") {
            return Err(InspectFailure::new(
                RULE_GRPC_ENCODING,
                415,
                format!("unsupported grpc-encoding: {encoding}"),
            ));
        }
    }
    let mut messages = Vec::new();
    let mut offset = 0_usize;
    while offset < body.len() {
        if body.len().saturating_sub(offset) < 5 {
            return Err(InspectFailure::new(
                RULE_GRPC_FRAME,
                400,
                "truncated gRPC message prefix",
            ));
        }
        let compressed = body[offset];
        if compressed > 1 {
            return Err(InspectFailure::new(
                RULE_GRPC_FRAME,
                400,
                "invalid gRPC compressed flag",
            ));
        }
        let length = u32::from_be_bytes(
            body[offset + 1..offset + 5]
                .try_into()
                .expect("gRPC length prefix"),
        ) as usize;
        offset += 5;
        let end = offset.checked_add(length).ok_or_else(|| {
            InspectFailure::new(RULE_GRPC_FRAME, 400, "gRPC message length overflow")
        })?;
        if end > body.len() {
            return Err(InspectFailure::new(
                RULE_GRPC_FRAME,
                400,
                "truncated gRPC message body",
            ));
        }
        if messages.len() >= limits.max_grpc_messages {
            return Err(InspectFailure::new(
                RULE_LIMIT,
                413,
                "gRPC message count exceeds the configured budget",
            ));
        }
        let message = &body[offset..end];
        let decoded = if compressed == 1 {
            let Some(encoding) = grpc_encoding.as_deref() else {
                return Err(InspectFailure::new(
                    RULE_GRPC_ENCODING,
                    400,
                    "compressed gRPC message has no grpc-encoding",
                ));
            };
            if encoding == "identity" {
                return Err(InspectFailure::new(
                    RULE_GRPC_ENCODING,
                    400,
                    "gRPC message is marked compressed but grpc-encoding is identity",
                ));
            }
            decode_one(
                encoding,
                message,
                limits
                    .max_grpc_message_bytes
                    .min(limits.max_inspect_decoded_bytes),
            )?
        } else {
            if message.len() > limits.max_grpc_message_bytes {
                return Err(InspectFailure::new(
                    RULE_LIMIT,
                    413,
                    "gRPC message exceeds the configured budget",
                ));
            }
            message.to_vec()
        };
        if decoded.len() > limits.max_grpc_message_bytes {
            return Err(InspectFailure::new(
                RULE_LIMIT,
                413,
                "decoded gRPC message exceeds the configured budget",
            ));
        }
        messages.push(decoded);
        offset = end;
    }
    Ok(messages)
}

fn grpc_uses_compression(headers: &[HeaderField]) -> bool {
    single_header(headers, "grpc-encoding")
        .is_some_and(|value| !value.trim().eq_ignore_ascii_case("identity"))
}

fn header_values<'a>(
    headers: &'a [HeaderField],
    name: &'a str,
) -> impl Iterator<Item = &'a str> + 'a {
    headers
        .iter()
        .filter(move |header| header.name.eq_ignore_ascii_case(name))
        .map(|header| header.value.as_str())
}

fn single_header<'a>(headers: &'a [HeaderField], name: &'a str) -> Option<&'a str> {
    let mut values = header_values(headers, name);
    let first = values.next()?;
    if values.next().is_some() {
        return None;
    }
    Some(first)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn header(name: &str, value: &str) -> HeaderField {
        HeaderField {
            name: name.to_string(),
            value: value.to_string(),
        }
    }

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn gzip_body_is_decoded_with_a_hard_limit() {
        let limits = LimitsConfig::default();
        let encoded = gzip(b"hello highwall");
        let inspected = inspect_body(
            &[header("content-encoding", "gzip")],
            &encoded,
            false,
            &limits,
            true,
        )
        .unwrap();
        assert_eq!(inspected.blobs[0], b"hello highwall");
        let mut tight = limits;
        tight.max_inspect_decoded_bytes = 4;
        assert!(inspect_body(
            &[header("content-encoding", "gzip")],
            &encoded,
            false,
            &tight,
            true,
        )
        .is_err());
    }

    #[test]
    fn grpc_frames_are_parsed_and_bounded() {
        let limits = LimitsConfig::default();
        let mut body = Vec::new();
        body.extend_from_slice(&[0, 0, 0, 0, 3]);
        body.extend_from_slice(b"abc");
        let inspected = inspect_body(
            &[header("content-type", "application/grpc")],
            &body,
            true,
            &limits,
            true,
        )
        .unwrap();
        assert_eq!(inspected.grpc_messages, 1);
        assert_eq!(inspected.blobs[0], b"abc");
        assert!(inspect_body(
            &[header("content-type", "application/grpc")],
            &[0, 0, 0, 0, 9, b'a'],
            true,
            &limits,
            true,
        )
        .is_err());
    }

    #[test]
    fn unsupported_encodings_fail_closed() {
        let limits = LimitsConfig::default();
        let error = inspect_body(
            &[header("content-encoding", "br")],
            b"not really brotli",
            false,
            &limits,
            true,
        )
        .unwrap_err();
        assert_eq!(error.rule, RULE_ENCODING);
    }
}
