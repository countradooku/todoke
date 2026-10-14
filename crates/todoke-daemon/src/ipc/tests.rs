use todoke_core::api::Request;

use super::*;
use crate::endpoint::{Proof, check};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[tokio::test]
async fn messages_round_trip() -> TestResult {
    let (mut a, mut b) = tokio::io::duplex(1 << 16);
    let message = ClientMessage::Request {
        id: 7,
        request: Request::Status,
    };
    write_message(&mut a, &message, MAX_CLIENT_MESSAGE).await?;
    let read: Option<ClientMessage> = read_message(&mut b, MAX_CLIENT_MESSAGE).await?;
    assert!(matches!(
        read,
        Some(ClientMessage::Request {
            id: 7,
            request: Request::Status
        })
    ));
    drop(a);
    assert!(
        read_message::<_, ClientMessage>(&mut b, MAX_CLIENT_MESSAGE)
            .await?
            .is_none()
    );
    Ok(())
}

/// A length prefix over the bound is refused before anything is
/// allocated; malformed and unknown messages are refused.
#[tokio::test]
async fn oversized_and_malformed_messages_are_refused() -> TestResult {
    let framed = |body: &[u8]| {
        let mut bytes = u32::try_from(body.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes()
            .to_vec();
        bytes.extend_from_slice(body);
        bytes
    };
    for bytes in [
        u32::MAX.to_be_bytes().to_vec(),
        (u32::try_from(MAX_CLIENT_MESSAGE)? + 1)
            .to_be_bytes()
            .to_vec(),
        framed(b"{bad}"),
        framed(br#"{"type":"format_disk","x":1}"#),
        framed(br#"{"type":"subscribe","extra":true}"#),
        framed(br#"{"type":"request","body":{"id":1,"request":{"request":"status","x":2}}}"#),
        framed(br#"{"type":"request","body":{"id":1,"request":{"request":"status"},"x":2}}"#),
    ] {
        let (mut a, mut b) = tokio::io::duplex(1 << 16);
        tokio::io::AsyncWriteExt::write_all(&mut a, &bytes).await?;
        drop(a);
        let read = read_message::<_, ClientMessage>(&mut b, MAX_CLIENT_MESSAGE).await;
        assert_eq!(
            read.map(|_| ()).map_err(|error| error.kind()),
            Err(std::io::ErrorKind::InvalidData)
        );
    }
    // A truncated message is an error, not a clean end.
    let (mut a, mut b) = tokio::io::duplex(1 << 16);
    tokio::io::AsyncWriteExt::write_all(&mut a, &10_u32.to_be_bytes()).await?;
    tokio::io::AsyncWriteExt::write_all(&mut a, b"{\"ty").await?;
    drop(a);
    assert!(
        read_message::<_, ClientMessage>(&mut b, MAX_CLIENT_MESSAGE)
            .await
            .is_err()
    );
    Ok(())
}

#[test]
fn tokens_are_checked_exactly() {
    let token = Proof::Token(zeroize::Zeroizing::new("00ff".repeat(16)));
    assert!(check(&token, Some(&"00ff".repeat(16))));
    assert!(!check(&token, Some(&"00fe".repeat(16))));
    assert!(!check(&token, Some("00ff")));
    assert!(!check(&token, None));
    assert!(check(&Proof::PeerChecked, None));
    assert!(!check(&Proof::PeerChecked, Some("anything")));
}

#[test]
fn hello_tokens_never_reach_debug_output() {
    let hello = ClientMessage::Hello {
        token: Some("secret-token-value".into()),
    };
    assert!(!format!("{hello:?}").contains("secret-token-value"));
}
