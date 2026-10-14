//! The command-line adapter for the public todoke core.
//!
//! # Trust boundary
//!
//! Arguments, terminal input, and displayed peer metadata are untrusted.
//! The CLI requests core operations through the daemon and duplicates no
//! security policy. Text a peer chose (file and folder names) is escaped
//! before it reaches the terminal ([`escape`]): control characters,
//! bidirectional overrides, and invisible formatting characters could
//! otherwise rewrite what the user sees.

#![forbid(unsafe_code)]

use core::fmt::Write as _;

use todoke_core::api::{ContactInfo, EntryInfo, Event, OfferInfo, StatusInfo, TransferInfo};

/// Escapes untrusted text for a terminal: every control character and
/// every character that hides or reorders text ([`todoke_fs::is_invisible`]:
/// bidi controls, tags, fillers, joiners, variation selectors, and the
/// rest of the default-ignorable code points) becomes `\u{…}`; a backslash
/// becomes `\\`.
#[must_use]
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c == '\\' {
            out.push_str("\\\\");
        } else if c.is_control() || todoke_fs::is_invisible(c) {
            let _ = write!(out, "\\u{{{:x}}}", u32::from(c));
        } else {
            out.push(c);
        }
    }
    out
}

/// `value` as one line of JSON for a terminal or a pipe: JSON escapes
/// only U+0000–U+001F, so every other control character and every
/// character [`escape`] escapes is written as a `\u` escape too. The JSON
/// means the same; a terminal shows nothing a peer smuggled in.
#[must_use]
pub fn json(value: &impl serde::Serialize) -> String {
    let text = serde_json::to_string(value).unwrap_or_default();
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        // Outside strings JSON is ASCII, so these occur only in strings.
        if c.is_control() || todoke_fs::is_invisible(c) {
            let mut units = [0_u16; 2];
            for unit in c.encode_utf16(&mut units) {
                let _ = write!(out, "\\u{unit:04x}");
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Bytes in human units.
#[must_use]
pub fn bytes(count: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = count;
    let mut unit = 0;
    let mut remainder = 0;
    while value >= 1024 && unit < UNITS.len() - 1 {
        remainder = value % 1024;
        value /= 1024;
        unit += 1;
    }
    if unit == 0 {
        format!("{value} B")
    } else {
        format!("{value}.{} {}", remainder * 10 / 1024, UNITS[unit])
    }
}

/// The first 12 hex digits of a device or transfer: enough to name it.
#[must_use]
pub fn short(hex: &str) -> &str {
    hex.get(..12).unwrap_or(hex)
}

/// A status, for people.
#[must_use]
pub fn status(status: &StatusInfo) -> String {
    format!(
        "device    {}\nsessions  {}\nlistening {}\ncontacts  {}\nopen      {}\npairing   {}\n",
        status.device,
        if status.sessions_enabled {
            "enabled"
        } else {
            "disabled in this build"
        },
        status
            .port
            .map_or_else(|| "no".to_owned(), |port| format!("port {port}")),
        status.contacts,
        status.sessions,
        if status.pairing { "offer shown" } else { "no" },
    )
}

/// Contacts, for people.
#[must_use]
pub fn contacts(contacts: &[ContactInfo]) -> String {
    if contacts.is_empty() {
        return "no contacts yet: pair with `todoke pair show` and `todoke pair scan`\n".to_owned();
    }
    let mut out = String::new();
    for contact in contacts {
        let _ = writeln!(
            out,
            "{}  {}{}{}",
            short(&contact.device),
            if contact.available {
                "available"
            } else {
                "blocked"
            },
            if contact.nearby { ", nearby" } else { "" },
            if contact.connected { ", connected" } else { "" },
        );
    }
    out
}

/// Transfers, for people.
#[must_use]
pub fn transfers(transfers: &[TransferInfo]) -> String {
    if transfers.is_empty() {
        return "no transfers\n".to_owned();
    }
    let mut out = String::new();
    for transfer in transfers {
        let _ = writeln!(
            out,
            "{}  {:?}  {}  {}/{}  peer {}",
            short(&transfer.transfer),
            transfer.way,
            transfer.state.as_str(),
            bytes(transfer.bytes_done),
            bytes(transfer.bytes_total),
            short(&transfer.peer),
        );
    }
    out
}

/// An offer's entries as a tree, names escaped.
#[must_use]
pub fn entries(entries: &[EntryInfo]) -> String {
    let mut out = String::new();
    for entry in entries {
        let depth = depth(entries, entry);
        let _ = writeln!(
            out,
            "  {:>4}  {}{}{}",
            entry.id,
            "  ".repeat(depth),
            escape(&entry.name),
            if entry.directory {
                "/".to_owned()
            } else {
                format!("  ({})", bytes(entry.size))
            },
        );
    }
    out
}

fn depth(entries: &[EntryInfo], entry: &EntryInfo) -> usize {
    let mut depth = 0;
    let mut parent = entry.parent;
    // Bounded: a manifest has at most 64 levels (§13); stop on a cycle.
    while parent != 0 && depth < 64 {
        depth += 1;
        parent = entries
            .iter()
            .find(|candidate| candidate.id == parent)
            .map_or(0, |candidate| candidate.parent);
    }
    depth
}

/// A received offer, for people (one line).
#[must_use]
pub fn offer_line(offer: &OfferInfo) -> String {
    format!(
        "offer {} from {}: {}{}",
        short(&offer.transfer),
        short(&offer.from),
        bytes(offer.total_bytes),
        if offer.resume.is_some() {
            " (resumes an earlier transfer)"
        } else {
            ""
        },
    )
}

/// An event, for people (one line, untrusted text escaped).
#[must_use]
pub fn event(event: &Event) -> String {
    match event {
        Event::Paired { contact } => format!("paired with {}", short(contact)),
        Event::OfferReceived(offer) => offer_line(offer),
        Event::Progress {
            transfer,
            done,
            total,
            bytes_per_second,
            ..
        } => format!(
            "{} {}/{} at {}/s",
            short(transfer),
            bytes(*done),
            bytes(*total),
            bytes(*bytes_per_second)
        ),
        Event::Completed { transfer } => format!("{} received", short(transfer)),
        Event::Delivered { transfer } => format!("{} delivered (signed receipt)", short(transfer)),
        Event::Missed { events } => {
            format!("{events} events were missed; offers and transfers are re-read")
        }
        Event::Ended {
            transfer,
            reason,
            message,
        } => format!(
            "{} {}: {}",
            short(transfer),
            reason.as_str(),
            escape(message)
        ),
    }
}

/// The QR code for pairing text, drawn with half-block characters.
///
/// # Errors
///
/// If the text is too long for a QR code.
#[cfg(not(target_family = "wasm"))]
pub fn qr(text: &str) -> Result<String, qrcode::types::QrError> {
    let code = qrcode::QrCode::with_error_correction_level(text, qrcode::EcLevel::L)?;
    Ok(code
        .render::<qrcode::render::unicode::Dense1x2>()
        .quiet_zone(true)
        .build())
}

#[cfg(all(test, not(target_family = "wasm")))]
mod tests;
