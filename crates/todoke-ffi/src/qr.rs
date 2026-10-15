//! A QR pairing offer: drawn here as modules, so the offer's secret text
//! crosses the boundary only when an app asks for it (to share as text).

#![allow(
    clippy::needless_pass_by_value,
    clippy::must_use_candidate,
    reason = "exported to foreign callers: arguments arrive owned, and must_use means nothing there"
)]

use boltffi::export;
use zeroize::Zeroizing;

/// A shown QR pairing offer. It works once and expires; stop it with
/// `Core::stop_pairing`.
pub struct QrOffer {
    text: Zeroizing<String>,
    width: u32,
    modules: Vec<u8>,
    expires_at: u64,
}

impl QrOffer {
    /// The offer for `text`, drawn as a QR code (low error correction, as
    /// the desktop app draws it).
    pub(crate) fn new(text: String, expires_at: u64) -> Option<Self> {
        let text = Zeroizing::new(text);
        let code =
            qrcode::QrCode::with_error_correction_level(text.as_str(), qrcode::EcLevel::L).ok()?;
        let width = u32::try_from(code.width()).ok()?;
        let modules = code
            .to_colors()
            .into_iter()
            .map(|color| u8::from(color == qrcode::Color::Dark))
            .collect();
        Some(Self {
            text,
            width,
            modules,
            expires_at,
        })
    }
}

impl core::fmt::Debug for QrOffer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("QrOffer")
            .field("width", &self.width)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

#[export]
impl QrOffer {
    /// Modules per side.
    pub fn width(&self) -> u32 {
        self.width
    }

    /// The modules, row by row: 1 dark, 0 light (`width` × `width`). Draw
    /// them black on white with a quiet zone of four modules.
    pub fn modules(&self) -> Vec<u8> {
        self.modules.clone()
    }

    /// When the offer expires (Unix seconds).
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// The offer as text (`TODOKE:…`), to share by other means than the
    /// camera. It is a pairing secret until it expires: never log it.
    pub fn text(&self) -> String {
        self.text.as_str().to_owned()
    }
}
