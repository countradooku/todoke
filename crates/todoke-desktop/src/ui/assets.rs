//! The icons the window draws: the component library's own set, and the
//! few Lucide icons beyond it that the pages use, embedded in the binary
//! (nothing is loaded at run time).

use std::borrow::Cow;

use gpui_kit::{AssetSource, Result, SharedString};

gpui_kit::assets::icon_assets!(
    Extra,
    [
        ArrowDownToLine,
        ArrowUpFromLine,
        Receipt,
        ShieldCheck,
        Upload,
    ]
);

/// The app's asset source.
#[derive(Clone, Copy, Debug, Default)]
pub struct Assets;

impl AssetSource for Assets {
    fn load(&self, path: &str) -> Result<Option<Cow<'static, [u8]>>> {
        if let Ok(Some(found)) = gpui_kit::assets::Assets.load(path) {
            return Ok(Some(found));
        }
        Extra.load(path)
    }

    fn list(&self, path: &str) -> Result<Vec<SharedString>> {
        let mut all = gpui_kit::assets::Assets.list(path)?;
        all.extend(Extra.list(path)?);
        Ok(all)
    }
}

#[cfg(test)]
mod tests {
    use gpui_kit::assets::IconName;

    use super::*;

    /// Every icon the pages draw is embedded.
    #[test]
    fn every_icon_used_is_embedded() {
        for icon in [
            IconName::ArrowDownToLine,
            IconName::ArrowUpFromLine,
            IconName::Copy,
            IconName::File,
            IconName::Folder,
            IconName::Receipt,
            IconName::ShieldCheck,
            IconName::Upload,
        ] {
            let path = icon.path();
            assert!(
                matches!(Assets.load(&path), Ok(Some(_))),
                "{path} is not embedded"
            );
        }
    }
}
