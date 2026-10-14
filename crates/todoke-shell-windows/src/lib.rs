//! "Send with todoke" at the top of File Explorer's context menu (Windows
//! 11): an `IExplorerCommand` COM server the MSIX package declares
//! (`desktop4:FileExplorerContextMenus`, CLSID [`CLSID`]), run by
//! Explorer's COM surrogate.
//!
//! Invoked, it starts `todoke-desktop.exe --send-stdin` from its own
//! directory and writes the selected paths to it (UTF-8, each ended by a
//! NUL): no command-line length limit, no temporary file. The app hands
//! them to its running window, which asks who to send them to. The
//! command decides nothing and reads no file.
//!
//! # Trust boundary
//!
//! COM calls from Explorer: pointers, reference counts, and strings the
//! shell allocates. The only unsafe code is that bridge; each block says
//! why it is sound.

#![deny(unsafe_op_in_unsafe_fn)]

/// The command's class ID (`AppxManifest.xml` names it).
pub const CLSID_TEXT: &str = "346A1ED9-A65C-4480-B1DE-A792C18293C8";

#[cfg(windows)]
mod com;

#[cfg(windows)]
pub use com::{CLSID, paths_message};

#[cfg(test)]
mod tests {
    #[test]
    fn the_clsid_is_the_manifests() {
        assert_eq!(super::CLSID_TEXT.len(), 36);
        #[cfg(windows)]
        assert_eq!(format!("{:?}", super::CLSID), super::CLSID_TEXT);
    }
}
