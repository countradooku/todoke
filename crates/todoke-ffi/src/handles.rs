//! Handles to a contact and to a transfer: what an app acts on. They hold
//! public IDs and the core they belong to, never a key.

#![allow(
    clippy::needless_pass_by_value,
    clippy::must_use_candidate,
    reason = "exported to foreign callers: arguments arrive owned, and must_use means nothing there"
)]

use std::sync::Arc;

use boltffi::export;
use todoke_core::api::{Request, Response};

use crate::engine::Shared;
use crate::error::TodokeError;
use crate::types::{Transfer, name_of};

/// A paired device.
pub struct ContactHandle {
    pub(crate) shared: Arc<Shared>,
    pub(crate) device: String,
}

#[export]
impl ContactHandle {
    /// Its fingerprint (hex).
    pub fn device(&self) -> String {
        self.device.clone()
    }

    /// What to call it.
    pub fn name(&self) -> String {
        name_of(&self.device)
    }

    /// Offers files and folders (absolute paths the app may read) to this
    /// contact; folders go with their contents. Blocks while the core hashes
    /// them: call it off the UI thread.
    ///
    /// # Errors
    ///
    /// The core's answer: a path that cannot be read, the contact out of
    /// reach.
    pub fn send(&self, paths: Vec<String>) -> Result<TransferHandle, TodokeError> {
        if paths.is_empty() {
            return Err(TodokeError::Invalid {
                message: "nothing to send".to_owned(),
            });
        }
        if paths
            .iter()
            .any(|path| !std::path::Path::new(path).is_absolute())
        {
            return Err(TodokeError::Invalid {
                message: "paths to send must be absolute".to_owned(),
            });
        }
        let request = Request::Send {
            contact: self.device.clone(),
            paths: paths.into_iter().map(Into::into).collect(),
        };
        self.offered(self.shared.request(request)?)
    }

    /// Offers files the app opened for the user (Android: documents from
    /// the Storage Access Framework) to this contact, each under its name
    /// in `names` (what the user saw; checked like a path's last part).
    /// `fds` are their descriptors, which this call takes over: detach them
    /// (`ParcelFileDescriptor.detachFd()`) and never close them afterwards,
    /// whatever this returns. Only regular files that can be read from the
    /// start again are sent. Blocks while the core hashes them: call it off
    /// the UI thread.
    ///
    /// # Errors
    ///
    /// [`TodokeError::Invalid`] for no files, `names` and `fds` of
    /// different lengths, or a descriptor that is not open or is given
    /// twice; [`TodokeError::Unsupported`] where there are no descriptors
    /// (Windows, the web); otherwise the core's answer.
    pub fn send_files(
        &self,
        names: Vec<String>,
        fds: Vec<i32>,
    ) -> Result<TransferHandle, TodokeError> {
        #[cfg(unix)]
        {
            // Take every descriptor first, so none leaks whatever follows.
            let files = crate::fds::adopt(&fds)?;
            if files.is_empty() || names.len() != files.len() {
                return Err(TodokeError::Invalid {
                    message: "give one name for each file to send".to_owned(),
                });
            }
            self.offered(self.shared.send_files(self.device.clone(), names, files)?)
        }
        #[cfg(not(unix))]
        {
            let _ = (names, fds);
            Err(TodokeError::Unsupported {
                message: "open files can only be handed over on Android and Unix".to_owned(),
            })
        }
    }
}

impl ContactHandle {
    fn offered(&self, response: Response) -> Result<TransferHandle, TodokeError> {
        match response {
            Response::Offered { transfer, .. } => Ok(TransferHandle {
                shared: Arc::clone(&self.shared),
                id: transfer,
            }),
            _ => Err(TodokeError::unexpected()),
        }
    }
}

/// A transfer, in either direction.
pub struct TransferHandle {
    pub(crate) shared: Arc<Shared>,
    pub(crate) id: String,
}

#[export]
impl TransferHandle {
    /// Its ID (hex).
    pub fn id(&self) -> String {
        self.id.clone()
    }

    /// Where it is now.
    ///
    /// # Errors
    ///
    /// [`TodokeError::State`] when the core no longer lists it (finished
    /// transfers are in the history).
    pub fn info(&self) -> Result<Transfer, TodokeError> {
        match self.shared.request(Request::Transfers)? {
            Response::Transfers(transfers) => transfers
                .into_iter()
                .find(|transfer| transfer.transfer == self.id)
                .map(Transfer::from)
                .ok_or_else(|| TodokeError::State {
                    message: "no such transfer in progress".to_owned(),
                }),
            _ => Err(TodokeError::unexpected()),
        }
    }

    /// Accepts the offer (this user's decision, §7.2): every file, or the
    /// entries in `files` (their IDs), when it is not empty.
    ///
    /// # Errors
    ///
    /// The core's answer: no such offer, an expired one.
    pub fn accept(&self, files: Vec<u32>) -> Result<(), TodokeError> {
        let files = (!files.is_empty()).then_some(files);
        self.shared.done(Request::Accept {
            transfer: self.id.clone(),
            files,
        })
    }

    /// Declines the offer.
    ///
    /// # Errors
    ///
    /// The core's answer.
    pub fn decline(&self) -> Result<(), TodokeError> {
        self.shared.done(Request::Decline {
            transfer: self.id.clone(),
        })
    }

    /// Cancels the transfer.
    ///
    /// # Errors
    ///
    /// The core's answer.
    pub fn cancel(&self) -> Result<(), TodokeError> {
        self.shared.done(Request::Cancel {
            transfer: self.id.clone(),
        })
    }
}

/// Whether `id` looks like a hex ID (before it reaches the core).
pub(crate) fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 128 && id.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::valid_id;

    /// An ID is 1 to 128 hex digits, either case; anything else is refused
    /// before it reaches the core (which checks the exact length).
    #[test]
    fn ids_are_short_hex() {
        for id in [
            "0",
            "abc",
            "ABCDEF",
            "aBcD09",
            &"f".repeat(64),
            &"0".repeat(128),
        ] {
            assert!(valid_id(id), "{id}");
        }
        for id in [
            "",
            &"0".repeat(129),
            "0x12",
            "12 34",
            " 12",
            "12\n",
            "g0",
            "١٢",
            "ａｂ",
            "12\0",
        ] {
            assert!(!valid_id(id), "{id:?}");
        }
    }
}
