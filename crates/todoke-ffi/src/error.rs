//! Errors as the boundary carries them: a kind to act on and a message for
//! people (never a secret).

use core::fmt;

use boltffi::error;
use todoke_core::api::ErrorCode;

/// Why something failed.
#[error]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TodokeError {
    /// Sessions are disabled in this build (PROTOCOL §16), or the feature
    /// is (Wi-Fi links, not built yet).
    Disabled {
        /// For people.
        message: String,
    },
    /// Not available on this platform (the core does not run in a browser
    /// yet).
    Unsupported {
        /// For people.
        message: String,
    },
    /// A malformed request: an ID, a path, a code.
    Invalid {
        /// For people.
        message: String,
    },
    /// The request names more than one thing.
    Ambiguous {
        /// For people.
        message: String,
    },
    /// The peer cannot be reached now.
    Unreachable {
        /// For people.
        message: String,
    },
    /// Not possible in the current state.
    State {
        /// For people.
        message: String,
    },
    /// Pairing failed.
    Pairing {
        /// For people.
        message: String,
    },
    /// A file to send could not be read or changed while offered.
    Source {
        /// For people.
        message: String,
    },
    /// The platform's key store refused or failed.
    KeyStore {
        /// For people.
        message: String,
    },
    /// The profile could not be opened.
    Profile {
        /// For people.
        message: String,
    },
    /// Anything else.
    Internal {
        /// For people.
        message: String,
    },
}

impl TodokeError {
    /// The error the core answered with; its message is escaped (it may
    /// name a local path).
    #[must_use]
    pub fn from_core(code: ErrorCode, message: &str) -> Self {
        let message = todoke_core::api::escape(message);
        match code {
            ErrorCode::Invalid => Self::Invalid { message },
            ErrorCode::Ambiguous => Self::Ambiguous { message },
            ErrorCode::Unreachable => Self::Unreachable { message },
            ErrorCode::State => Self::State { message },
            ErrorCode::Pairing => Self::Pairing { message },
            ErrorCode::Source => Self::Source { message },
            ErrorCode::Disabled => Self::Disabled { message },
            ErrorCode::Internal => Self::Internal { message },
        }
    }

    /// An answer of the wrong kind (a core bug).
    pub(crate) fn unexpected() -> Self {
        Self::Internal {
            message: "the core answered with something unexpected".to_owned(),
        }
    }

    /// The message for people.
    #[must_use]
    pub fn message(&self) -> &str {
        match self {
            Self::Disabled { message }
            | Self::Unsupported { message }
            | Self::Invalid { message }
            | Self::Ambiguous { message }
            | Self::Unreachable { message }
            | Self::State { message }
            | Self::Pairing { message }
            | Self::Source { message }
            | Self::KeyStore { message }
            | Self::Profile { message }
            | Self::Internal { message } => message,
        }
    }
}

impl fmt::Display for TodokeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for TodokeError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every core error keeps its kind, and its message crosses escaped:
    /// no control or bidi character, as the core's own `escape` writes it.
    #[test]
    fn core_errors_keep_their_kind_and_are_escaped() {
        let raw = "C:\\in\u{202e}fdp.exe\n\u{200b}\u{7}done";
        let escaped = todoke_core::api::escape(raw);
        assert_eq!(escaped, "C:\\\\in\\u{202e}fdp.exe\\u{a}\\u{200b}\\u{7}done");
        let cases = [
            (
                ErrorCode::Invalid,
                TodokeError::Invalid {
                    message: escaped.clone(),
                },
            ),
            (
                ErrorCode::Ambiguous,
                TodokeError::Ambiguous {
                    message: escaped.clone(),
                },
            ),
            (
                ErrorCode::Unreachable,
                TodokeError::Unreachable {
                    message: escaped.clone(),
                },
            ),
            (
                ErrorCode::State,
                TodokeError::State {
                    message: escaped.clone(),
                },
            ),
            (
                ErrorCode::Pairing,
                TodokeError::Pairing {
                    message: escaped.clone(),
                },
            ),
            (
                ErrorCode::Source,
                TodokeError::Source {
                    message: escaped.clone(),
                },
            ),
            (
                ErrorCode::Disabled,
                TodokeError::Disabled {
                    message: escaped.clone(),
                },
            ),
            (
                ErrorCode::Internal,
                TodokeError::Internal {
                    message: escaped.clone(),
                },
            ),
        ];
        for (code, expected) in cases {
            let error = TodokeError::from_core(code, raw);
            assert_eq!(error, expected);
            assert!(!error.message().chars().any(char::is_control));
            assert!(!error.message().contains('\u{202e}'));
        }
    }

    /// What an app prints is the message alone.
    #[test]
    fn display_is_the_message() {
        let errors = [
            TodokeError::Unsupported {
                message: "a".into(),
            },
            TodokeError::KeyStore {
                message: "b".into(),
            },
            TodokeError::Profile {
                message: "c".into(),
            },
            TodokeError::unexpected(),
        ];
        for error in errors {
            assert_eq!(error.to_string(), error.message());
        }
        assert_eq!(
            TodokeError::unexpected().message(),
            "the core answered with something unexpected"
        );
    }
}
