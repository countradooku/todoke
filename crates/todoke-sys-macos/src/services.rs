//! "Send with todoke" in Finder's Quick Actions and in every app's
//! Services menu: the bundle's `Info.plist` declares the services
//! (`NSServices`: `sendFiles` for files and folders, `sendText` for selected
//! text), and this provider answers them in the running app. macOS starts
//! the app first when it is not running.
//!
//! The only unsafe code is the Objective-C class definition and its
//! registration below; each block says why it is sound.

#![allow(
    unsafe_code,
    reason = "an Objective-C class for AppKit's services; each block is justified"
)]

use std::path::PathBuf;

use objc2::rc::Retained;
use objc2::runtime::AnyObject;
use objc2::{DefinedClass as _, MainThreadMarker, MainThreadOnly, define_class, msg_send};
use objc2_app_kit::{
    NSApplication, NSPasteboard, NSPasteboardTypeFileURL, NSPasteboardTypeString,
    NSUpdateDynamicServices,
};
use objc2_foundation::{NSObject, NSObjectProtocol, NSString, NSURL};

/// What a service was asked to send.
#[derive(Debug, PartialEq, Eq)]
pub enum Service {
    /// Files and folders (Finder's selection).
    Files(Vec<PathBuf>),
    /// Selected text.
    Text(String),
}

/// What receives the services' requests.
type Handler = Box<dyn Fn(Service)>;

/// The provider's state.
struct Ivars {
    on: Handler,
}

define_class!(
    // SAFETY: NSObject has no subclassing requirements; the class has no
    // Drop, and its ivars are plain Rust values. AppKit calls services on
    // the main thread only.
    #[unsafe(super(NSObject))]
    #[thread_kind = MainThreadOnly]
    #[name = "TodokeServicesProvider"]
    #[ivars = Ivars]
    struct Provider;

    unsafe impl NSObjectProtocol for Provider {}

    impl Provider {
        // SAFETY: the signature AppKit calls services with:
        // `- (void)sendFiles:(NSPasteboard *)pboard userData:(NSString *)data
        // error:(NSString **)error`. The error is left unset.
        #[unsafe(method(sendFiles:userData:error:))]
        fn send_files(
            &self,
            pasteboard: &NSPasteboard,
            _data: Option<&NSString>,
            _error: *mut *mut NSString,
        ) {
            let files = files(pasteboard);
            if !files.is_empty() {
                (self.ivars().on)(Service::Files(files));
            }
        }

        // SAFETY: as above.
        #[unsafe(method(sendText:userData:error:))]
        fn send_text(
            &self,
            pasteboard: &NSPasteboard,
            _data: Option<&NSString>,
            _error: *mut *mut NSString,
        ) {
            // SAFETY: an immutable string constant AppKit exports.
            let kind = unsafe { NSPasteboardTypeString };
            if let Some(text) = pasteboard.stringForType(kind) {
                let text = text.to_string();
                if !text.is_empty() {
                    (self.ivars().on)(Service::Text(text));
                }
            }
        }
    }
);

/// The file paths on `pasteboard`.
fn files(pasteboard: &NSPasteboard) -> Vec<PathBuf> {
    // SAFETY: an immutable string constant AppKit exports.
    let kind = unsafe { NSPasteboardTypeFileURL };
    let Some(items) = pasteboard.pasteboardItems() else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|item| item.stringForType(kind))
        .filter_map(|url| NSURL::URLWithString(&url))
        .filter(|url| url.isFileURL())
        .filter_map(|url| url.path())
        .map(|path| PathBuf::from(path.to_string()))
        .collect()
}

/// The registered provider; it stays registered while this lives.
pub struct Services(
    #[expect(dead_code, reason = "held: AppKit keeps a weak reference")] Retained<Provider>,
);

impl core::fmt::Debug for Services {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Services")
    }
}

/// Answers the services in `Info.plist` with `on` (on the main thread).
/// Call once the app runs.
#[must_use]
pub fn provide(mtm: MainThreadMarker, on: impl Fn(Service) + 'static) -> Services {
    let this = Provider::alloc(mtm).set_ivars(Ivars { on: Box::new(on) });
    // SAFETY: NSObject's designated initialiser, on a freshly allocated
    // object whose ivars are set.
    let provider: Retained<Provider> = unsafe { msg_send![super(this), init] };
    let application = NSApplication::sharedApplication(mtm);
    let object: &AnyObject = &provider;
    // SAFETY: the provider implements the methods `Info.plist` names, with
    // the signatures AppKit calls; `Services` keeps it alive.
    unsafe { application.setServicesProvider(Some(object)) };
    NSUpdateDynamicServices();
    Services(provider)
}
