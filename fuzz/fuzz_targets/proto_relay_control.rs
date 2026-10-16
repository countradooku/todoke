//! Relay control records (PROTOCOL §10) on arbitrary bytes: an accepted
//! envelope or body must be canonical, re-encoding to exactly its input.
#![no_main]

use libfuzzer_sys::fuzz_target;
use todoke_proto::relay::Control;

fuzz_target!(|data: &[u8]| {
    if let Ok(Some((control, used))) = Control::split(data) {
        assert_eq!(control.encode().ok().as_deref(), data.get(..used));
    }
    if let Some((&kind, body)) = data.split_first()
        && let Ok(control) = Control::decode(kind, body)
    {
        let encoded = control.encode().ok();
        assert_eq!(
            encoded.as_deref().and_then(|bytes| bytes.get(2..)),
            Some(data)
        );
    }
});
