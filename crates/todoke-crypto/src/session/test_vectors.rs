//! Readers for the committed public fixtures in `spec/test-vectors`.

use std::path::Path;

pub(crate) type Vector = serde_json::Value;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub(crate) fn load(name: &str) -> Result<Vector> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../spec/test-vectors")
        .join(name);
    Ok(serde_json::from_slice(&std::fs::read(path)?)?)
}

pub(crate) fn json_at<'a>(value: &'a Vector, pointer: &str) -> Result<&'a Vector> {
    value
        .pointer(pointer)
        .ok_or_else(|| format!("missing fixture field {pointer}").into())
}

pub(crate) fn hex_at(value: &Vector, pointer: &str) -> Result<Vec<u8>> {
    let text = json_at(value, pointer)?
        .as_str()
        .ok_or_else(|| format!("fixture field {pointer} is not a string"))?;
    Ok(hex::decode(text)?)
}

pub(crate) fn hex_array_at<const N: usize>(value: &Vector, pointer: &str) -> Result<[u8; N]> {
    let bytes = hex_at(value, pointer)?;
    <[u8; N]>::try_from(bytes.as_slice())
        .map_err(|_| format!("fixture field {pointer} has the wrong length").into())
}
