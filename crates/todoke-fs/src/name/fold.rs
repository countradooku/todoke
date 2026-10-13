//! The collision key: two names that a case-insensitive or
//! normalization-insensitive filesystem could treat as the same entry get
//! the same key.

use unicode_normalization::UnicodeNormalization as _;

/// A conservative superset of the equivalences that NTFS (upcase table),
/// APFS and HFS+ (case-insensitive variants, normalization-insensitive),
/// exFAT, and FAT apply: canonical decomposition (NFD), then each
/// character mapped to upper case and back to lower case twice (so that
/// "ß", "ẞ", "SS", and "ss" meet, as do "ı", "I", and "i", and the Greek
/// sigmas), then NFD again.
pub(crate) fn collision_key(name: &str) -> String {
    let round = |text: &str| -> String {
        let mut out = String::with_capacity(text.len());
        for c in text.chars() {
            for upper in c.to_uppercase() {
                out.extend(upper.to_lowercase());
            }
        }
        out
    };
    let decomposed: String = name.nfd().collect();
    round(&round(&decomposed)).nfd().collect()
}

#[cfg(test)]
mod tests {
    use super::collision_key;

    #[test]
    fn equivalent_names_share_a_key() {
        for (a, b) in [
            ("Report.PDF", "report.pdf"),
            ("Straße", "STRASSE"),
            ("ẞ", "ss"),
            ("ı", "I"),
            ("ı", "i"),
            ("İ", "i\u{0307}"),
            ("Σ", "ς"),
            ("σ", "ς"),
            ("é", "e\u{0301}"),
            ("Å", "\u{212B}"),
            ("K", "\u{212A}"),
            ("ﬀ", "FF"),
        ] {
            assert_eq!(collision_key(a), collision_key(b), "{a} / {b}");
        }
        for (a, b) in [("a", "b"), ("e", "é"), ("1", "١")] {
            assert_ne!(collision_key(a), collision_key(b), "{a} / {b}");
        }
    }
}
