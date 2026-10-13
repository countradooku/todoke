//! Character classes the sanitizer acts on. Small, fixed tables of code
//! points: Unicode data (`Default_Ignorable_Code_Point`, bidi controls,
//! separators) copied as ranges, not computed.

/// What to do with one character of a peer-supplied name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Class {
    /// Shown as itself.
    Plain,
    /// Always replaced: bidi controls, C1 controls, line and paragraph
    /// separators, invisible fillers, tags, noncharacters, and other
    /// invisible format characters.
    Hidden,
    /// Joiners and variation selectors: legitimate inside non-ASCII text
    /// (emoji sequences, Persian and Indic scripts), replaced elsewhere.
    Joiner,
}

/// Bidirectional formatting characters (Unicode UAX #9, table 1): ALM,
/// LRM, RLM, LRE, RLE, PDF, LRO, RLO, LRI, RLI, FSI, PDI.
pub(crate) const fn is_bidi_control(c: char) -> bool {
    matches!(
        c,
        '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
    )
}

/// Classifies `c`. Covers every `Default_Ignorable_Code_Point` range of
/// Unicode 16 (DerivedCoreProperties.txt), the bidi controls, C1
/// controls, U+2028/U+2029, the interlinear annotation controls, and
/// noncharacters.
pub(crate) const fn classify(c: char) -> Class {
    if is_bidi_control(c) {
        return Class::Hidden;
    }
    match c {
        // Zero-width non-joiner, joiner, combining grapheme joiner, and
        // variation selectors (including the Mongolian ones).
        '\u{200C}'
        | '\u{200D}'
        | '\u{034F}'
        | '\u{180B}'..='\u{180D}'
        | '\u{180F}'
        | '\u{FE00}'..='\u{FE0F}'
        | '\u{E0100}'..='\u{E01EF}' => Class::Joiner,
        // C1 controls (U+0080..U+009F; ASCII controls are rejected by the
        // manifest decoder).
        '\u{0080}'..='\u{009F}'
        // Soft hyphen, Hangul and Khmer fillers, Mongolian vowel separator.
        | '\u{00AD}'
        | '\u{115F}'
        | '\u{1160}'
        | '\u{17B4}'
        | '\u{17B5}'
        | '\u{180E}'
        | '\u{3164}'
        | '\u{FFA0}'
        // Zero-width space, word joiner, invisible operators, deprecated
        // format characters (U+2065 is reserved default-ignorable).
        | '\u{200B}'
        | '\u{2060}'..='\u{2065}'
        | '\u{206A}'..='\u{206F}'
        // Line and paragraph separators.
        | '\u{2028}'
        | '\u{2029}'
        // Byte order mark / zero-width no-break space.
        | '\u{FEFF}'
        // Reserved default-ignorables and interlinear annotation.
        | '\u{FFF0}'..='\u{FFFB}'
        // Shorthand format controls, musical formatting.
        | '\u{1BCA0}'..='\u{1BCA3}'
        | '\u{1D173}'..='\u{1D17A}'
        // Tags (they can spell hidden ASCII text) and the rest of the
        // default-ignorable plane-14 block.
        | '\u{E0000}'..='\u{E00FF}'
        | '\u{E01F0}'..='\u{E0FFF}'
        // Noncharacters.
        | '\u{FDD0}'..='\u{FDEF}' => Class::Hidden,
        _ if (c as u32) & 0xFFFE == 0xFFFE => Class::Hidden,
        _ => Class::Plain,
    }
}

/// Space separators (general category Zs) and ASCII space.
pub(crate) const fn is_space(c: char) -> bool {
    matches!(
        c,
        ' ' | '\u{00A0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200A}' | '\u{202F}' | '\u{205F}' | '\u{3000}'
    )
}

/// Characters drawn like a full stop, which can fake an extension
/// separator ("photo\u{2024}jpg.exe" displays as "photo.jpg.exe").
pub(crate) const fn is_dot_lookalike(c: char) -> bool {
    matches!(
        c,
        '\u{00B7}'
            | '\u{0701}'
            | '\u{0702}'
            | '\u{06D4}'
            | '\u{2024}'
            | '\u{2027}'
            | '\u{2219}'
            | '\u{22C5}'
            | '\u{2E33}'
            | '\u{3002}'
            | '\u{A4F8}'
            | '\u{FE52}'
            | '\u{FF0E}'
            | '\u{FF61}'
    )
}

/// The ASCII letter or digit `c` is commonly confused with, lowercase:
/// Cyrillic, Greek, Armenian, and Latin look-alikes and fullwidth forms
/// (a subset of Unicode's confusables.txt covering the letters that file
/// extensions use).
pub(crate) fn ascii_skeleton(c: char) -> Option<char> {
    if c.is_ascii_alphanumeric() {
        return Some(c.to_ascii_lowercase());
    }
    // Fullwidth ASCII.
    if let '\u{FF10}'..='\u{FF19}' | '\u{FF21}'..='\u{FF3A}' | '\u{FF41}'..='\u{FF5A}' = c {
        let ascii = char::from_u32(c as u32 - 0xFEE0)?;
        return Some(ascii.to_ascii_lowercase());
    }
    let mapped = match c {
        'а' | 'А' | 'α' | 'Α' | 'ɑ' => 'a',
        'в' | 'В' | 'β' | 'Β' | 'ь' => 'b',
        'с' | 'С' | 'ϲ' | 'Ϲ' | 'ⅽ' => 'c',
        'ԁ' | 'ⅾ' => 'd',
        'е' | 'Е' | 'ε' | 'Ε' | 'ё' | 'ҽ' => 'e',
        'ғ' | 'ϝ' => 'f',
        'ɡ' | 'ց' => 'g',
        'һ' | 'Н' | 'Η' | 'հ' => 'h',
        'і' | 'І' | 'ι' | 'Ι' | 'ı' | 'ⅰ' | 'ӏ' | 'Ӏ' => 'i',
        'ј' | 'Ј' | 'ϳ' => 'j',
        'к' | 'К' | 'κ' | 'Κ' => 'k',
        'ⅼ' | 'ℓ' | 'Ɩ' => 'l',
        'м' | 'М' | 'Μ' | 'ⅿ' => 'm',
        'п' | 'η' | 'Ν' | 'ո' => 'n',
        'о' | 'О' | 'ο' | 'Ο' | 'օ' | 'σ' => 'o',
        'р' | 'Р' | 'ρ' | 'Ρ' | 'թ' => 'p',
        'ԛ' | 'գ' => 'q',
        'г' | 'ⲅ' => 'r',
        'ѕ' | 'Ѕ' | 'ꜱ' => 's',
        'т' | 'Т' | 'τ' | 'Τ' => 't',
        'υ' | 'ս' | 'ʋ' => 'u',
        'ν' | 'ѵ' | 'ⅴ' => 'v',
        'ԝ' | 'ա' | 'ѡ' => 'w',
        'х' | 'Х' | 'χ' | 'Χ' | 'ⅹ' => 'x',
        'у' | 'У' | 'γ' | 'Υ' => 'y',
        'Ζ' | 'ᴢ' => 'z',
        _ => return None,
    };
    Some(mapped)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bidi_controls_and_invisibles_are_hidden() {
        for c in [
            '\u{061C}',
            '\u{200E}',
            '\u{200F}',
            '\u{202A}',
            '\u{202B}',
            '\u{202C}',
            '\u{202D}',
            '\u{202E}',
            '\u{2066}',
            '\u{2067}',
            '\u{2068}',
            '\u{2069}',
            '\u{200B}',
            '\u{2060}',
            '\u{FEFF}',
            '\u{00AD}',
            '\u{3164}',
            '\u{0085}',
            '\u{2028}',
            '\u{E0041}',
            '\u{FFFE}',
            '\u{1FFFF}',
            '\u{FDD0}',
        ] {
            assert_eq!(classify(c), Class::Hidden, "{:04X}", c as u32);
        }
        for c in ['\u{200C}', '\u{200D}', '\u{FE0F}', '\u{E0100}'] {
            assert_eq!(classify(c), Class::Joiner, "{:04X}", c as u32);
        }
        for c in ['a', 'é', '漢', '😀', '\u{FFFD}', ' ', '\u{3000}'] {
            assert_eq!(classify(c), Class::Plain, "{:04X}", c as u32);
        }
    }

    #[test]
    fn skeletons_map_lookalikes_to_ascii() {
        assert_eq!(ascii_skeleton('е'), Some('e'));
        assert_eq!(ascii_skeleton('Ｅ'), Some('e'));
        assert_eq!(ascii_skeleton('７'), Some('7'));
        assert_eq!(ascii_skeleton('X'), Some('x'));
        assert_eq!(ascii_skeleton('漢'), None);
    }
}
