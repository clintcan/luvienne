//! Caret editing for a single-line text buffer.
//!
//! Shared by the three places that take typed input — the host form's fields,
//! the fuzzy filter, and quick connect. They had three copies of "append a
//! character, pop from the end", and grew a caret one at a time; this is the one
//! copy they now agree on.
//!
//! Cursors are counted in **characters**, not bytes: a caret between `é` and the
//! next letter is one position, and byte offsets are computed only where
//! `String` demands them.

/// Where character `index` starts, or the end of the string.
fn byte_at(value: &str, index: usize) -> usize {
    value
        .char_indices()
        .nth(index)
        .map_or(value.len(), |(byte, _)| byte)
}

/// The caret can never sit past the end — values are also assigned wholesale in
/// places (a file picker returning a path), which would otherwise strand it.
pub fn clamp(value: &str, cursor: usize) -> usize {
    cursor.min(value.chars().count())
}

pub fn end(value: &str) -> usize {
    value.chars().count()
}

pub fn insert(value: &mut String, cursor: &mut usize, c: char) {
    let at = clamp(value, *cursor);
    value.insert(byte_at(value, at), c);
    *cursor = at + 1;
}

/// Remove the character *before* the caret. A no-op at the start, rather than
/// wrapping round or eating the first character.
pub fn backspace(value: &mut String, cursor: &mut usize) {
    let at = clamp(value, *cursor);
    if at == 0 {
        return;
    }
    value.remove(byte_at(value, at - 1));
    *cursor = at - 1;
}

/// Remove the character *at* the caret, which stays put.
pub fn delete(value: &mut String, cursor: usize) {
    let at = clamp(value, cursor);
    let byte = byte_at(value, at);
    if byte < value.len() {
        value.remove(byte);
    }
}

pub fn left(value: &str, cursor: &mut usize) {
    *cursor = clamp(value, *cursor).saturating_sub(1);
}

pub fn right(value: &str, cursor: &mut usize) {
    *cursor = (clamp(value, *cursor) + 1).min(end(value));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typing_inserts_at_the_caret() {
        let (mut value, mut cursor) = ("web-1".to_string(), 4);
        insert(&mut value, &mut cursor, '0');
        assert_eq!(value, "web-01");
        assert_eq!(cursor, 5, "the caret follows what was typed");
    }

    #[test]
    fn backspace_at_the_start_does_nothing() {
        let (mut value, mut cursor) = ("web".to_string(), 0);
        backspace(&mut value, &mut cursor);
        assert_eq!(value, "web");
        assert_eq!(cursor, 0);
    }

    #[test]
    fn delete_takes_the_character_under_the_caret() {
        let (mut value, cursor) = ("web".to_string(), 0);
        delete(&mut value, cursor);
        assert_eq!(value, "eb");

        // And is a no-op at the end, where there is nothing under it.
        let mut done = "e".to_string();
        delete(&mut done, 1);
        assert_eq!(done, "e");
    }

    /// Characters, not bytes — a multi-byte character is one caret position and
    /// must not be split down the middle.
    #[test]
    fn the_caret_counts_characters() {
        let (mut value, mut cursor) = ("héllo".to_string(), 2);
        insert(&mut value, &mut cursor, 'X');
        assert_eq!(value, "héXllo");

        let (mut value, mut cursor) = ("héllo".to_string(), 2);
        backspace(&mut value, &mut cursor);
        assert_eq!(value, "hllo", "removed the wrong character");
        assert_eq!(cursor, 1);
    }

    /// A value replaced wholesale leaves the caret past the end; every operation
    /// has to survive that rather than panic on a byte index.
    #[test]
    fn a_stranded_caret_is_clamped_everywhere() {
        let mut value = "ab".to_string();
        let mut cursor = 99;
        insert(&mut value, &mut cursor, 'c');
        assert_eq!(value, "abc");

        let mut value = "ab".to_string();
        let mut cursor = 99;
        backspace(&mut value, &mut cursor);
        assert_eq!(value, "a");

        let mut value = "ab".to_string();
        delete(&mut value, 99);
        assert_eq!(value, "ab");
    }
}
