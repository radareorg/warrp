

/// Clean symbol name by removing common prefixes and suffixes.
pub fn clean_symbol_name(symbol_name: &str) -> String {
    let mut result = symbol_name;

    // Strip radare2 prefixes (sym., imp., fcn., etc.)
    for prefix in &["sym.", "imp.", "fcn.", "loc."] {
        if result.starts_with(prefix) {
            result = &result[prefix.len()..];
            break;
        }
    }

    // Handle MSVC-style imported symbols (__imp__)
    if result.starts_with("__imp__") {
        result = &result[7..];
    }

    // Handle jump thunk prefix
    if result.starts_with("j_") {
        result = &result[2..];
    }

    // Strip leading underscores (but keep at least one char)
    while result.starts_with('_') && result.len() > 1 {
        result = &result[1..];
    }

    // Remove stdcall decoration (@N suffix)
    match result.find('@') {
        Some(pos) => result[..pos].to_string(),
        None => result.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_symbol_name() {
        assert_eq!(clean_symbol_name("sym.free"), "free");
        assert_eq!(clean_symbol_name("imp.free"), "free");
        assert_eq!(clean_symbol_name("__imp__RemoveDirectoryW@4"), "RemoveDirectoryW");
        assert_eq!(clean_symbol_name("j___free_base"), "free_base");
        assert_eq!(clean_symbol_name("fcn.0x1234"), "0x1234");
    }
}
