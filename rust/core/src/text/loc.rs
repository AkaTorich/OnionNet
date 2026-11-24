//! Lookup over the phrase table, mirroring `Loc.cs`.

use super::strings_en;

/// The phrase behind a key.
///
/// A missing key must be loud, not silent: an empty label looks like a layout
/// bug and gets hunted in the wrong place. So an unknown key comes back as
/// `?key?`.
pub fn t(key: &str) -> String {
    match strings_en::get(key) {
        Some(text) => text.to_string(),
        None => format!("?{}?", key),
    }
}

/// The phrase behind a key, with `{0}`, `{1}`... filled in from `args`.
///
/// Mirrors the C# `string.Format(InvariantCulture, text, args)`: `{{` and `}}`
/// are literal braces, `{N}` is replaced by `args[N]`. If the template is
/// malformed or an index is out of range (what C# surfaces as
/// `FormatException`), the unformatted phrase is returned unchanged.
pub fn t_args(key: &str, args: &[&str]) -> String {
    let text = t(key);
    if args.is_empty() {
        return text;
    }
    match format_braces(&text, args) {
        Ok(s) => s,
        Err(()) => text,
    }
}

/// Substitute `{0}`, `{1}`... in `template`. `Err(())` stands in for the C#
/// `FormatException` that `t_args` swallows.
fn format_braces(template: &str, args: &[&str]) -> Result<String, ()> {
    let chars: Vec<char> = template.chars().collect();
    let mut out = String::with_capacity(template.len());
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '{' => {
                if chars.get(i + 1) == Some(&'{') {
                    out.push('{');
                    i += 2;
                    continue;
                }
                i += 1;
                let start = i;
                while i < chars.len() && chars[i].is_ascii_digit() {
                    i += 1;
                }
                if i == start {
                    // `{` with no index digits.
                    return Err(());
                }
                let index: usize = chars[start..i].iter().collect::<String>().parse().map_err(|_| ())?;
                if chars.get(i) != Some(&'}') {
                    // Alignment / format specifiers are not used by any phrase;
                    // anything but a closing brace is a malformed item.
                    return Err(());
                }
                i += 1;
                if index >= args.len() {
                    return Err(());
                }
                out.push_str(args[index]);
            }
            '}' => {
                if chars.get(i + 1) == Some(&'}') {
                    out.push('}');
                    i += 2;
                    continue;
                }
                // A lone `}` is malformed, as in C#.
                return Err(());
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_keys_resolve_exactly() {
        assert_eq!(t("app.subtitle"), "onion network");
        assert_eq!(t("title.minimise"), "Minimize");
        assert_eq!(t("btn.join"), "RECONNECT");
        assert_eq!(t("peer.status.ok"), "OK");
        assert_eq!(t("tray.tip.idle"), "StalkNet - node stopped");
    }

    #[test]
    fn concatenated_phrase_is_seamless() {
        assert_eq!(
            t("login.address.hint"),
            "Your folder address. It is derived from a separate key and does not \
reveal your relay."
        );
    }

    #[test]
    fn missing_key_hits_fallback() {
        assert_eq!(t("no.such.key"), "?no.such.key?");
        // The fallback also holds through the formatting overload.
        assert_eq!(t_args("no.such.key", &["x"]), "?no.such.key?");
    }

    #[test]
    fn placeholders_are_filled() {
        assert_eq!(t_args("state.node", &["9001"]), "Relay on port 9001");
        assert_eq!(
            t_args("stats.format", &["3", "12", "5"]),
            "Own circuits: 3   Relayed: 12   Streams: 5"
        );
        assert_eq!(t_args("msg.download.progress", &["file.bin", "42"]), "file.bin: 42%");
    }

    #[test]
    fn no_args_returns_template_unchanged() {
        // Same as C#: with no args the raw template (braces intact) comes back.
        assert_eq!(t_args("state.node", &[]), "Relay on port {0}");
    }

    #[test]
    fn missing_index_returns_unformatted() {
        // Index out of range is a FormatException in C#, swallowed to the text.
        assert_eq!(t_args("state.node", &[]), "Relay on port {0}");
        // One placeholder, no matching arg -> unchanged.
        assert_eq!(
            t_args("stats.format", &["only-one"]),
            "Own circuits: {0}   Relayed: {1}   Streams: {2}"
        );
    }
}
