//! Offline cache of the *encrypted* sync response.
//!
//! Only the raw `/api/sync` JSON and the user id are stored. Decryption keys,
//! master passwords and API secrets are never written to disk: keeping the
//! protected key alone would allow an offline master-password guess.
//!
//! Wiring (see [`cached_sync_for`]): the auth layer reads this cache when
//! `/api/sync` fails *after* a successful login, then unlocks with the
//! protected key from the live `Session`. This is a read-only, best-effort
//! restore. Both the server URL and the account id (derived from the personal
//! API key's `client_id`) must match before a cached body is accepted, so a
//! cache left by another account on the same server is refused. There is
//! currently no production writer: `openwarden` 0.1.0's
//! `Client::sync()` returns a parsed `SyncData` without the raw body and keeps
//! `Session::access_token` private, so `from_body`/`save_default` cannot be
//! fed from the login flow. A cache file therefore exists only if a legacy
//! release wrote one or it was provisioned out of band. A missing cache keeps
//! the original `AuthError::Sync` status; a present but unusable cache reports
//! the classified reason (corrupt / unreadable / outdated / mismatched).

use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::PathBuf;

use crate::vault_sync;

/// Errors produced while reading an offline sync cache.
///
/// Alias of [`AppError`](crate::error::AppError). Parsing, redaction and
/// serialization have separate `CacheParse` / `CacheRedact` / `CacheSerialize`
/// variants, each retaining the underlying error through `Error::source()`.
pub type SyncCacheError = crate::error::AppError;

/// Maximum age of a cached sync response before it is refused.
///
/// Seven days balances offline availability with the risk of acting on stale
/// vault data (for example after a key rotation on the server).
pub const MAX_CACHE_AGE_SECS: i64 = 7 * 24 * 60 * 60;

/// Maximum raw `/api/sync` body accepted from a cache.
///
/// openwarden caps a live sync response at 32 MiB; a PoC vault needs far less.
pub const MAX_CACHE_BODY_BYTES: usize = 8 * 1024 * 1024;

/// Maximum on-disk cache file size accepted before parsing.
///
/// `body: Vec<u8>` is serialized as a JSON number per byte, expanding roughly
/// fourfold, so the file cap leaves headroom over the raw-body cap. A corrupt
/// or hostile file must not exhaust memory before the parser runs.
pub const MAX_CACHE_BYTES: u64 = 64 * 1024 * 1024;

/// A cached sync response, still encrypted.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncCache {
    /// Schema version, so a future format change can be detected.
    pub version: u32,
    /// The account the response belongs to.
    pub user_id: String,
    /// Server URL the response came from.
    ///
    /// Known constraint: this value is stored verbatim and may contain URL-embedded
    /// credentials (for example `https://user:pass@host`). `from_body` does not
    /// strip userinfo from the URL because the offline-mismatch check compares
    /// the stored value byte-for-byte with the URL used at restore time, and no
    /// production writer currently feeds this path. Restore also compares
    /// [`Self::user_id`] with the account id derived from the API key's
    /// `client_id`, so a cache from another account on the same server is no
    /// longer accepted. Treat the field as sensitive: `Debug` masks it, and
    /// callers must not log or persist it via another route.
    pub server_url: String,
    /// Raw `/api/sync` JSON body.
    pub body: Vec<u8>,
    /// When the body was captured, in Unix seconds.
    ///
    /// Absent in caches written by earlier builds; those remain usable as a
    /// best-effort fallback because the writer is not connected in this PoC.
    #[serde(default)]
    pub created_at: Option<i64>,
}

/// Byte index where the authority of `url` starts.
///
/// `://` is a scheme delimiter only when it follows a valid scheme at the very
/// front of the text ([`is_scheme`]). A plain `find("://")` also matched a
/// nested URL inside a query (`//host/p?next=https://cb.example.com`) and
/// started the authority scan there, leaving real userinfo unmasked. Skipping
/// non-scheme candidates keeps the scan in the outer authority. The scheme
/// check is ASCII-case-insensitive, so `HTTPS://` is recognized as well.
/// Without a scheme, the authority starts after any leading `/` bytes: a
/// protocol-relative `//user:pass@host` starts at byte two, and a decoded
/// scheme-less nested authority such as `/user:pass@host` starts at byte one.
/// Treating the single leading `/` as the *end* of the authority would leave
/// its userinfo outside the scan.
fn authority_start(url: &str) -> usize {
    let mut from = 0usize;
    while let Some(relative) = url[from..].find("://") {
        let delimiter = from + relative;
        if is_scheme(&url[..delimiter]) {
            return delimiter + 3;
        }
        from = delimiter + 3;
    }
    // No leading scheme: skip path-absolute prefixes. Counting *all* leading
    // slashes keeps the protocol-relative form at 2 while also handling a
    // single-slash scheme-less authority from a decoded nested value.
    url.bytes().take_while(|byte| *byte == b'/').count()
}

/// Whether `text` is an RFC 3986 scheme: an ASCII letter followed by ASCII
/// letters, digits, `+`, `-` or `.`. Matching is case-insensitive so an
/// upper-case spelling such as `HTTPS` still delimits the authority.
fn is_scheme(text: &str) -> bool {
    let mut bytes = text.bytes();
    matches!(bytes.next(), Some(b'A'..=b'Z' | b'a'..=b'z'))
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
}

/// Whether `text` contains a `user:secret`-style marker.
///
/// A colon followed by a non-empty, non-all-digits value distinguishes userinfo
/// from a `host:8443` port. Used to tell an unescaped '/' inside a password
/// from the path separator that closes the authority.
fn has_userinfo_colon(text: &str) -> bool {
    text.split_once(':').is_some_and(|(_, value)| {
        !value.is_empty() && !value.bytes().all(|byte| byte.is_ascii_digit())
    })
}

/// Render a server URL for `Debug`, dropping any URL-embedded userinfo.
///
/// A URL such as `https://user:pass@vault.example.com` must not leak the
/// credentials through a log line. The userinfo before the userinfo delimiter
/// is replaced by `[redacted]`; the host/path that follows is kept so
/// diagnostics remain useful. A protocol-relative `//user:pass@host/p` skips
/// its two leading bytes so the authority scan still sees the userinfo; the
/// same applies to a single leading `/` (`/user:pass@host/p`) from a decoded
/// nested value.
///
/// The delimiter is the last `@` **of the authority**, not the last `@` of the
/// whole pre-path text: a password may contain `@`, but an `@` in a query or
/// fragment (`https://host?email=a@b`) is not userinfo. A `?`/`#` before the
/// delimiter can be an unescaped character in the password, so it does not by
/// itself terminate the authority ([`at_is_in_query`] decides). The same holds
/// for an unescaped `/` in the password: a `/` preceded by a `user:secret`
/// marker and followed by an `@` with a plausible host does not close the
/// authority either — even when `?`/`#` follows that `/` immediately.
/// [`authority_start`] keeps `://` confined to a leading scheme, so a nested
/// URL in a query cannot move the scan into the query.
fn mask_url_userinfo(url: &str) -> String {
    let scheme_end = authority_start(url);
    // A path separator normally closes the authority. '?'/'#' are *not* used
    // as the boundary: an unescaped one inside a password would hide the real
    // delimiter. The same applies to an unescaped '/': when the text before it
    // carries a `user:secret` marker and a plausible separator followed by a
    // host comes after it, that '/' is part of the password, so extend the
    // authority to the next path separator before scanning for userinfo.
    let mut path_start = url[scheme_end..]
        .find('/')
        .map(|at| scheme_end + at)
        .unwrap_or(url.len());
    while path_start < url.len() {
        if !has_userinfo_colon(&url[scheme_end..path_start]) {
            break;
        }
        // Search every '@' after the '/', not only the text before the first
        // '?'/'#': one directly after the '/' (or later in the password) is an
        // unescaped password character, so it must not stop the authority scan.
        // `at_is_in_query` still rejects a genuine query/fragment '@', and the
        // host check rejects a stray one.
        let tail = &url[path_start..];
        let mut delimiter = None;
        for (relative_at, _) in tail.match_indices('@') {
            let at = path_start + relative_at;
            if at_is_in_query(&url[scheme_end..=at], at - scheme_end) {
                continue;
            }
            let host = url[at + 1..]
                .split(&['/', '?', '#'][..])
                .next()
                .unwrap_or("");
            if host_with_optional_port_ok(host) {
                delimiter = Some(at);
                break;
            }
        }
        let Some(at) = delimiter else {
            break;
        };
        path_start = url[at + 1..]
            .find('/')
            .map(|relative| at + 1 + relative)
            .unwrap_or(url.len());
    }
    let scan = &url[scheme_end..path_start];

    // The userinfo separator is the last '@' that belongs to the authority.
    // Earlier '@'s can be part of the password; later ones can belong to the
    // query/fragment and must be left untouched.
    let Some(at) = scan
        .match_indices('@')
        .map(|(index, _)| index)
        .rev()
        .find(|index| !at_is_in_query(scan, *index))
    else {
        return url.to_string();
    };

    let host_start = scheme_end + at + 1;
    format!("{}[redacted]@{}", &url[..scheme_end], &url[host_start..])
}

/// Whether the `@` at byte index `at` of `scan` belongs to a query/fragment
/// rather than to userinfo.
///
/// `scan` is the URL text between the scheme and the first path separator. A
/// `?`/`#` before `at` is either an unescaped character in the password or a
/// genuine query/fragment delimiter. It is genuine when the text before it has
/// no userinfo-style `user:password` marker (`host:8443` is a port, not a
/// password); an '@' already followed by a clean host also closes the authority,
/// so a later `?`/`#` starts the query. This keeps `https://host?email=a@b`
/// untouched while still masking `https://user:pass?x=1@host`.
///
/// Bracketed IPv6 hosts need special care: the colons in `[::1]` belong to the
/// address, not to a `user:password` marker, and `:1]` is not a port. Both
/// colon heuristics therefore look through IPv6 literals first.
fn at_is_in_query(scan: &str, at: usize) -> bool {
    let before = &scan[..at];
    before.match_indices(&['?', '#'][..]).any(|(delimiter, _)| {
        let head = &before[..delimiter];
        let has_userinfo_colon = head.split(&['?', '#'][..]).any(|part| {
            let part = without_ipv6_literals(part);
            part.split_once(':').is_some_and(|(_, value)| {
                !value.is_empty() && !value.bytes().all(|byte| byte.is_ascii_digit())
            })
        });
        let host_complete = head.match_indices('@').any(|(earlier, _)| {
            let candidate = &head[earlier + 1..];
            let host = candidate.split(&['/', '?', '#'][..]).next().unwrap_or("");
            host_with_optional_port_ok(host)
        });
        !has_userinfo_colon || host_complete
    })
}

/// Remove bracketed IPv6 literals so colon heuristics only see host and port.
///
/// In `[::1]` the colons are part of the address; treating them as a
/// `user:password` marker makes a query '@' look like the userinfo separator
/// and leaks the real credential. Dropping the literal is enough: the caller
/// only asks whether a non-numeric colon remains.
fn without_ipv6_literals(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find('[') {
        let Some(end_relative) = rest[start..].find(']') else {
            break;
        };
        let end = start + end_relative;
        out.push_str(&rest[..start]);
        rest = &rest[end + 1..];
    }
    out.push_str(rest);
    out
}

/// Whether `host` is a plausible authority host with an optional numeric port.
///
/// A plain `split_once(':')` mistakes the `:1]` of `[::1]` for a non-numeric
/// port, so a bracketed literal is parsed as an address closed by `]`; only an
/// optional numeric `:port` may follow it. This makes `host_complete` in
/// [`at_is_in_query`] recognize IPv6 hosts.
fn host_with_optional_port_ok(host: &str) -> bool {
    if host.is_empty() {
        return false;
    }
    let (hostname, port) = if let Some(rest) = host.strip_prefix('[') {
        let Some(end) = rest.find(']') else {
            return false;
        };
        let address = &rest[..end];
        if address.is_empty() || !address.contains(':') {
            return false;
        }
        let tail = &rest[end + 1..];
        let port = match tail.strip_prefix(':') {
            Some(port) => Some(port),
            None if tail.is_empty() => None,
            None => return false,
        };
        (address, port)
    } else {
        match host.split_once(':') {
            Some((name, value)) => (name, Some(value)),
            None => (host, None),
        }
    };
    if hostname.is_empty() || hostname.contains(&['@', '=', '?', '#'][..]) {
        return false;
    }
    port.is_none_or(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
}

/// Whether a decoded value looks like a nested authority carrying userinfo.
///
/// A nested URL is normally detected by `?`, `#` or `//` (see
/// [`mask_param_pairs`]). A scheme-less authority such as
/// `user:secret@host/path` has none of those, so its `@` with a `user:password`
/// marker before it and a plausible host after it is the signal here. The
/// check stays narrow on purpose: a harmless `state=a@b` has no userinfo colon
/// and is left verbatim in the diagnostic URL.
fn nested_authority_with_userinfo(value: &str) -> bool {
    value.match_indices('@').any(|(at, _)| {
        let before = &value[..at];
        let after = &value[at + 1..];
        let has_userinfo = before
            .split(&['?', '#'][..])
            .next_back()
            .is_some_and(|part| {
                part.split_once(':').is_some_and(|(_, secret)| {
                    !secret.is_empty() && !secret.bytes().all(|byte| byte.is_ascii_digit())
                })
            });
        let host = after.split(&['/', '?', '#'][..]).next().unwrap_or("");
        has_userinfo && host_with_optional_port_ok(host)
    })
}

/// Whether a query/fragment parameter name denotes a credential.
///
/// The match is a case-insensitive substring so common variants such as
/// `api_key`, `accessToken` and `session_id` are covered by the same small
/// list. Besides the audit contract's `secret`, `password`, `passwd`, `auth`,
/// `sig`, `session` and `code`, the list includes the short spellings `pass`,
/// `pwd`, `pw` and `credential` (plus the pre-existing `token` and `key`):
/// a bare `?pass=…` or `?credential=…` is just as secret as `?password=…`.
/// Known constraint: the match is on ASCII text only. A key whose name is
/// hidden behind a non-ASCII percent escape is not folded into a sensitive
/// name: `percent_decode` deliberately keeps escapes that decode outside
/// printable ASCII as literal `%XX`, and a multi-byte UTF-8 sequence cannot
/// spell an ASCII key at all. Such a key's value therefore survives in the
/// diagnostic URL. This masker's contract covers ASCII (including twice
/// percent-encoded ASCII) key names only; do not rely on `Debug` redaction for
/// URLs whose keys use non-ASCII escapes.
fn is_sensitive_param_key(key: &str) -> bool {
    let folded = key.to_ascii_lowercase();
    [
        "token",
        "key",
        "secret",
        "password",
        "passwd",
        "pass",
        "pwd",
        "pw",
        "credential",
        "auth",
        "sig",
        "session",
        "code",
    ]
    .iter()
    .any(|needle| folded.contains(needle))
}

/// Decode one hexadecimal digit of a percent escape.
fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Percent-decode the `%XX` escapes of a value before inspecting it.
///
/// Only printable ASCII escapes are decoded: a raw non-ASCII byte produced by
/// a sequence such as `%E3%81%82` is kept as its original escape so the
/// rendered diagnostic stays valid UTF-8. Control escapes (`%00`-`%1F`,
/// `%7F`) stay literal too: decoding them would inject a newline or NUL into
/// a log line. Malformed escapes stay literal as well; a crafted value must
/// not change the structure of the URL merely by being decoded.
fn percent_decode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(first) = rest.chars().next() {
        if first == '%' {
            let bytes = rest.as_bytes();
            if bytes.len() >= 3 {
                if let (Some(high), Some(low)) = (hex_value(bytes[1]), hex_value(bytes[2])) {
                    let decoded = (high << 4) | low;
                    if decoded.is_ascii() && !decoded.is_ascii_control() {
                        out.push(char::from(decoded));
                        rest = &rest[3..];
                        continue;
                    }
                }
            }
        }
        out.push(first);
        rest = &rest[first.len_utf8()..];
    }
    out
}

/// Maximum recursion depth when a harmless parameter value is itself a URL.
///
/// A diagnostic URL can nest URLs in values (`?next=https://h/?next=...`).
/// Unbounded recursion would let a hostile URL exhaust the stack. Past this
/// depth the nested value is replaced by `[redacted]` instead of being
/// descended into, so a credential hidden in the unrendered tail cannot leak.
/// The legitimate one- and two-level cases stay fully masked.
pub(crate) const MAX_MASK_DEPTH: usize = 8;

/// Mask userinfo in nested URLs before `&`/`;` pair separators are applied.
///
/// `mask_param_pairs` treats both `&` and `;` as query separators, but either
/// is also a legal character inside a password. A nested value such as
/// `next=https://user:p;a&b=s@host/p` would be cut into several pairs, so the
/// recursive masker would never see the whole authority and the password would
/// reach a log line. Rewrite only userinfo that contains one of those
/// separators and looks like `user:secret@plausible-host`: harmless `state=a@b`
/// values and values without a pair separator stay verbatim, and the
/// surrounding key/scheme is kept so the diagnostic URL remains traceable.
/// A '/' inside the password is not a boundary either: the delimiter search
/// keeps the rightmost split that still yields a whole `user:secret` value.
fn mask_nested_userinfo_in_pairs(pairs: &str) -> String {
    let mut out = String::with_capacity(pairs.len());
    let mut rest = pairs;
    // This pre-pass only rewrites credentials the pair splitter would cut
    // apart, so a candidate must carry one of those separators as well as a
    // `user:secret` marker.
    let userinfo_with_separator = |candidate: &str| {
        let has_secret = candidate.split_once(':').is_some_and(|(_, secret)| {
            !secret.is_empty() && !secret.bytes().all(|byte| byte.is_ascii_digit())
        });
        has_secret && (candidate.contains(';') || candidate.contains('&'))
    };
    while let Some(relative_at) = rest.find('@') {
        let before = &rest[..relative_at];
        // '?', '#' and '/' normally close the enclosing path/query, but '/' is
        // also a legal password character. Walk the delimiters from right to
        // left and keep the rightmost one whose tail is still a whole
        // `user:secret` value: a password like `p/&ss` must not be cut at the
        // '/', or the userinfo colon before it becomes invisible. '&' itself is
        // deliberately never a boundary here, for the same reason.
        let mut pair_start = 0usize;
        for (index, _) in before.match_indices(&['?', '#', '/'][..]).rev() {
            let start = index + 1;
            if userinfo_with_separator(&before[start..]) {
                pair_start = start;
                break;
            }
        }
        // Everything after the chosen delimiter is the authority candidate. Do
        // not look for '=' here: a password may itself contain `a=s`, and
        // treating that as the key/value boundary hid the real userinfo from
        // this helper.
        let (prefix_end, candidate) = if pair_start == 0 {
            // Scheme-less authority: keep the `key=` prefix in the diagnostic
            // output. The first '=' is the pair separator here; later '=' are
            // part of the password and must not be treated as boundaries.
            let head = before.find('=').map(|index| index + 1).unwrap_or(0);
            (head, &before[head..])
        } else {
            (pair_start, &before[pair_start..])
        };
        let after = &rest[relative_at + 1..];
        let host = after.split(&['/', '?', '#'][..]).next().unwrap_or("");
        // Both separators must be checked in the *candidate*: the pair splitter
        // below would otherwise cut a password containing either one before
        // the recursive masker ever sees the authority.
        if userinfo_with_separator(candidate) && host_with_optional_port_ok(host) {
            out.push_str(&before[..prefix_end]);
            out.push_str("[redacted]");
            out.push('@');
        } else {
            out.push_str(&rest[..relative_at + 1]);
        }
        rest = &rest[relative_at + 1..];
    }
    out.push_str(rest);
    out
}

/// Redact secret-bearing `key=value` pairs in a query or a fragment.
///
/// A harmless key whose *value* is itself a URL is masked recursively: a
/// nested `?token=...` or `#code=...` would otherwise survive the top-level
/// key check and reach a diagnostic log verbatim. The nested URL may be
/// percent-encoded (`%3F`, `%3A%2F%2F`), protocol-relative
/// (`//user:SECRET@host/p`) or a bare authority (`user:SECRET@host/p`);
/// decoding first keeps credentials from hiding. Both `&` and `;` are query
/// separators, so neither may shield a following secret. When found, the
/// decoded masked form is rendered; plain values are copied unchanged.
/// Recursion is capped by [`MAX_MASK_DEPTH`]; `depth` counts already-entered
/// nested URLs.
fn mask_param_pairs(pairs: &str, depth: usize) -> String {
    // A ';' may be part of a nested URL's userinfo (`next=https://u:p;a=s@host`).
    // Mask that authority *before* splitting, otherwise the cut would leave the
    // password in the diagnostic URL (see `mask_nested_userinfo_in_pairs`).
    let pairs = mask_nested_userinfo_in_pairs(pairs);
    let pairs = pairs.as_str();
    let mut out = String::with_capacity(pairs.len());
    // Split on either separator but keep the original delimiter in the
    // diagnostic output; a trailing separator leaves an empty final pair.
    let mut segments: Vec<&str> = Vec::new();
    let mut separators: Vec<char> = Vec::new();
    let mut start = 0;
    for (index, ch) in pairs.char_indices() {
        if ch == '&' || ch == ';' {
            segments.push(&pairs[start..index]);
            separators.push(ch);
            start = index + ch.len_utf8();
        }
    }
    segments.push(&pairs[start..]);

    for (index, &pair) in segments.iter().enumerate() {
        if index > 0 {
            out.push(separators[index - 1]);
        }
        if let Some((key, value)) = pair.split_once('=') {
            // A key can hide a credential name behind percent escapes
            // (`%74oken` is `token`), or behind two rounds of them
            // (`%2574oken` -> `%74oken` -> `token`). Decode twice before the
            // substring match so a crafted key cannot slip past
            // `is_sensitive_param_key`. The original spelling is kept in the
            // diagnostic output.
            let decoded_key = percent_decode(&percent_decode(key));
            if is_sensitive_param_key(&decoded_key) {
                out.push_str(key);
                out.push_str("=[redacted]");
                continue;
            }
            // Decode *twice* before the nested-URL check: a doubly encoded
            // delimiter such as `%253F` becomes `%3F` after one pass and
            // `?` only after the second. `//` matches nested URLs both with
            // (`://`) and without (`//user:SECRET@host/p`) a scheme; the
            // authority helper covers the scheme-less form. A value that is
            // not a nested URL is left verbatim.
            let decoded = percent_decode(&percent_decode(value));
            if decoded.contains('?')
                || decoded.contains('#')
                || decoded.contains("//")
                || nested_authority_with_userinfo(&decoded)
            {
                out.push_str(key);
                out.push('=');
                if depth >= MAX_MASK_DEPTH {
                    // Stop the descent before the stack grows further. The
                    // whole tail is replaced, so nothing behind the cap is
                    // rendered into the diagnostic URL.
                    out.push_str("[redacted]");
                } else {
                    out.push_str(&mask_url_secrets_inner(&decoded, depth + 1));
                }
            } else {
                out.push_str(pair);
            }
        } else {
            out.push_str(pair);
        }
    }
    out
}

/// Redact secret-bearing values in the userinfo, query **and fragment** while
/// keeping the URL's structure.
///
/// A diagnostic URL may carry a token, API key or password in any of those
/// three components. Those values are credentials and must never reach a log
/// line. Only values whose key looks sensitive are replaced; harmless
/// parameters are preserved so the diagnostic remains useful. A URL without a
/// query is still checked for a fragment, and nested URLs inside a value are
/// handled by [`mask_param_pairs`].
///
/// The first `?`/`#` decides which section follows: a `?` that appears
/// *after* the `#` belongs to the fragment, not to a query. Treating such a
/// `?` as a query delimiter would copy the fragment text before it verbatim
/// into the output and leak its credentials.
fn mask_url_secrets(url: &str) -> String {
    mask_url_secrets_inner(url, 0)
}

/// Depth-limited implementation of [`mask_url_secrets`].
fn mask_url_secrets_inner(url: &str, depth: usize) -> String {
    let masked = mask_url_userinfo(url);
    let fragment_start = masked.find('#');
    let query_start = masked
        .find('?')
        .filter(|at| fragment_start.is_none_or(|fragment| *at < fragment));
    if let Some(query_start) = query_start {
        let query_end = fragment_start.unwrap_or(masked.len());
        let mut out = String::with_capacity(masked.len());
        out.push_str(&masked[..query_start + 1]);
        out.push_str(&mask_param_pairs(
            &masked[query_start + 1..query_end],
            depth,
        ));
        if let Some(fragment_start) = fragment_start {
            out.push('#');
            out.push_str(&mask_param_pairs(&masked[fragment_start + 1..], depth));
        }
        out
    } else if let Some(fragment_start) = fragment_start {
        format!(
            "{}#{}",
            &masked[..fragment_start],
            mask_param_pairs(&masked[fragment_start + 1..], depth)
        )
    } else {
        masked
    }
}

impl core::fmt::Debug for SyncCache {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SyncCache")
            .field("version", &self.version)
            .field("user_id", &self.user_id)
            // The URL may carry userinfo or query credentials; never render it
            // verbatim.
            .field("server_url", &mask_url_secrets(&self.server_url))
            .field("body", &format!("<{} bytes redacted>", self.body.len()))
            .finish()
    }
}

impl SyncCache {
    /// The current schema version.
    pub const VERSION: u32 = 1;

    /// Build a cache entry from a sync response body.
    ///
    /// All `key` / `private_key` fields are stripped before storage, including
    /// nested per-item keys on ciphers and folders: keeping any protected key
    /// on disk would allow an offline master-password guess. `apply_sync`
    /// tolerates the absence of profile keys because the live `Session`
    /// supplies the protected key at unlock time; a cipher whose own key was
    /// stripped cannot be decrypted offline and is reported as uninspectable.
    /// Both camelCase (`privateKey`) and PascalCase / snake_case spellings are
    /// removed, since this runs on the *raw* body before normalization (see
    /// `redact_profile_keys`).
    ///
    /// # Errors
    ///
    /// [`SyncCacheError::InvalidCache`] when the body is not a valid sync
    /// response.
    pub fn from_body(body: Vec<u8>, server_url: &str) -> Result<Self, SyncCacheError> {
        if body.len() > MAX_CACHE_BODY_BYTES {
            return Err(SyncCacheError::CacheTooLarge);
        }
        let sync = vault_sync::parse_sync(&body)
            .map_err(|error| SyncCacheError::CacheParse(crate::error::BoxedCause::new(error)))?;
        let user_id = sync.user_id().to_string();
        let sanitized = redact_profile_keys(&body)?;
        Ok(Self {
            version: Self::VERSION,
            user_id,
            server_url: server_url.to_string(),
            body: sanitized,
            created_at: Some(i64::try_from(crate::totp::now_unix()).unwrap_or(i64::MAX)),
        })
    }

    /// Parse the cached body back into an `openwarden::SyncData`.
    ///
    /// # Errors
    ///
    /// [`SyncCacheError::InvalidCache`] when the body no longer parses.
    pub fn sync(&self) -> Result<openwarden::SyncData, SyncCacheError> {
        vault_sync::parse_sync(&self.body)
            .map_err(|error| SyncCacheError::CacheParse(crate::error::BoxedCause::new(error)))
    }
}

/// Whether a captured-at timestamp is outside the accepted offline window.
///
/// `None` means a cache written before timestamps existed; it stays usable as
/// a best-effort fallback rather than silently disabling offline restore. A
/// timestamp in the future is treated as expired: it can only come from clock
/// skew or a forged/stale file, and trusting it would extend the offline
/// window indefinitely. `i64::MAX` is the sentinel used when a clock value
/// cannot be represented, so it is expired even if the reader's clock is
/// broken in the same way.
pub(crate) fn is_cache_expired(created_at: Option<i64>, now: i64) -> bool {
    match created_at {
        None => false,
        Some(i64::MAX) => true,
        Some(captured) if captured > now => true,
        Some(captured) => now.saturating_sub(captured) > MAX_CACHE_AGE_SECS,
    }
}

/// Whether a field name denotes protected or private key material, regardless
/// of the casing/separator convention the server used.
///
/// `normalize_sync_keys` (in [`crate::vault_sync`]) only lowercases the first
/// character, so a raw PascalCase `Key` / `PrivateKey` would survive a literal
/// `remove("key")`/`remove("privateKey")` pair. Comparing a separator-free,
/// ASCII-lowercased form closes that gap without touching fields such as
/// `keyId` that are not themselves secrets. The same fold is used for nested
/// per-item keys (`ciphers[].key`, `attachments[].key`, …).
fn is_secret_profile_key(key: &str) -> bool {
    let folded: String = key
        .chars()
        .filter(|character| *character != '_' && *character != '-')
        .flat_map(char::to_lowercase)
        .collect();
    matches!(folded.as_str(), "key" | "privatekey")
}

/// Recursively remove secret key fields from a JSON value.
///
/// Only object members are removed; arrays and all other structure stay
/// intact, so the cached body remains a valid sync response. Traversing every
/// object covers profile keys, per-item keys (`ciphers[].key`), attachment keys
/// and any other nested container without maintaining a list of container
/// names (which a server-side rename could bypass).
fn redact_secret_keys(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(object) => {
            object.retain(|key, _| !is_secret_profile_key(key));
            for child in object.values_mut() {
                redact_secret_keys(child);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                redact_secret_keys(item);
            }
        }
        _ => {}
    }
}

/// Remove key material from a raw sync body, keeping the rest of the
/// encrypted ciphers and folders intact.
///
/// The walk is recursive and case-insensitive: a Vaultwarden body that uses
/// `Profile` / `Key`, a second crafted `profile` object, and per-item keys on
/// ciphers or folders must not smuggle key material past the redactor and onto
/// disk. Once an item's key is gone, offline decryption of that specific item
/// fails (the health layer reports it as uninspectable), which is the intended
/// trade-off: the live `Session` supplies the protected key at unlock time.
fn redact_profile_keys(body: &[u8]) -> Result<Vec<u8>, SyncCacheError> {
    let mut value: serde_json::Value = serde_json::from_slice(body)
        .map_err(|error| SyncCacheError::CacheRedact(crate::error::BoxedCause::new(error)))?;
    redact_secret_keys(&mut value);
    serde_json::to_vec(&value)
        .map_err(|error| SyncCacheError::CacheSerialize(crate::error::BoxedCause::new(error)))
}

/// The default cache file path.
///
/// The sync cache is disposable (it can be rebuilt from the server), so it
/// belongs under the platform cache directory rather than the config
/// directory. On Linux this is
/// `$XDG_CACHE_HOME/bitwarden-gpui-poc/sync-cache.json`, falling back to
/// `$HOME/.cache/bitwarden-gpui-poc/sync-cache.json` when `XDG_CACHE_HOME`
/// is unset. All new writes must use this path (see [`save_default`]).
pub fn default_path() -> Option<PathBuf> {
    dirs::cache_dir().map(|dir| dir.join("bitwarden-gpui-poc").join("sync-cache.json"))
}

/// The legacy cache path under the config directory, kept **read-only**.
///
/// Older releases stored the sync cache in `dirs::config_dir()`. A file left
/// there by such a release is still readable through [`load_default`] and
/// [`load_with_fallback`], so upgrading does not lose the offline cache. It
/// is never written to again: the legacy file is left untouched, and the next
/// write goes to [`default_path`] (see [`save_default`]), which then takes
/// precedence on subsequent reads. No automatic copy/move is performed on
/// read, so loading a cache has no filesystem side effects.
pub fn legacy_path() -> Option<PathBuf> {
    dirs::config_dir().map(|dir| dir.join("bitwarden-gpui-poc").join("sync-cache.json"))
}

/// Read a cache from `primary`, falling back to `fallback` only when the
/// primary file does not exist.
///
/// This is the read side of the cache-directory migration: the fallback is
/// purely for backward compatibility and is never copied, moved or rewritten.
/// A primary file that exists but is unreadable, malformed or outdated is
/// reported as-is instead of silently falling back to potentially stale
/// legacy data.
///
/// # Errors
///
/// [`CacheLoadError`] when neither location holds a usable cache.
pub fn load_with_fallback(
    primary: impl AsRef<std::path::Path>,
    fallback: impl AsRef<std::path::Path>,
) -> Result<SyncCache, CacheLoadError> {
    match load_detailed(primary) {
        Ok(cache) => Ok(cache),
        Err(CacheLoadError::NotFound) => load_detailed(fallback),
        Err(error) => Err(error),
    }
}

/// Read the cache from [`default_path`], falling back to the read-only
/// [`legacy_path`] when no cache-dir file exists yet.
///
/// This is the loader used by [`cached_sync_for_detailed`], so the offline
/// restore path also accepts a cache left in the legacy config directory.
/// The fallback is a pure read: no copy, move or rewrite is performed, and a
/// primary file that exists but is unreadable/stale never falls back.
///
/// # Errors
///
/// [`CacheLoadError`] when no usable cache exists, or when no platform
/// cache/config directory is available at all.
pub fn load_default() -> Result<SyncCache, CacheLoadError> {
    load_from_paths(default_path(), legacy_path())
}

/// Resolve the four location combinations of [`load_default`] without touching
/// the process-global XDG/HOME environment.
///
/// `dirs` falls back to the passwd database when `HOME` is unset, so a test
/// cannot reliably force `default_path()` / `legacy_path()` to return `None`
/// by editing environment variables. Keeping the branch on plain `Option`s
/// makes every combination directly testable.
fn load_from_paths(
    primary: Option<PathBuf>,
    fallback: Option<PathBuf>,
) -> Result<SyncCache, CacheLoadError> {
    match (primary, fallback) {
        (Some(primary), Some(fallback)) => load_with_fallback(primary, fallback),
        (Some(primary), None) => load_detailed(primary),
        (None, Some(fallback)) => load_detailed(fallback),
        (None, None) => Err(CacheLoadError::NotFound),
    }
}

/// Why a cache entry could not be loaded.
///
/// Alias of [`AppError`](crate::error::AppError); read and parse failures keep
/// the original `std::io::Error` / `serde_json::Error` in `Error::source()`.
pub type CacheLoadError = crate::error::AppError;

/// Read at most `limit + 1` bytes, rejecting anything larger.
///
/// The extra byte is what makes the post-`metadata` check effective against a
/// file that grows between the two reads (TOCTOU): the caller's earlier
/// `metadata.len()` check is only an optimization, not the security boundary.
fn read_bounded<R: Read>(reader: &mut R, limit: u64) -> Result<Vec<u8>, CacheLoadError> {
    let mut contents = Vec::new();
    reader
        .take(limit.saturating_add(1))
        .read_to_end(&mut contents)
        .map_err(|error| CacheLoadError::ReadFailedCause(crate::error::BoxedCause::new(error)))?;
    if contents.len() as u64 > limit {
        return Err(CacheLoadError::CacheTooLarge);
    }
    Ok(contents)
}

/// Read a cache entry, distinguishing missing, unreadable, malformed and
/// outdated files.
///
/// On Unix a file with group/other read or write bits is refused as unreadable:
/// the encrypted body must stay owner-only, matching the `private_file` policy
/// that every write applies. The size cap is checked first so an oversized
/// file keeps its `CacheTooLarge` classification.
///
/// # Errors
///
/// [`CacheLoadError`] when the file cannot be used as a cache.
pub fn load_detailed(path: impl AsRef<std::path::Path>) -> Result<SyncCache, CacheLoadError> {
    let mut file = std::fs::File::open(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            CacheLoadError::NotFound
        } else {
            CacheLoadError::ReadFailedCause(crate::error::BoxedCause::new(error))
        }
    })?;
    let metadata = file
        .metadata()
        .map_err(|error| CacheLoadError::ReadFailedCause(crate::error::BoxedCause::new(error)))?;
    if metadata.len() > MAX_CACHE_BYTES {
        return Err(CacheLoadError::CacheTooLarge);
    }
    // `write_private` creates cache files with 0600. A wider mode means the
    // file was written by an older build or provisioned out of band, so it is
    // not trusted with the encrypted body. `#[cfg(unix)]` keeps the check
    // portable: platforms without Unix permission bits skip it entirely.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode();
        if mode & 0o066 != 0 {
            return Err(CacheLoadError::ReadFailedCause(
                crate::error::BoxedCause::text(format!(
                    "キャッシュファイルの権限が安全ではありません（mode {mode:04o}）"
                )),
            ));
        }
    }
    // Read one byte past the limit so a file that grew after `metadata` is
    // still rejected without loading an unbounded body.
    let contents = read_bounded(&mut file, MAX_CACHE_BYTES)?;
    let cache: SyncCache = serde_json::from_slice(&contents)
        .map_err(|error| CacheLoadError::ParseFailedCause(crate::error::BoxedCause::new(error)))?;
    if cache.body.len() > MAX_CACHE_BODY_BYTES {
        return Err(CacheLoadError::CacheTooLarge);
    }
    if cache.version != SyncCache::VERSION {
        return Err(CacheLoadError::VersionMismatch);
    }
    Ok(cache)
}

/// Read a cache entry, returning `None` when missing or unreadable.
pub fn load(path: impl AsRef<std::path::Path>) -> Option<SyncCache> {
    load_detailed(path).ok()
}

/// Write a cache entry to an explicit path.
///
/// Callers should pass [`default_path`] (or use [`save_default`]) so that new
/// data is written under the cache directory. [`legacy_path`] must never be
/// used for writes: an old config-dir file is left in place and simply stops
/// being read once a cache-dir file exists.
///
/// A body larger than [`MAX_CACHE_BODY_BYTES`] is refused before any file is
/// touched, mirroring the read-side check in [`load_detailed`]: writing a body
/// this build would immediately reject on load can only waste disk space and
/// hide a runaway sync response. `save_default` inherits the same guard via
/// `save_to_path`.
///
/// # Errors
///
/// Returns `std::io::Error` on filesystem or serialization failure, with
/// [`std::io::ErrorKind::InvalidInput`] when the body exceeds
/// [`MAX_CACHE_BODY_BYTES`].
pub fn save(path: impl AsRef<std::path::Path>, cache: &SyncCache) -> Result<(), std::io::Error> {
    if cache.body.len() > MAX_CACHE_BODY_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "cache body of {} bytes exceeds MAX_CACHE_BODY_BYTES ({})",
                cache.body.len(),
                MAX_CACHE_BODY_BYTES
            ),
        ));
    }
    let path = path.as_ref();
    let contents = serde_json::to_vec_pretty(cache)?;
    crate::private_file::write_private(path, &contents)
}

/// Write a cache entry to [`default_path`] only.
///
/// This never creates or updates [`legacy_path`], enforcing the migration
/// policy: existing config-dir caches remain readable, but all new writes go
/// exclusively under the cache directory.
///
/// # Errors
///
/// Returns `std::io::Error` when no platform cache directory is available,
/// or on a filesystem/serialization failure.
pub fn save_default(cache: &SyncCache) -> Result<(), std::io::Error> {
    save_to_path(default_path(), cache)
}

/// Write through a resolved optional default path.
///
/// Keeping the "no platform cache directory" branch on a plain `Option`
/// mirrors `load_from_paths`: the real XDG/HOME environment cannot reliably be
/// changed inside a test, but the branch can be exercised directly with
/// `None`. Every filesystem failure still propagates through [`save`].
fn save_to_path(path: Option<PathBuf>, cache: &SyncCache) -> Result<(), std::io::Error> {
    let path = path.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no platform cache directory available",
        )
    })?;
    save(path, cache)
}

/// Load the encrypted cache for a best-effort offline restore.
///
/// The auth layer calls this when `/api/sync` fails but the API-key login has
/// already succeeded. Both the server URL and the caller's `user_id` must
/// match: a cache left by a different account on the same server is rejected
/// with [`SyncCacheError::UserMismatch`] instead of being restored. The id is
/// derived from the personal API key's `client_id` (`user.<uuid>`), which is
/// the trusted account identifier available on a failed-sync path; a plain
/// `client_id` without that prefix fails closed. [`validate`] applies the same
/// comparisons to a cache the caller already holds.
///
/// After parsing, the body's `Profile.Id` is compared with the envelope
/// `user_id` as well: a hand-edited cache whose envelope claims one account
/// while its body belongs to another is refused with
/// [`SyncCacheError::UserMismatch`]. The envelope alone is not proof of
/// ownership. A body without that field fails closed too — either its parse
/// fails or the resulting id cannot match a non-empty envelope.
///
/// Key material is never taken from the cache — its
/// `profile.key` / `privateKey` are stripped by [`SyncCache::from_body`] and
/// the live `Session` supplies the protected key at unlock time. A key change
/// since the cache was written can therefore leave cached items undecryptable.
///
/// Returns the classified failure so the caller can tell a missing cache from
/// a corrupt or outdated one instead of collapsing every case into `None`.
///
/// # Errors
///
/// [`SyncCacheError::NotFound`] when no cache file exists,
/// [`SyncCacheError::ReadFailedCause`] when it cannot be read,
/// [`SyncCacheError::ParseFailedCause`] / [`SyncCacheError::CacheParse`] when
/// the stored body is invalid, [`SyncCacheError::VersionMismatch`] when the
/// format changed, [`SyncCacheError::ServerMismatch`] when it belongs to
/// another server, [`SyncCacheError::UserMismatch`] when it belongs to another
/// account, and [`SyncCacheError::CacheRedact`] /
/// [`SyncCacheError::CacheSerialize`] when sanitizing the body fails.
pub fn cached_sync_for_detailed(
    server_url: &str,
    user_id: &str,
) -> Result<openwarden::SyncData, SyncCacheError> {
    let cache = load_default()?;
    if cache.server_url != server_url {
        return Err(SyncCacheError::ServerMismatch);
    }
    if cache.user_id != user_id {
        return Err(SyncCacheError::UserMismatch);
    }
    let now = i64::try_from(crate::totp::now_unix()).unwrap_or(i64::MAX);
    if is_cache_expired(cache.created_at, now) {
        return Err(SyncCacheError::CacheExpired);
    }
    let sync = cache.sync()?;
    if sync.user_id() != cache.user_id.as_str() {
        return Err(SyncCacheError::UserMismatch);
    }
    Ok(sync)
}

/// Best-effort wrapper around [`cached_sync_for_detailed`] for callers that
/// only need to know whether a usable cache was found. Both the server URL and
/// the account id are checked by the detailed entry point.
pub fn cached_sync_for(server_url: &str, user_id: &str) -> Option<openwarden::SyncData> {
    cached_sync_for_detailed(server_url, user_id).ok()
}

/// Validate the parts of a cache that do not need a filesystem read.
///
/// Both the server URL and `user_id` are compared with the stored values, and
/// the parsed body's `Profile.Id` is checked against the envelope `user_id`,
/// matching [`cached_sync_for_detailed`] so a caller that already holds a
/// cache cannot accept another account's entry by skipping the restore path.
/// The auth layer supplies the id derived from the personal API key's
/// `client_id`; callers without a trusted id must not use this helper.
///
/// Unlike [`cached_sync_for_detailed`], this helper deliberately does **not**
/// apply the [`MAX_CACHE_AGE_SECS`] expiry window: it checks an object the
/// caller already holds and never consults the clock. An outdated cache can
/// therefore pass `validate` while the restore path rejects it with
/// [`SyncCacheError::CacheExpired`] (see
/// `validate_does_not_apply_the_restore_expiry_window`). Callers that need
/// the restore's freshness guarantee must check `is_cache_expired` on
/// `cache.created_at` themselves.
///
/// # Errors
///
/// [`SyncCacheError::ServerMismatch`] when the server differs,
/// [`SyncCacheError::UserMismatch`] when the account differs, or a parse error
/// when the body cannot be read back.
pub fn validate(cache: &SyncCache, user_id: &str, server_url: &str) -> Result<(), SyncCacheError> {
    if cache.server_url != server_url {
        return Err(SyncCacheError::ServerMismatch);
    }
    if cache.user_id != user_id {
        return Err(SyncCacheError::UserMismatch);
    }
    let sync = cache.sync()?;
    if sync.user_id() != cache.user_id.as_str() {
        return Err(SyncCacheError::UserMismatch);
    }
    Ok(())
}

/// Reason strings shared by the cache layer and the auth status mapper.
pub(crate) const REASON_CORRUPT: &str = "キャッシュが破損しています";
pub(crate) const REASON_UNREADABLE: &str = "キャッシュを読み込めません";
pub(crate) const REASON_MISSING: &str = "キャッシュがありません";
pub(crate) const REASON_OUTDATED: &str = "キャッシュのバージョンに互換性がありません";
pub(crate) const REASON_EXPIRED: &str = "キャッシュが有効期限を過ぎています";
pub(crate) const REASON_USER_MISMATCH: &str = "キャッシュが別のアカウントのものです";
pub(crate) const REASON_SERVER_MISMATCH: &str = "キャッシュが別のサーバーのものです";
pub(crate) const REASON_TOO_LARGE: &str = "キャッシュがサイズ上限を超えています";

/// Full status text for a failed cache fallback, or `None` when the missing
/// cache is the normal first-launch case. Keeping these strings next to the
/// reason constants prevents the auth layer from duplicating them.
pub(crate) fn cache_restore_status(error: crate::error::AppError) -> Option<&'static str> {
    match cache_error_message(error) {
        REASON_MISSING => None,
        REASON_CORRUPT => Some("同期に失敗しました（キャッシュが破損しています）"),
        REASON_UNREADABLE => Some("同期に失敗しました（キャッシュを読み込めません）"),
        REASON_OUTDATED => Some("同期に失敗しました（キャッシュのバージョンに互換性がありません）"),
        REASON_EXPIRED => Some("同期に失敗しました（キャッシュが有効期限を過ぎています）"),
        REASON_USER_MISMATCH => Some("同期に失敗しました（キャッシュが別のアカウントのものです）"),
        REASON_SERVER_MISMATCH => Some("同期に失敗しました（キャッシュが別のサーバーのものです）"),
        REASON_TOO_LARGE => Some("同期に失敗しました（キャッシュがサイズ上限を超えています）"),
        _ => Some("同期に失敗しました（キャッシュを復元できませんでした）"),
    }
}

/// Map a cache error to a short reason for a status-bar message.
pub fn cache_error_message(error: SyncCacheError) -> &'static str {
    match error {
        SyncCacheError::InvalidCache
        | SyncCacheError::CacheParse(_)
        | SyncCacheError::CacheRedact(_)
        | SyncCacheError::CacheSerialize(_)
        | SyncCacheError::ParseFailed
        | SyncCacheError::ParseFailedCause(_) => REASON_CORRUPT,
        SyncCacheError::UserMismatch => REASON_USER_MISMATCH,
        SyncCacheError::ServerMismatch => REASON_SERVER_MISMATCH,
        SyncCacheError::NotFound => REASON_MISSING,
        SyncCacheError::ReadFailed | SyncCacheError::ReadFailedCause(_) => REASON_UNREADABLE,
        SyncCacheError::VersionMismatch => REASON_OUTDATED,
        SyncCacheError::CacheExpired => REASON_EXPIRED,
        SyncCacheError::CacheTooLarge => REASON_TOO_LARGE,
        SyncCacheError::Other(_) => crate::error::OTHER_ERROR_MESSAGE,
        // A future variant must never be reported as proven corruption.
        _ => crate::error::OTHER_ERROR_MESSAGE,
    }
}

#[cfg(test)]
#[path = "cache_tests.rs"]
mod tests;
