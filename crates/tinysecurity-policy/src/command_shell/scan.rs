//! Quote-aware scanning of a shell command *string*.
//!
//! These helpers are lexical only: they split a command on unquoted
//! separators, find unquoted control characters, blank quoted-heredoc bodies,
//! and normalise a command word. They decide nothing about whether a command
//! is safe; a host that gates execution builds its policy on top of them.
//! Every function is pure and none of them expands or evaluates anything.

use std::borrow::Cow;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QuoteState {
    None,
    Single,
    Double,
}

/// Split a shell command into sub-commands by unquoted separators.
///
/// Separators:
/// - `;` and newline
/// - `|`
/// - `&&`, `||`
///
/// Characters inside single or double quotes are treated as literals, so
/// `sqlite3 db "SELECT 1; SELECT 2;"` remains a single segment.
#[must_use]
pub(crate) fn split_unquoted_segments(command: &str) -> Vec<String> {
    let mut segments = Vec::new();
    let mut current = String::new();
    let mut quote = QuoteState::None;
    let mut escaped = false;
    let mut chars = command.chars().peekable();

    let push_segment = |segments: &mut Vec<String>, current: &mut String| {
        let trimmed = current.trim();
        if !trimmed.is_empty() {
            segments.push(trimmed.to_string());
        }
        current.clear();
    };

    while let Some(ch) = chars.next() {
        match quote {
            QuoteState::Single => {
                if ch == '\'' {
                    quote = QuoteState::None;
                }
                current.push(ch);
            }
            QuoteState::Double => {
                if escaped {
                    escaped = false;
                    current.push(ch);
                    continue;
                }
                if ch == '\\' {
                    escaped = true;
                    current.push(ch);
                    continue;
                }
                if ch == '"' {
                    quote = QuoteState::None;
                }
                current.push(ch);
            }
            QuoteState::None => {
                if escaped {
                    escaped = false;
                    current.push(ch);
                    continue;
                }
                if ch == '\\' {
                    escaped = true;
                    current.push(ch);
                    continue;
                }

                match ch {
                    '\'' => {
                        quote = QuoteState::Single;
                        current.push(ch);
                    }
                    '"' => {
                        quote = QuoteState::Double;
                        current.push(ch);
                    }
                    ';' | '\n' => push_segment(&mut segments, &mut current),
                    '|' => {
                        if chars.next_if_eq(&'|').is_some() {
                            // Consume full `||`; both characters are separators.
                        }
                        push_segment(&mut segments, &mut current);
                    }
                    '&' => {
                        if chars.next_if_eq(&'&').is_some() {
                            // `&&` is a separator; single `&` is handled separately.
                            push_segment(&mut segments, &mut current);
                        } else {
                            current.push(ch);
                        }
                    }
                    _ => current.push(ch),
                }
            }
        }
    }

    let trimmed = current.trim();
    if !trimmed.is_empty() {
        segments.push(trimmed.to_string());
    }

    segments
}

/// Detect a single unquoted `&` operator (background/chain). `&&` is allowed.
///
/// We treat any standalone `&` as unsafe in policy validation because it can
/// chain hidden sub-commands and escape foreground timeout expectations.
#[must_use]
pub(crate) fn contains_unquoted_single_ampersand(command: &str) -> bool {
    let mut quote = QuoteState::None;
    let mut escaped = false;
    let mut chars = command.chars().peekable();

    while let Some(ch) = chars.next() {
        match quote {
            QuoteState::Single => {
                if ch == '\'' {
                    quote = QuoteState::None;
                }
            }
            QuoteState::Double => {
                if escaped {
                    escaped = false;
                    continue;
                }
                if ch == '\\' {
                    escaped = true;
                    continue;
                }
                if ch == '"' {
                    quote = QuoteState::None;
                }
            }
            QuoteState::None => {
                if escaped {
                    escaped = false;
                    continue;
                }
                if ch == '\\' {
                    escaped = true;
                    continue;
                }
                match ch {
                    '\'' => quote = QuoteState::Single,
                    '"' => quote = QuoteState::Double,
                    '&' if chars.next_if_eq(&'&').is_none() => {
                        return true;
                    }
                    _ => {}
                }
            }
        }
    }

    false
}

/// Like [`contains_unquoted_single_ampersand`] but ignores file-descriptor
/// duplication redirects, where the `&` is part of a redirect operator rather
/// than a background/separator: `2>&1`, `>&2` (prev char `>`), and `&>file`
/// (next char `>`). Used by a hidden-execution guard so
/// a benign `… 2>&1` — which a classifier already accounts for as a
/// `Write` redirect — is not mistaken for a backgrounded command and
/// hard-blocked after the human approved it. A standalone `&` (e.g. `cmd &`,
/// `a & b`) still returns true, since it can run a second command
/// a classifier wouldn't see.
#[must_use]
pub(crate) fn contains_unquoted_background_ampersand(command: &str) -> bool {
    let mut quote = QuoteState::None;
    let mut escaped = false;
    let mut prev = '\0';
    let mut chars = command.chars().peekable();

    while let Some(ch) = chars.next() {
        match quote {
            QuoteState::Single => {
                if ch == '\'' {
                    quote = QuoteState::None;
                }
            }
            QuoteState::Double => {
                if escaped {
                    escaped = false;
                    prev = ch;
                    continue;
                }
                if ch == '\\' {
                    escaped = true;
                    prev = ch;
                    continue;
                }
                if ch == '"' {
                    quote = QuoteState::None;
                }
            }
            QuoteState::None => {
                if escaped {
                    escaped = false;
                    prev = ch;
                    continue;
                }
                if ch == '\\' {
                    escaped = true;
                    prev = ch;
                    continue;
                }
                match ch {
                    '\'' => quote = QuoteState::Single,
                    '"' => quote = QuoteState::Double,
                    '&' => {
                        if chars.next_if_eq(&'&').is_some() {
                            // `&&` logical AND — consume both, not background.
                        } else {
                            let next = chars.peek().copied().unwrap_or('\0');
                            // Skip fd-dup redirects: `2>&1`/`>&2` (prev `>`) and
                            // `&>file` (next `>`).
                            if prev != '>' && next != '>' {
                                return true;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        prev = ch;
    }

    false
}

/// Detect an unquoted character in a shell command.
#[must_use]
pub(crate) fn contains_unquoted_char(command: &str, target: char) -> bool {
    let mut quote = QuoteState::None;
    let mut escaped = false;

    for ch in command.chars() {
        match quote {
            QuoteState::Single => {
                if ch == '\'' {
                    quote = QuoteState::None;
                }
            }
            QuoteState::Double => {
                if escaped {
                    escaped = false;
                    continue;
                }
                if ch == '\\' {
                    escaped = true;
                    continue;
                }
                if ch == '"' {
                    quote = QuoteState::None;
                }
            }
            QuoteState::None => {
                if escaped {
                    escaped = false;
                    continue;
                }
                if ch == '\\' {
                    escaped = true;
                    continue;
                }
                match ch {
                    '\'' => quote = QuoteState::Single,
                    '"' => quote = QuoteState::Double,
                    _ if ch == target => return true,
                    _ => {}
                }
            }
        }
    }

    false
}

/// Blank out the body of every **quoted-delimiter** heredoc in `command`.
///
/// A command classifier and structural guards scan the raw command string, so
/// until now a heredoc body was read as live shell text. That is wrong for a
/// quoted delimiter: in `cat > f << 'EOF' … EOF` the shell performs no
/// expansion inside the body, so an `&`, a `` ` `` or a `$(` there is data.
/// Measured consequence : a recipe document was
/// refused as "background (&) is not allowed" because four dinner titles read
/// "Chicken & Spinach".
///
/// An **unquoted** delimiter (`<< EOF`) is deliberately left alone — expansion
/// *is* live inside that body, so `$(rm -rf ~)` there really would execute and
/// must keep tripping the guard. All delimiters on a command line are queued
/// in lexical order, including unquoted delimiters: each body ends only at its
/// own complete delimiter. Operators inside either kind of body are data.
///
/// Body lines are replaced by empty lines rather than removed, so line counts,
/// the surrounding command text and the `>` of the redirect are all preserved:
/// a heredoc write still classifies as a write and still
/// prompts. Returns [`Cow::Borrowed`] when the command has no quoted heredoc,
/// which is the overwhelmingly common case.
#[must_use]
pub(crate) fn strip_quoted_heredoc_bodies(command: &str) -> Cow<'_, str> {
    if !command.contains("<<") {
        return Cow::Borrowed(command);
    }

    let mut pending = std::collections::VecDeque::new();
    let mut out = String::with_capacity(command.len());
    let mut header = HeredocHeader {
        quote: QuoteState::None,
        token_boundary: true,
    };
    let mut reading_bodies = false;
    for line in command.split_inclusive('\n') {
        if reading_bodies && let Some((delim, strip_tabs, quoted)) = pending.front() {
            // Body text cannot introduce another redirect, even when it expands.
            let terminator = line.trim_end_matches('\n');
            // Expanded bodies remove backslash-newline before matching their
            // terminator. Without that expansion lexer, retain the whole input
            // rather than let a later command realign this queue accidentally.
            if !quoted
                && line.ends_with('\n')
                && terminator.chars().rev().take_while(|c| *c == '\\').count() % 2 == 1
            {
                return Cow::Borrowed(command);
            }
            let terminator = if *strip_tabs {
                terminator.trim_start_matches('\t')
            } else {
                terminator
            };
            if terminator == delim {
                pending.pop_front();
                out.push_str(line);
            } else if !quoted {
                out.push_str(line);
            } else if line.ends_with('\n') {
                out.push('\n');
            }
            reading_bodies = !pending.is_empty();
            continue;
        }
        out.push_str(line);
        let Some(logical_newline) = scan_heredoc_header(line, &mut header, &mut pending) else {
            return Cow::Borrowed(command);
        };
        reading_bodies = logical_newline && !pending.is_empty();
    }
    if out == command {
        Cow::Borrowed(command)
    } else {
        Cow::Owned(out)
    }
}

struct HeredocHeader {
    quote: QuoteState,
    token_boundary: bool,
}

// Physical lines can continue a word or quote. Only an unquoted, unescaped
// newline ends the command header and starts consuming its ordered bodies.
fn scan_heredoc_header(
    line: &str,
    header: &mut HeredocHeader,
    pending: &mut std::collections::VecDeque<(String, bool, bool)>,
) -> Option<bool> {
    let mut logical_newline = false;
    let mut chars = line.char_indices().peekable();
    while let Some((idx, ch)) = chars.next() {
        match header.quote {
            QuoteState::Single => {
                if ch == '\'' {
                    header.quote = QuoteState::None;
                }
            }
            QuoteState::Double => match ch {
                // POSIX double quotes escape only these characters. Consuming
                // a continued newline leaves the command and quote open.
                '\\' if chars
                    .peek()
                    .is_some_and(|(_, c)| matches!(c, '$' | '`' | '"' | '\\' | '\n')) =>
                {
                    chars.next();
                }
                '"' => header.quote = QuoteState::None,
                '`' => return None,
                '$' if chars.peek().is_some_and(|(_, c)| *c == '{') => {
                    return None;
                }
                '$' if chars.peek().is_some_and(|(_, c)| *c == '(')
                    && !skip_simple_substitution(&mut chars) =>
                {
                    return None;
                }
                _ => {}
            },
            QuoteState::None => match ch {
                '\\' => {
                    if let Some((_, next)) = chars.next() {
                        // Backslash-newline disappears before tokenization:
                        // neither a token boundary nor a body boundary.
                        if next != '\n' {
                            header.token_boundary = false;
                        }
                    }
                }
                '\'' => {
                    header.quote = QuoteState::Single;
                    header.token_boundary = false;
                }
                '"' => {
                    header.quote = QuoteState::Double;
                    header.token_boundary = false;
                }
                '#' if header.token_boundary => {
                    // Backslashes and quotes inside a comment are just data.
                    logical_newline = line.ends_with('\n') && !pending.is_empty();
                    header.token_boundary = true;
                    break;
                }
                '\n' => {
                    logical_newline = !pending.is_empty();
                    header.token_boundary = true;
                }
                '<' if chars.next_if(|(_, c)| *c == '<').is_some() => {
                    if chars.next_if(|(_, c)| *c == '<').is_some() {
                        header.token_boundary = true;
                        continue;
                    }
                    let rest = &line[idx + 2..];
                    let Some((delim, consumed, quoted)) = heredoc_delimiter(rest) else {
                        // Unsupported quote/expansion syntax cannot safely
                        // establish where any queued body ends.
                        return None;
                    };
                    pending.push_back((delim, rest.starts_with('-'), quoted));
                    for _ in 0..consumed {
                        chars.next();
                    }
                    header.token_boundary = false;
                }
                '`' => return None,
                '$' if chars
                    .peek()
                    .is_some_and(|(_, c)| matches!(c, '{' | '\'' | '"')) =>
                {
                    return None;
                }
                '$' if chars.peek().is_some_and(|(_, c)| *c == '(') => {
                    if !skip_simple_substitution(&mut chars) {
                        return None;
                    }
                    header.token_boundary = false;
                }
                _ => header.token_boundary = matches!(ch, ' ' | '\t') || ";&|<>()".contains(ch),
            },
        }
    }
    Some(logical_newline)
}

// Skip only a flat command substitution whose text cannot declare a heredoc or
// change quoting. Complex nested shell syntax stays visible in its entirety.
fn skip_simple_substitution(chars: &mut std::iter::Peekable<std::str::CharIndices<'_>>) -> bool {
    chars.next(); // Opening parenthesis, already inspected by the caller.
    for (_, ch) in chars.by_ref() {
        match ch {
            ')' => return true,
            '\n' | '\\' | '\'' | '"' | '`' | '$' | '<' | '(' | '#' => return false,
            _ => {}
        }
    }
    false
}

/// Parse a heredoc delimiter token immediately after `<<`, returning the
/// delimiter after complete quote removal and how many chars of `rest` it spans.
/// Any quoted or escaped part disables expansion, including concatenated runs
/// such as `'EO'"F"x`; optional `-` and whitespace precede the token.
/// The final flag records whether quoting disables body expansion.
fn heredoc_delimiter(rest: &str) -> Option<(String, usize, bool)> {
    let mut consumed = 0usize;
    let mut chars = rest.chars().peekable();

    if chars.peek() == Some(&'-') {
        chars.next();
        consumed += 1;
    }
    while chars.peek().is_some_and(|c| *c == ' ' || *c == '\t') {
        chars.next();
        consumed += 1;
    }

    let mut delim = String::new();
    let mut quote = QuoteState::None;
    let mut quoted = false;
    while let Some(c) = chars.next() {
        if quote == QuoteState::None && (matches!(c, ' ' | '\t' | '\n') || ";&|<>()".contains(c)) {
            break;
        }
        consumed += 1;
        match (quote, c) {
            (QuoteState::None, '$') if chars.peek().is_some_and(|c| matches!(c, '\'' | '"')) => {
                // ANSI-C and locale quotes require expansion beyond quote removal.
                return None;
            }
            (QuoteState::None, '\'') => {
                quote = QuoteState::Single;
                quoted = true;
            }
            (QuoteState::None, '"') => {
                quote = QuoteState::Double;
                quoted = true;
            }
            (QuoteState::Single, '\'') | (QuoteState::Double, '"') => quote = QuoteState::None,
            (QuoteState::None | QuoteState::Double, '\\') => {
                let next = chars.next()?;
                if next == '\n' {
                    return None;
                }
                consumed += 1;
                quoted = true;
                if quote == QuoteState::Double && !matches!(next, '$' | '`' | '"' | '\\' | '\n') {
                    delim.push('\\');
                }
                if next != '\n' {
                    delim.push(next);
                }
            }
            (_, '\n') => return None,
            _ => delim.push(c),
        }
    }
    (quote == QuoteState::None && !delim.is_empty()).then_some((delim, consumed, quoted))
}

/// The last path component of a command word, splitting on both `/` and `\`.
#[must_use]
pub(crate) fn command_basename(command: &str) -> &str {
    command.split(['/', '\\']).next_back().unwrap_or(command)
}

/// The lowercased basename of a command word with a trailing `.exe` removed.
#[must_use]
pub(crate) fn normalized_command_name(command: &str) -> String {
    let command = command_basename(command).to_ascii_lowercase();
    command
        .strip_suffix(".exe")
        .unwrap_or(command.as_str())
        .to_string()
}

/// Returns true if `s` starts with at least one inline env-var
/// assignment of the shape `NAME=...`, where `NAME` begins with an ASCII
/// letter or underscore. Matches any name, so `GIT_SSH=…`, `SSH_ASKPASS=…`, `LD_PRELOAD=…` and
/// `IFS=…` all count; deciding which of them are dangerous is the caller's job.
#[must_use]
pub(crate) fn has_leading_env_assignment(s: &str) -> bool {
    let Some(word) = s.split_whitespace().next() else {
        return false;
    };
    let Some((name, _value)) = word.split_once('=') else {
        return false;
    };
    if name.is_empty() {
        return false;
    }
    // Identifier shape: first char letter or `_`, the rest alphanumeric
    // or `_`. Anything else (e.g. `foo[bar]=`) is not a shell assignment.
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    if !chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return false;
    }
    true
}

/// Skip leading environment variable assignments (e.g. `FOO=bar cmd args`).
/// Returns the remainder starting at the first non-assignment word.
#[must_use]
pub(crate) fn skip_env_assignments(s: &str) -> &str {
    let mut rest = s;
    loop {
        let Some(word) = rest.split_whitespace().next() else {
            return rest;
        };
        // Environment assignment: contains '=' and starts with a letter or underscore
        if word.contains('=')
            && word
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        {
            // Advance past this word
            rest = rest[word.len()..].trim_start();
        } else {
            return rest;
        }
    }
}

/// Parse literal shell words without expansion or execution. Adjacent quoted
/// runs concatenate; POSIX escapes are decoded. Unquoted redirect operators
/// separate attached literal targets; quoted or escaped operators stay in the
/// word. Native Windows drive/UNC words
/// preserve backslashes, so a quoted executable path with spaces has one basename.
/// Unfinished quotes/escapes fail closed. This is lexical executable recognition,
/// not a promise that an executable is trusted or that dynamic expansion is safe.
pub(crate) fn command_words(command: &str) -> Option<Vec<String>> {
    parse_command_words(command, true)
}

/// Decode the POSIX representation produced by `native_command`.
pub(crate) fn encoded_command_words(command: &str) -> Option<Vec<String>> {
    parse_command_words(command, false)
}

fn parse_command_words(command: &str, preserve_windows: bool) -> Option<Vec<String>> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut active = false;
    let mut quote = QuoteState::None;
    let mut windows = false;
    let mut chars = command.char_indices().peekable();
    while let Some((offset, ch)) = chars.next() {
        if !active && !ch.is_whitespace() {
            let start = command[offset..].trim_start_matches(['\'', '"']);
            windows = preserve_windows
                && (start.as_bytes().get(1) == Some(&b':') || start.starts_with("\\\\"));
            active = true;
        }
        match (quote, ch) {
            (QuoteState::None, '\'') => quote = QuoteState::Single,
            (QuoteState::None, '"') => quote = QuoteState::Double,
            (QuoteState::Single, '\'') | (QuoteState::Double, '"') => quote = QuoteState::None,
            (QuoteState::None, '<' | '>') => {
                // Redirect operators are shell syntax even when attached to a
                // word. Quoted and escaped operator characters remain data.
                if active && !word.is_empty() {
                    words.push(std::mem::take(&mut word));
                }
                active = false;
            }
            (QuoteState::None, c) if c.is_whitespace() => {
                if active {
                    words.push(std::mem::take(&mut word));
                }
                active = false;
            }
            (QuoteState::None | QuoteState::Double, '\\') if !windows => {
                let (_, next) = chars.next()?;
                if quote == QuoteState::Double && !matches!(next, '$' | '`' | '"' | '\\' | '\n') {
                    word.push('\\');
                }
                if next != '\n' {
                    word.push(next);
                }
            }
            _ => word.push(ch),
        }
    }
    if quote != QuoteState::None {
        return None;
    }
    if active {
        words.push(word);
    }
    // Prefix assignment tokens never become the executable. Values can contain
    // spaces, quotes and '='; no environment values are read or expanded here.
    let prefix = words
        .iter()
        .take_while(|word| has_leading_env_assignment(word))
        .count();
    words.drain(..prefix);
    Some(words)
}

/// Translate native literal quoting to the POSIX lexical representation used by
/// the scanner. This never expands variables or evaluates executable expressions.
pub(crate) fn native_command(
    command: &str,
    dialect: tinysecurity_bus::ShellDialect,
) -> Cow<'_, str> {
    use tinysecurity_bus::ShellDialect;
    if dialect == ShellDialect::Posix {
        return Cow::Borrowed(command);
    }
    let mut out = String::with_capacity(command.len());
    let mut quote = QuoteState::None;
    let mut chars = command.chars().peekable();
    while let Some(c) = chars.next() {
        let escape = match dialect {
            ShellDialect::PowerShell => c == '`' && quote != QuoteState::Single,
            ShellDialect::Cmd => c == '^' && quote == QuoteState::None,
            ShellDialect::Posix => false,
        };
        if escape {
            if let Some(next) = chars.next() {
                // Encode a literal escaped native character without accidentally
                // turning it into a POSIX operator, quote or escape.
                if quote == QuoteState::None || matches!(next, '$' | '`' | '"' | '\\') {
                    out.push('\\');
                }
                out.push(next);
            } else {
                out.push('\\');
            }
            continue;
        }
        match (quote, c) {
            (QuoteState::None, '\'') if dialect == ShellDialect::PowerShell => {
                quote = QuoteState::Single;
            }
            (QuoteState::Single, '\'') => {
                if chars.next_if_eq(&'\'').is_some() {
                    out.push_str("'\\''");
                    continue;
                }
                quote = QuoteState::None;
            }
            (QuoteState::None, '"') => quote = QuoteState::Double,
            (QuoteState::Double, '"') => quote = QuoteState::None,
            (_, '\\') if quote != QuoteState::Single => out.push('\\'),
            (QuoteState::None, '\'') => out.push('\\'),
            _ => {}
        }
        out.push(c);
    }
    Cow::Owned(out)
}
