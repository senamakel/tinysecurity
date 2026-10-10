//! Fixed linear-time patterns and validated identifiers; registry contents stay private.
use crate::{MARKER, output_bounded};
use regex::Regex;
use tinysecurity_bus::{Error, RedactorConfig, Result};
pub(crate) struct Patterns {
    literal: Option<Regex>,
    rules: Vec<(Regex, Validator)>,
    assignment: Regex,
    home: Regex,
    endpoint: Regex,
}
#[derive(Clone, Copy)]
enum Validator {
    Always,
    Card,
    Iban,
    NationalId,
    Ip,
    Phone,
}
impl Patterns {
    pub(crate) fn new(config: &RedactorConfig) -> Result<Self> {
        let mut secrets: Vec<_> = config.secrets.iter().map(|s| s.0.as_str()).collect();
        if secrets.len() > 128
            || secrets.iter().map(|s| s.len()).sum::<usize>() > 16_384
            || secrets.iter().any(|s| {
                !(4..=4096).contains(&s.len())
                    || [
                        MARKER,
                        "<HOME>",
                        "<redacted: string",
                        "<redacted: array",
                        "<redacted: object",
                        "<redacted: number>",
                        "<redacted: bool>",
                    ]
                    .iter()
                    .any(|marker| marker.contains(*s))
                    || marker_collision(s)
            })
        {
            return Err(Error::InvalidConfig);
        }
        secrets.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
        secrets.dedup();
        let literal = if secrets.is_empty() {
            None
        } else {
            Some(compile(
                &secrets
                    .iter()
                    .map(|s| regex::escape(s))
                    .collect::<Vec<_>>()
                    .join("|"),
            )?)
        };
        let definitions = [
            (
                r"\b(?:sk-(?:ant-|admin-|proj-|org-)?[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]{16,}|AKIA[A-Z0-9]{16})\b",
                Validator::Always,
            ),
            (
                r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
                Validator::Always,
            ),
            (
                r"(?s)-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?(?:-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|$)",
                Validator::Always,
            ),
            (
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
                Validator::Always,
            ),
            (
                r"\b[0-9]{3}[- ][0-9]{2}[- ][0-9]{4}\b",
                Validator::NationalId,
            ),
            (r"\b[0-9](?:[ -]?[0-9]){12,18}\b", Validator::Card),
            (r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}\b", Validator::Iban),
            (r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", Validator::Ip),
            (
                r"(?:\+1[-. ]?)?\(?[0-9]{3}\)?[-. ][0-9]{3}[-. ][0-9]{4}\b|\+[0-9](?:[0-9 -]{6,16}[0-9])",
                Validator::Phone,
            ),
            (
                r"(?i)\b[0-9]{1,6}\s+[A-Za-z0-9.' -]{2,40}?\b(?:street|st|avenue|ave|road|rd|boulevard|blvd|lane|ln|drive|dr|court|ct|way|place|pl|terrace|ter|circle|cir|highway|hwy)\b",
                Validator::Always,
            ),
        ];
        Ok(Self {
            literal,
            rules: definitions
                .into_iter()
                .map(|(p, v)| compile(p).map(|r| (r, v)))
                .collect::<Result<_>>()?,
            assignment: compile(
                r#"(?i)\b(bearer[ \t]+|(?:api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|authorization|password|secret|token)["']?[ \t]*[=:][ \t]*)(?:\[REDACTED\]|"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;\}\]]+)"#,
            )?,
            home: compile(r#"(?i)(?:/(?:home|users)/|[a-z]:[\\/]+users[\\/]+)[^\\/\s"'<>]+"#)?,
            endpoint: compile(r#"[a-zA-Z][a-zA-Z0-9+.-]*://[^\s"'<>]+"#)?,
        })
    }
    pub(crate) fn literal(&self, text: &str) -> String {
        self.literal.as_ref().map_or_else(
            || text.into(),
            |r| r.replace_all(text, regex::NoExpand(MARKER)).into_owned(),
        )
    }
    pub(crate) fn text(&self, text: &str) -> Result<String> {
        let mut out = self.literal(text);
        out = self
            .assignment
            .replace_all(&out, |caps: &regex::Captures<'_>| {
                format!("{}{MARKER}", &caps[1])
            })
            .into_owned();
        output_bounded(&out)?;
        out = self
            .endpoint
            .replace_all(&out, |caps: &regex::Captures<'_>| {
                url::Url::parse(&caps[0])
                    .ok()
                    .and_then(|mut u| {
                        u.host_str()?;
                        u.set_username("").ok()?;
                        u.set_password(None).ok()?;
                        u.set_query(None);
                        u.set_fragment(None);
                        Some(u.to_string().trim_end_matches('/').to_owned())
                    })
                    .unwrap_or_else(|| MARKER.into())
            })
            .into_owned();
        out = self.home.replace_all(&out, "<HOME>").into_owned();
        for (regex, validator) in &self.rules {
            out = regex
                .replace_all(&out, |caps: &regex::Captures<'_>| {
                    if validator.valid(&caps[0]) {
                        MARKER.into()
                    } else {
                        caps[0].to_string()
                    }
                })
                .into_owned();
            output_bounded(&out)?;
        }
        Ok(out)
    }
}
fn marker_collision(secret: &str) -> bool {
    let skeleton: String = secret.chars().filter(|c| !c.is_ascii_digit()).collect();
    if skeleton.is_empty() {
        return secret.len() <= 6;
    }
    [
        "<redacted: string ( chars)>",
        "<redacted: array ( items)>",
        "<redacted: object ( keys)>",
    ]
    .iter()
    .any(|marker| marker.contains(&skeleton))
}
fn compile(pattern: &str) -> Result<Regex> {
    Regex::new(pattern).map_err(|_| Error::InvalidConfig)
}
impl Validator {
    fn valid(self, text: &str) -> bool {
        match self {
            Self::Always => true,
            Self::Ip => text.parse::<std::net::Ipv4Addr>().is_ok(),
            Self::NationalId => {
                let digits: String = text.chars().filter(char::is_ascii_digit).collect();
                !matches!(&digits[..3], "000" | "666")
                    && !digits.starts_with('9')
                    && &digits[3..5] != "00"
                    && &digits[5..] != "0000"
            }
            Self::Phone => (7..=15).contains(&text.bytes().filter(u8::is_ascii_digit).count()),
            Self::Card => {
                let digits: Vec<_> = text
                    .bytes()
                    .filter(u8::is_ascii_digit)
                    .map(|b| b - b'0')
                    .collect();
                (13..=19).contains(&digits.len())
                    && (matches!(digits.first(), Some(3..=6))
                        || (digits.first() == Some(&2)
                            && digits.get(1).is_some_and(|d| (2..=7).contains(d))))
                    && digits
                        .iter()
                        .rev()
                        .enumerate()
                        .map(|(i, &d)| {
                            let n = u32::from(d) * if i % 2 == 1 { 2 } else { 1 };
                            if n > 9 { n - 9 } else { n }
                        })
                        .sum::<u32>()
                        % 10
                        == 0
            }
            Self::Iban => {
                let mut remainder = 0u32;
                for b in text.bytes().skip(4).chain(text.bytes().take(4)) {
                    let n = if b.is_ascii_digit() {
                        u32::from(b - b'0')
                    } else {
                        u32::from(b - b'A') + 10
                    };
                    remainder = (remainder * if n < 10 { 10 } else { 100 } + n) % 97;
                }
                remainder == 1
            }
        }
    }
}
#[cfg(test)]
#[path = "patterns_tests.rs"]
mod tests;
