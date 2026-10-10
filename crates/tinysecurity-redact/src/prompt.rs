//! Semantic prompt intent, independent of protocol sanitation and package admission.
use regex::Regex;
use tinysecurity_bus::{Error, Result, ScanResponse, ScanVerdict};
use unicode_normalization::UnicodeNormalization;
pub(crate) struct Scanner {
    rules: Vec<(&'static str, Regex, bool)>,
}
impl Scanner {
    pub(crate) fn new() -> Result<Self> {
        let rules = [
            (
                "override.instructions",
                r"\b(ignore|disregard|forget|bypass)\s+(all\s+)?(previous|prior|above|system)\s+(instructions|rules|constraints|prompts?)\b",
                false,
            ),
            (
                "override.role",
                r"\b(developer mode|jailbreak|unrestricted mode|you are now (a|an|dan|unrestricted|unfiltered|uncensored)|act as dan)\b",
                false,
            ),
            (
                "exfiltrate.hidden_prompt",
                r"\b(reveal|show|print|dump|leak|display|expose)\s+((the|your)\s+)?(system|developer|hidden|internal)\s+(prompt|instructions|rules|message)\b",
                true,
            ),
            (
                "exfiltrate.credentials",
                r"\b(reveal|print|dump|leak|display|share|expose|exfiltrate)\s+(\S+\s+){0,2}(the|your|my|all|stored|active|internal|hidden|configured|saved|env|environment)\s+(\S+\s+){0,3}(api\s*keys?|secrets?|passwords?|private\s+keys?|credentials?|session\s+cookies?|jwts?|bearer|(access|auth|api|oauth|refresh|session|stored|saved)\s+tokens?|token)\b",
                true,
            ),
            (
                "tool.approval_bypass",
                r"\b(call|use|run|execute)\s+(the\s+)?(tool|tools|function|functions)\b.{0,256}\b(without approval|even if forbidden|no matter what)\b",
                true,
            ),
        ];
        Ok(Self {
            rules: rules
                .into_iter()
                .map(|(id, p, blocked)| {
                    Regex::new(p)
                        .map(|r| (id, r, blocked))
                        .map_err(|_| Error::InvalidConfig)
                })
                .collect::<Result<_>>()?,
        })
    }
    pub(crate) fn scan(&self, text: &str) -> ScanResponse {
        let mut result = ScanResponse {
            verdict: ScanVerdict::Clean,
            rule_ids: vec![],
        };
        if text.chars().any(invisible) {
            result.verdict = ScanVerdict::Blocked;
            result.rule_ids.push("content.invisible_control".into());
        }
        let normalized = normalize(text);
        for (id, pattern, blocked) in &self.rules {
            if pattern.is_match(&normalized) {
                result.rule_ids.push((*id).into());
                if *blocked {
                    result.verdict = ScanVerdict::Blocked;
                } else if result.verdict == ScanVerdict::Clean {
                    result.verdict = ScanVerdict::Suspicious;
                }
            }
        }
        let compact: String = normalized.chars().filter(|c| !c.is_whitespace()).collect();
        if [
            "ignorepreviousinstructions",
            "ignoreallpreviousinstructions",
        ]
        .iter()
        .any(|s| compact.contains(s))
            && !result.rule_ids.iter().any(|s| s == "override.instructions")
        {
            result
                .rule_ids
                .push("override.obfuscated_instructions".into());
            if result.verdict == ScanVerdict::Clean {
                result.verdict = ScanVerdict::Suspicious;
            }
        }
        result.rule_ids.sort();
        result
    }
}
fn invisible(c: char) -> bool {
    matches!(c,'\u{200b}'..='\u{200f}'|'\u{2060}'|'\u{feff}'|'\u{00ad}'|'\u{034f}'|'\u{180e}'|'\u{202a}'..='\u{202e}'|'\u{2066}'..='\u{2069}')
        || (c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
}
fn normalize(text: &str) -> String {
    text.nfkc()
        .flat_map(char::to_lowercase)
        .filter(|c| !invisible(*c))
        .map(|c| match c {
            '0' | 'о' => 'o',
            '1' | 'і' => 'i',
            '3' | 'е' => 'e',
            '4' | '@' | 'а' => 'a',
            '5' | 'ѕ' => 's',
            '7' => 't',
            '8' => 'b',
            '6' => 'g',
            'р' => 'p',
            'с' => 'c',
            'у' => 'y',
            'х' => 'x',
            'һ' => 'h',
            'ԁ' => 'd',
            c if c.is_alphanumeric() || c.is_whitespace() => c,
            _ => ' ',
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}
pub(crate) fn merge(target: &mut ScanResponse, other: ScanResponse) {
    if other.verdict == ScanVerdict::Blocked
        || (other.verdict == ScanVerdict::Suspicious && target.verdict == ScanVerdict::Clean)
    {
        target.verdict = other.verdict;
    }
    target.rule_ids.extend(other.rule_ids);
}
#[cfg(test)]
#[path = "prompt_tests.rs"]
mod tests;
