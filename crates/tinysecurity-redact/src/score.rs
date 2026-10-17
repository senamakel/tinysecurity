//! Scored prompt-injection screening: additive rule weights, normalized variants and
//! `Allow`/`Review`/`Block` tiers (contract 1.22).
//!
//! This is the scorer the host used to run itself, with its false-positive tuning
//! kept: recalled-memory transcripts that merely mention "system prompt" or a
//! "token push", the plural "tokens" of language-model text, and a colleague named
//! Dan. Weights are integers in thousandths so tiers never depend on float rounding.
//! Results provide context and never authorize execution.
use regex::{Regex, RegexSet};
use tinysecurity_bus::{
    Error, PROMPT_MAX_SCORE_MILLI2, PromptTier2, Result, ScanPromptScoredResponse2,
};

struct Rule {
    code: &'static str,
    score: u16,
    pattern: &'static str,
}

/// Extraction verb within three words of the hidden state it targets. A bare mention
/// of "system prompt" is not intent: transcripts and notes about building agents say
/// it constantly, and a recalled-memory block carries that text into later messages.
const EXFILTRATION_INTENT: &str = r"\b(reveal|show|print|dump|leak|display|repeat|output|expose)\s+(\S+\s+){0,3}(system\s+prompt|developer\s+instructions|hidden\s+prompt|internal\s+instructions)|\breveal\s+(\S+\s+){0,3}(system|hidden|developer|internal|prompts?|instructions?|rules?|secrets?)\b";

/// Weight of the obfuscated override heuristic. Above the review threshold on its own,
/// so spacing-obfuscated attacks ("i g n o r e   a l l ...") that the whitespace-bound
/// regex rule misses are still held for review.
const OBFUSCATED_OVERRIDE: u16 = 560;
/// Weight of the exfiltration-intent heuristic.
const EXFILTRATION: u16 = 240;

// Notes per rule, kept from the host detector that this replaces:
// - `exfiltrate.secrets` is a weak signal, a credential noun anywhere. Benign questions
//   ("how do I rotate my api key") carry it, so its weight stays far below review.
// - `exfiltrate.credentials_with_intent` needs an extraction verb, up to two filler
//   words, a determiner, then the noun. "show", "give", "tell", "fetch", "return" and
//   "output" are excluded verbs because benign technical questions use them constantly.
//   The noun ends at a word boundary and the plural "tokens" only counts with a
//   credential qualifier: "print the next 20 tokens" is a language-model task.
// - `override.role_hijack` needs a role after "you are now", and the DAN branches only
//   count with "unrestricted" or "no restrictions" within two words of "dan".
const RULES: &[Rule] = &[
    Rule {
        code: "override.ignore_previous",
        score: 440,
        pattern: r"(ignore|disregard|forget|bypass)\s+(all\s+)?(previous|prior|above|system)\s+(instructions|rules|constraints|prompts?)",
    },
    Rule {
        code: "override.role_hijack",
        score: 300,
        pattern: r"(you\s+are\s+now\s+(a|an|my|dan|free|unrestricted|unfiltered|uncensored|jailbroken|evil|no\s+longer|not\s+bound)\b|developer\s+mode|jailbreak|unrestricted\s+mode|(you\s+are|pretend\s+you\s+are|act\s+as)\s+dan\b|(no\s+restrictions|unrestricted)\s+(\S+\s+){0,2}dan\b|\bdan\b\s+(\S+\s+){0,2}(no\s+restrictions|unrestricted))",
    },
    Rule {
        code: "exfiltrate.system_prompt",
        score: 420,
        pattern: r"(reveal|show|print|dump|leak|display)\s+((the|your)\s+)?(system|developer|hidden)\s+(prompt|instructions|rules|message)",
    },
    Rule {
        code: "exfiltrate.secrets",
        score: 180,
        pattern: r"(api\s*key|secret|token|password|private\s+key|credentials?|session\s+cookie|jwt|bearer)",
    },
    Rule {
        code: "exfiltrate.credentials_with_intent",
        score: 460,
        pattern: r"(reveal|print|dump|leak|display|share|expose|exfiltrate)\s+(\S+\s+){0,2}(the|your|my|all|stored|active|internal|hidden|configured|saved|env|environment)\s+(\S+\s+){0,3}(api\s*keys?|secrets?|passwords?|private\s+keys?|credentials?|session\s+cookies?|jwts?|bearer|(access|auth|api|oauth|refresh|session|secret|csrf|login|account|stored|saved|configured|active|internal|hidden|env|environment)\s+tokens?|token)\b",
    },
    Rule {
        code: "tool.abuse",
        score: 300,
        pattern: r"(call|use|run|execute)\s+(the\s+)?(tool|tools?|function|functions?)\s+.*(without\s+approval|even\s+if\s+forbidden|no\s+matter\s+what)",
    },
];

/// Compiled scorer; immutable and shared.
pub(crate) struct Scorer {
    set: RegexSet,
    intent: Regex,
    base64: Regex,
    space: Regex,
}

struct Normalized {
    lowered: String,
    collapsed: String,
    compact: String,
    had_obfuscation: bool,
    has_base64: bool,
}

impl Scorer {
    pub(crate) fn new() -> Result<Self> {
        let compile = |p: &str| Regex::new(p).map_err(|_| Error::InvalidConfig);
        Ok(Self {
            set: RegexSet::new(RULES.iter().map(|r| r.pattern))
                .map_err(|_| Error::InvalidConfig)?,
            intent: compile(EXFILTRATION_INTENT)?,
            base64: compile(r"[A-Za-z0-9+/]{24,}={0,2}")?,
            space: compile(r"\s+")?,
        })
    }

    pub(crate) fn score(&self, input: &str) -> ScanPromptScoredResponse2 {
        let n = self.normalize(input);
        let has_override = n.collapsed.contains("ignore previous instructions")
            || n.collapsed.contains("ignore all previous instructions")
            || n.compact.contains("ignoreallpreviousinstructions")
            || n.compact.contains("ignorepreviousinstructions");
        let has_intent = self.intent.is_match(&n.collapsed);
        let mut score: u16 = 0;
        let mut rule_ids: Vec<String> = Vec::new();
        if has_override {
            score += OBFUSCATED_OVERRIDE;
            rule_ids.push("override.obfuscated_instruction".into());
        }
        if has_intent {
            score += EXFILTRATION;
            rule_ids.push("exfiltration.intent".into());
        }
        // Three batched passes, one per variant. The compact (whitespace-stripped)
        // variant matters: single-token branches (`jailbreak`, `jwt`, `secret`) carry no
        // `\s+`, so only the compact form catches a space-padded trigger word.
        let lowered = self.set.matches(&n.lowered);
        let collapsed = self.set.matches(&n.collapsed);
        let compact = self.set.matches(&n.compact);
        for (index, rule) in RULES.iter().enumerate() {
            if lowered.matched(index) || collapsed.matched(index) || compact.matched(index) {
                score += rule.score;
                rule_ids.push(rule.code.into());
            }
        }
        // Informational markers: reported, never scored. They are common in benign
        // content (identifiers, hashes, paths), so a weight would only add noise.
        if n.had_obfuscation {
            rule_ids.push("obfuscation.invisible_character".into());
        }
        if n.has_base64 {
            rule_ids.push("obfuscation.base64_run".into());
        }
        let score_milli = score.min(PROMPT_MAX_SCORE_MILLI2);
        ScanPromptScoredResponse2 {
            tier: PromptTier2::from_score_milli(score_milli),
            score_milli,
            rule_ids,
        }
    }

    fn normalize(&self, input: &str) -> Normalized {
        let lowered = input.to_lowercase();
        let has_base64 = self.base64.is_match(&lowered);
        let mut had_obfuscation = false;
        let mut buffer = String::with_capacity(lowered.len());
        for ch in lowered.chars() {
            let mapped = match ch {
                // Leet speak and Cyrillic confusables (the common UAX 39 set).
                '0' | '\u{043e}' => 'o',
                '1' | '\u{0456}' => 'i',
                '3' | '\u{0435}' => 'e',
                '4' | '@' | '\u{0430}' => 'a',
                '5' | '\u{0455}' => 's',
                '7' => 't',
                '8' => 'b',
                '6' => 'g',
                '\u{0440}' => 'p',
                '\u{0441}' => 'c',
                '\u{0443}' => 'y',
                '\u{0445}' => 'x',
                '\u{04bb}' => 'h',
                '\u{0501}' => 'd',
                ch if obfuscation_char(ch) => {
                    had_obfuscation = true;
                    continue;
                }
                // Fullwidth ASCII to plain ASCII (U+FF01..U+FF5E to U+0021..U+007E).
                '\u{ff01}'..='\u{ff5e}' => {
                    let ascii = char::from_u32(ch as u32 - 0xfee0).unwrap_or(' ');
                    buffer.extend(ascii.to_lowercase());
                    continue;
                }
                other if other.is_ascii_alphanumeric() || other.is_whitespace() => other,
                _ => ' ',
            };
            buffer.push(mapped);
        }
        let collapsed = self.space.replace_all(buffer.trim(), " ").into_owned();
        let compact: String = collapsed.chars().filter(|ch| !ch.is_whitespace()).collect();
        Normalized {
            lowered,
            collapsed,
            compact,
            had_obfuscation,
            has_base64,
        }
    }
}

/// Zero-width, bidirectional and formatting characters stripped during normalization.
fn obfuscation_char(ch: char) -> bool {
    matches!(
        ch,
        '\u{200b}'
            | '\u{200c}'
            | '\u{200d}'
            | '\u{2060}'
            | '\u{feff}'
            | '\u{00ad}'
            | '\u{034f}'
            | '\u{180e}'
            | '\u{200e}'
            | '\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2066}'..='\u{2069}'
    )
}

#[cfg(test)]
#[path = "score_tests.rs"]
mod tests;
