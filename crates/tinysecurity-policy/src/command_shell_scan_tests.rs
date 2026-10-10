use super::*;
// Tests for the quote-aware shell scanners.
//
// A host that gates command execution relies on these, so every case here is
// one such a host was found to depend on: quoting that must hide a separator,
// an escape that must not, and heredoc bodies that are data only when their
// delimiter is quoted.

use std::borrow::Cow;

use scan::{
    command_basename, contains_unquoted_background_ampersand, contains_unquoted_char,
    contains_unquoted_single_ampersand, has_leading_env_assignment, normalized_command_name,
    skip_env_assignments, split_unquoted_segments, strip_quoted_heredoc_bodies,
};

fn segs(command: &str) -> Vec<String> {
    split_unquoted_segments(command)
}

#[test]
fn splits_on_every_unquoted_separator() {
    assert_eq!(segs("a; b"), ["a", "b"]);
    assert_eq!(segs("a\nb"), ["a", "b"]);
    assert_eq!(segs("a | b"), ["a", "b"]);
    assert_eq!(segs("a && b"), ["a", "b"]);
    assert_eq!(segs("a || b"), ["a", "b"]);
    assert_eq!(segs("a && b || c; d | e"), ["a", "b", "c", "d", "e"]);
}

#[test]
fn quotes_hide_separators() {
    assert_eq!(
        segs(r#"sqlite3 db "SELECT 1; SELECT 2;""#),
        [r#"sqlite3 db "SELECT 1; SELECT 2;""#]
    );
    assert_eq!(segs("echo 'a | b && c'"), ["echo 'a | b && c'"]);
    assert_eq!(segs("echo 'a'; echo \"b\""), ["echo 'a'", "echo \"b\""]);
}

#[test]
fn backslash_escapes_a_separator_outside_and_inside_double_quotes() {
    assert_eq!(segs(r"echo a\; b"), [r"echo a\; b"]);
    assert_eq!(segs(r#"echo "a\"; b""#), [r#"echo "a\"; b""#]);
    // Inside single quotes a backslash is literal, so the quote still closes.
    assert_eq!(segs(r"echo 'a\'; b"), [r"echo 'a\'", "b"]);
}

#[test]
fn single_ampersand_stays_inside_its_segment() {
    assert_eq!(segs("a & b"), ["a & b"]);
    assert_eq!(segs("cmd 2>&1 && next"), ["cmd 2>&1", "next"]);
}

#[test]
fn empty_and_blank_segments_are_dropped() {
    assert_eq!(segs("").len(), 0);
    assert_eq!(segs("  ;  ;\n").len(), 0);
    assert_eq!(segs(";;a;;"), ["a"]);
}

#[test]
fn single_ampersand_detection() {
    assert!(contains_unquoted_single_ampersand("sleep 1 &"));
    assert!(contains_unquoted_single_ampersand("a & b"));
    assert!(!contains_unquoted_single_ampersand("a && b"));
    assert!(!contains_unquoted_single_ampersand("echo 'a & b'"));
    assert!(!contains_unquoted_single_ampersand(r#"echo "a & b""#));
    assert!(contains_unquoted_single_ampersand(r"echo \& &"));
    assert!(!contains_unquoted_single_ampersand(r"echo \&"));
    // The fd-dup redirect counts here; the background variant is the lenient one.
    assert!(contains_unquoted_single_ampersand("cmd 2>&1"));
}

#[test]
fn background_ampersand_ignores_fd_duplication() {
    assert!(!contains_unquoted_background_ampersand("cmd 2>&1"));
    assert!(!contains_unquoted_background_ampersand("cmd >&2"));
    assert!(!contains_unquoted_background_ampersand("cmd &>out.log"));
    assert!(!contains_unquoted_background_ampersand("a && b"));
    assert!(contains_unquoted_background_ampersand("cmd &"));
    assert!(contains_unquoted_background_ampersand("a & b"));
    assert!(contains_unquoted_background_ampersand("cmd 2>&1 &"));
    assert!(!contains_unquoted_background_ampersand("echo 'a & b'"));
    assert!(!contains_unquoted_background_ampersand(r#"echo "a & b""#));
    assert!(!contains_unquoted_background_ampersand(r"echo a\&b"));
}

#[test]
fn unquoted_char_detection() {
    assert!(contains_unquoted_char("echo hi > out", '>'));
    assert!(!contains_unquoted_char("echo '>'", '>'));
    assert!(!contains_unquoted_char(r#"echo ">""#, '>'));
    assert!(!contains_unquoted_char(r"echo \>", '>'));
    assert!(contains_unquoted_char(r#"echo "x" > f"#, '>'));
    assert!(contains_unquoted_char("a`b", '`'));
    assert!(!contains_unquoted_char("", '>'));
    // An escaped quote inside double quotes does not close them.
    assert!(!contains_unquoted_char(r#"echo "a\" > b""#, '>'));
}

const MEAL_PLAN: &str = "cat > out/meal_plan.md << 'EOF'\n\
                         # Dinners\n\
                         - Chicken & Spinach\n\
                         - `backtick` and $(subshell)\n\
                         EOF";

#[test]
fn quoted_heredoc_body_is_blanked_and_shape_preserved() {
    let out = strip_quoted_heredoc_bodies(MEAL_PLAN);
    assert_eq!(out, "cat > out/meal_plan.md << 'EOF'\n\n\n\nEOF");
    assert_eq!(out.lines().count(), MEAL_PLAN.lines().count());
    assert!(out.contains('>'));
}

#[test]
fn double_quoted_and_dash_delimiters_count_as_quoted() {
    let out = strip_quoted_heredoc_bodies("cat << \"END\"\na & b\nEND\n");
    assert_eq!(out, "cat << \"END\"\n\nEND\n");
    let out = strip_quoted_heredoc_bodies("cat <<-'END'\na & b\nEND");
    assert_eq!(out, "cat <<-'END'\n\nEND");
    let out = strip_quoted_heredoc_bodies("cat <<'END'\na & b\nEND");
    assert_eq!(out, "cat <<'END'\n\nEND");
}

#[test]
fn unquoted_heredoc_delimiter_is_left_alone() {
    let live = "cat > out/x.md << EOF\nhello $(rm -rf ~)\nEOF";
    assert!(matches!(
        strip_quoted_heredoc_bodies(live),
        Cow::Borrowed(_)
    ));
    let dash = "cat <<-EOF\n$(x)\nEOF";
    assert!(matches!(
        strip_quoted_heredoc_bodies(dash),
        Cow::Borrowed(_)
    ));
}

#[test]
fn here_string_is_not_a_heredoc() {
    let command = "cat <<< 'plain'\necho $(whoami)";
    assert!(matches!(
        strip_quoted_heredoc_bodies(command),
        Cow::Borrowed(_)
    ));
}

#[test]
fn commands_without_heredocs_are_borrowed() {
    assert!(matches!(
        strip_quoted_heredoc_bodies("ls -la"),
        Cow::Borrowed(_)
    ));
    // `<<` present but only inside quotes.
    assert!(matches!(
        strip_quoted_heredoc_bodies("echo '<< EOF'"),
        Cow::Borrowed(_)
    ));
    assert!(matches!(
        strip_quoted_heredoc_bodies(r#"echo "<<'EOF'""#),
        Cow::Borrowed(_)
    ));
}

#[test]
fn text_outside_the_heredoc_is_kept() {
    let command = "cat > out/$(whoami).md << 'EOF'\nplain text\nEOF\nrm -rf /tmp/x";
    let out = strip_quoted_heredoc_bodies(command);
    assert_eq!(out, "cat > out/$(whoami).md << 'EOF'\n\nEOF\nrm -rf /tmp/x");
}

#[test]
fn unterminated_heredoc_blanks_to_the_end() {
    let out = strip_quoted_heredoc_bodies("cat << 'EOF'\nbody & more\nstill body");
    assert_eq!(out, "cat << 'EOF'\n\n");
}

#[test]
fn delimiter_line_requires_exact_match() {
    let out = strip_quoted_heredoc_bodies("cat << 'EOF'\nEOF is not it\n  EOF  \nnext");
    assert_eq!(out, "cat << 'EOF'\n\n\n");
}

#[test]
fn empty_or_multiline_quoted_delimiter_is_not_a_heredoc() {
    assert!(matches!(
        strip_quoted_heredoc_bodies("cat << ''\nbody\n"),
        Cow::Borrowed(_)
    ));
    assert!(matches!(
        strip_quoted_heredoc_bodies("cat << 'EO\nF'\nbody\n"),
        Cow::Borrowed(_)
    ));
}

#[test]
fn basename_handles_both_separators() {
    assert_eq!(command_basename("/usr/bin/git"), "git");
    assert_eq!(command_basename(r"C:\Windows\System32\cmd.exe"), "cmd.exe");
    assert_eq!(command_basename("git"), "git");
    assert_eq!(command_basename(""), "");
    assert_eq!(command_basename("/bin/"), "");
}

#[test]
fn normalized_name_lowercases_and_strips_exe() {
    assert_eq!(normalized_command_name("/usr/bin/GIT"), "git");
    assert_eq!(
        normalized_command_name(r"C:\x\PowerShell.EXE"),
        "powershell"
    );
    assert_eq!(normalized_command_name("python3"), "python3");
    assert_eq!(normalized_command_name("a.exe.exe"), "a.exe");
}

#[test]
fn leading_env_assignment_shape() {
    assert!(has_leading_env_assignment("FOO=bar cmd"));
    assert!(has_leading_env_assignment("  _x1=1 cmd"));
    assert!(has_leading_env_assignment("LD_PRELOAD=/x ls"));
    assert!(has_leading_env_assignment("A= cmd"));
    assert!(!has_leading_env_assignment("cmd FOO=bar"));
    assert!(!has_leading_env_assignment("=bar cmd"));
    assert!(!has_leading_env_assignment("1A=b cmd"));
    assert!(!has_leading_env_assignment("foo[bar]=1 cmd"));
    assert!(!has_leading_env_assignment("git log"));
    assert!(!has_leading_env_assignment(""));
}

#[test]
fn skipping_env_assignments() {
    assert_eq!(skip_env_assignments("A=1 B=2 git log"), "git log");
    assert_eq!(skip_env_assignments("git log"), "git log");
    assert_eq!(skip_env_assignments("A=1"), "");
    assert_eq!(skip_env_assignments(""), "");
    // `=` in a non-identifier word is a command, not an assignment.
    assert_eq!(skip_env_assignments("1A=b cmd"), "1A=b cmd");
    // The assignment filter is intentionally looser than the shape check.
    assert_eq!(skip_env_assignments("foo[bar]=1 cmd"), "cmd");
}

#[test]
fn concatenated_and_escaped_delimiters_use_complete_quote_removal() {
    for token in ["'EO'\"F\"x", "E'O'F\\x", "\\EOFx", "'EOF'x"] {
        let command = format!("cat <<{token}\nbody ~/.ssh/id_rsa $(touch x)\nEOFx\ntouch after");
        assert_eq!(
            strip_quoted_heredoc_bodies(&command),
            format!("cat <<{token}\n\nEOFx\ntouch after")
        );
    }
    assert!(strip_quoted_heredoc_bodies("cat <<'unfinished\nbody").contains("body"));
    assert_eq!(
        strip_quoted_heredoc_bodies("cat <<'EOF'\n\tEOF\nEOF\nls"),
        "cat <<'EOF'\n\nEOF\nls"
    );
    assert_eq!(
        strip_quoted_heredoc_bodies("cat <<-'EOF'\nbody\n\tEOF\nls"),
        "cat <<-'EOF'\n\n\tEOF\nls"
    );
}

#[test]
fn native_shell_literals_round_trip_through_the_lexical_representation() {
    use scan::{encoded_command_words, native_command};
    use tinysecurity_bus::ShellDialect;
    for (dialect, source, expected) in [
        (
            ShellDialect::PowerShell,
            "echo 'it''s (data)'",
            "it's (data)",
        ),
        (ShellDialect::PowerShell, "echo \"(data)\"", "(data)"),
        (ShellDialect::PowerShell, "echo `(data`)", "(data)"),
        (ShellDialect::PowerShell, "echo \"a`\"b\"", "a\"b"),
        (
            ShellDialect::PowerShell,
            "echo 'C:\\ordinary'",
            "C:\\ordinary",
        ),
        (ShellDialect::Cmd, "echo 'literal'", "'literal'"),
        (ShellDialect::Cmd, "echo ^(data^)", "(data)"),
        (ShellDialect::Cmd, "echo \"a^b\"", "a^b"),
    ] {
        let encoded = native_command(source, dialect);
        assert_eq!(
            encoded_command_words(&encoded),
            Some(vec!["echo".into(), expected.into()])
        );
    }
    assert_eq!(
        encoded_command_words(&native_command("echo trailing^", ShellDialect::Cmd)),
        None
    );
    assert_eq!(
        native_command("echo ordinary", ShellDialect::Posix),
        "echo ordinary"
    );
}

#[test]
fn literal_nested_heredoc_operator_never_blanks_following_execution() {
    let command = "cat <<'EOF'\ncat <<'NESTED'\nEOF\ncat ~/.ssh/id_rsa\nNESTED";
    assert_eq!(
        strip_quoted_heredoc_bodies(command),
        "cat <<'EOF'\n\nEOF\ncat ~/.ssh/id_rsa\nNESTED"
    );
}

#[test]
fn unsupported_delimiter_expansions_are_never_blanked() {
    for command in [
        "cat <<$'EOF'\nbody\nEOF\ncat ~/.ssh/id_rsa",
        "cat <<$\"EOF\"\nbody\nEOF\ntouch after",
        "cat <<E\\\nOF\n$(touch proof)\nEOF",
    ] {
        assert_eq!(strip_quoted_heredoc_bodies(command), command);
    }
}

#[test]
fn mixed_heredocs_follow_lexical_order_without_parsing_body_operators() {
    for (command, expected) in [
        (
            "cat <<A <<'B'\nlive <<'fake'\nA\ndata\nB\ntouch after",
            "cat <<A <<'B'\nlive <<'fake'\nA\n\nB\ntouch after",
        ),
        (
            "cat <<'A' <<B\ndata\nA\nlive <<'fake'\nB\ntouch after",
            "cat <<'A' <<B\n\nA\nlive <<'fake'\nB\ntouch after",
        ),
        (
            "cat <<-'A' <<-B\n\tdata\n\tA\n\tlive\n\tB\ntouch after",
            "cat <<-'A' <<-B\n\n\tA\n\tlive\n\tB\ntouch after",
        ),
        (
            "cat <<'A'x <<B\ndata\nA\nstill data\nAx\nlive\nB",
            "cat <<'A'x <<B\n\n\n\nAx\nlive\nB",
        ),
    ] {
        assert_eq!(strip_quoted_heredoc_bodies(command), expected);
    }
}

#[test]
fn comments_never_declare_heredocs() {
    for command in [
        "echo ok # <<'EOF'\ntouch review-proof",
        "echo ok;# <<'EOF'\ncat ~/.ssh/id_rsa",
        "echo ok # ignored \\\ntouch review-proof",
    ] {
        assert_eq!(strip_quoted_heredoc_bodies(command), command);
    }
    for prefix in [
        "echo '#'",
        "echo \\#",
        "echo word#",
        "echo ''#",
        "echo \\ #",
    ] {
        let command = format!("{prefix} <<'EOF'\nliteral\nEOF\ntouch after");
        assert_eq!(
            strip_quoted_heredoc_bodies(&command),
            format!("{prefix} <<'EOF'\n\nEOF\ntouch after")
        );
    }
}

#[test]
fn heredoc_bodies_wait_for_the_logical_unquoted_newline() {
    for header in [
        "cat <<'EOF' \\\n~/.ssh/id_rsa",
        "cat <<'EOF' \\\n\\\n~/.ssh/id_rsa",
        "cat <<'EOF' \\\n'~/.ssh/id_rsa'",
        "cat <<'EOF' \\\n\"~/.ssh/id_rsa\"",
        "cat <<'EOF' \"continued\n~/.ssh/id_rsa\"",
        "cat <<'EOF' \"continued\\\n~/.ssh/id_rsa\"",
        "cat <<'EOF' 'literal\\\n~/.ssh/id_rsa'",
    ] {
        let command = format!("{header}\nbody\nEOF\ntouch after");
        assert_eq!(
            strip_quoted_heredoc_bodies(&command),
            format!("{header}\n\nEOF\ntouch after")
        );
    }
    let command = "cat <<'A' \\\n<<B <<-'C'x # <<'fake'\nquoted\nA\nlive <<'nested'\nB\n\tquoted\n\tCx\ntouch after";
    assert_eq!(
        strip_quoted_heredoc_bodies(command),
        "cat <<'A' \\\n<<B <<-'C'x # <<'fake'\n\nA\nlive <<'nested'\nB\n\n\tCx\ntouch after"
    );
}

#[test]
fn unsupported_header_syntax_preserves_all_command_text() {
    for header in [
        "cat <<'A' <<$'B'",
        "cat <<'A' <<E\\\nOF",
        "cat <<'A' <<'unfinished",
        "cat <<'A' $(echo <<'NESTED')",
        "cat <<'A' \"$(echo <<'NESTED')\"",
        "cat <<'A' $(unfinished",
        "cat <<'A' $(echo safe # ) <<'fake')",
        "cat <<'A' `echo literal`",
        "cat <<'A' \"`echo literal`\"",
        "cat <<'A' ${value:-<<'NESTED'}",
        "cat <<'A' \"${value:-<<'NESTED'}\"",
        "cat <<'A' $'literal'",
    ] {
        let command = format!("{header}\ncat ~/.ssh/id_rsa\nA\ntouch after");
        assert_eq!(strip_quoted_heredoc_bodies(&command), command);
    }
    let command = "cat <<'A' \"$(echo safe)\"\nbody\nA";
    assert_eq!(
        strip_quoted_heredoc_bodies(command),
        "cat <<'A' \"$(echo safe)\"\n\nA"
    );
}

#[test]
fn comment_boundaries_survive_line_continuation_and_literal_backslashes() {
    for (command, expected) in [
        ("echo word\\\n# <<'A'\nbody\nA", "echo word\\\n# <<'A'\n\nA"),
        (
            "echo \\\n# <<'A'\ncat ~/.ssh/id_rsa",
            "echo \\\n# <<'A'\ncat ~/.ssh/id_rsa",
        ),
        ("cat <<'A' \\\\\nbody\nA", "cat <<'A' \\\\\n\nA"),
        (
            "cat <<'A' \"literal\\x\"\nbody\nA",
            "cat <<'A' \"literal\\x\"\n\nA",
        ),
        (
            "cat <<'A' # comment \\\nbody\nA",
            "cat <<'A' # comment \\\n\nA",
        ),
    ] {
        assert_eq!(strip_quoted_heredoc_bodies(command), expected);
    }
}
