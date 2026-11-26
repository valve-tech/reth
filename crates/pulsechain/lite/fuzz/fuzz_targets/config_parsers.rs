//! The size and duration flags and the URL-file parser on arbitrary strings.
//!
//! * Each size flag reads any text as pulse-reth's `parse_byte_size` does, and that parser agrees
//!   with a reference written here from the README grammar: an optional `+`, ASCII digits, an
//!   optional space and an optional binary unit `B KB MB GB TB` in any case, refused when the value
//!   overflows a `usize`.
//! * Each duration flag reads any text as `humantime::parse_duration` does.
//! * Sizes and durations built from a number and a unit round-trip to that number times the unit,
//!   or are refused only when they overflow.
//! * A URL file is parsed in order or refused; a refusal names a kept line and never echoes the
//!   file's text, and every accepted URL is https or loopback with no fragment.
#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use reth_pulsechain_lite::{
    config::ConfigError,
    fuzz_api::{duration_flags, parse_url_text, size_flags},
};
use std::net::IpAddr;

const SIZE_UNITS: [(&str, usize); 6] =
    [("", 1), ("b", 1), ("kb", 1 << 10), ("mb", 1 << 20), ("gb", 1 << 30), ("tb", 1 << 40)];

/// The README size grammar, independently: `[+]<digits>[<space>][unit]`, trimmed.
fn reference_size(s: &str) -> Option<usize> {
    let s = s.trim();
    let s = s.strip_prefix('+').unwrap_or(s);
    let num_end = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (num, unit) = s.split_at(num_end);
    if num.is_empty() {
        return None;
    }
    let unit = unit.trim_start().to_ascii_lowercase();
    let mult = SIZE_UNITS.iter().find(|(u, _)| *u == unit)?.1;
    num.parse::<usize>().ok()?.checked_mul(mult)
}

#[derive(Debug, Arbitrary)]
struct Built {
    n: u64,
    unit: u8,
    upper: bool,
    space: bool,
    pad: bool,
    dur_unit: u8,
}

#[derive(Debug, Arbitrary)]
enum Line {
    Blank,
    Comment(String),
    Url { scheme: u8, host: u8, path: String, query: bool, fragment: bool },
    Any(String),
}

const MARK: &str = "SECRETfile";

impl Line {
    fn render(&self) -> String {
        match self {
            Self::Blank => String::new(),
            Self::Comment(s) => format!("#{s} {MARK}"),
            Self::Url { scheme, host, path, query, fragment } => {
                let scheme = ["https", "http", "ftp", "HTTPS"][usize::from(*scheme) % 4];
                let host = [
                    "a.example",
                    "127.0.0.1",
                    "localhost",
                    "[::1]",
                    "10.0.0.1",
                    "user:pw@b.example",
                    "LOCALHOST.",
                    "127.1",
                ][usize::from(*host) % 8];
                let path: String = path.chars().filter(|c| !c.is_whitespace()).take(12).collect();
                let mut s = format!("  {scheme}://{host}/{path}/{MARK} ");
                if *query {
                    s.push_str("?k=1");
                }
                if *fragment {
                    s.push_str("#f");
                }
                s
            }
            Self::Any(s) => format!("{s}{MARK}"),
        }
    }
}

#[derive(Debug, Arbitrary)]
struct Input {
    raw: String,
    built: Built,
    lines: Vec<Line>,
    crlf: bool,
}

fn sizes(input: &Input) {
    let want = reth_cli_util::parse_byte_size(&input.raw).ok();
    assert_eq!(want, reference_size(&input.raw), "parse_byte_size({:?})", input.raw);
    for got in size_flags(&input.raw) {
        assert_eq!(got, want, "size flag {:?}", input.raw);
    }

    let b = &input.built;
    let (unit, mult) = SIZE_UNITS[usize::from(b.unit) % SIZE_UNITS.len()];
    let unit = if b.upper { unit.to_ascii_uppercase() } else { unit.to_owned() };
    let sep = if b.space { " " } else { "" };
    let pad = if b.pad { " \t" } else { "" };
    let s = format!("{pad}{}{sep}{unit}{pad}", b.n);
    let want = usize::try_from(b.n).ok().and_then(|n| n.checked_mul(mult));
    for got in size_flags(&s) {
        assert_eq!(got, want, "{s:?}");
    }
}

fn durations(input: &Input) {
    let want = humantime::parse_duration(&input.raw).ok();
    for got in duration_flags(&input.raw) {
        assert_eq!(got, want, "duration flag {:?}", input.raw);
    }
    let b = &input.built;
    // humantime refuses a value when its `u64` count overflows: nanoseconds for `ms`, seconds
    // for `s`, `m` and `h`.
    let (unit, mult_ms, count) =
        [("ms", 1u128, 1_000_000u64), ("s", 1000, 1), ("m", 60_000, 60), ("h", 3_600_000, 3600)]
            [usize::from(b.dur_unit) % 4];
    let s = format!("{}{unit}", b.n);
    let want = b.n.checked_mul(count).map(|_| u128::from(b.n) * mult_ms);
    for got in duration_flags(&s) {
        assert_eq!(got.map(|d| d.as_millis()), want, "{s:?}");
    }
}

fn url_file(input: &Input) {
    let rendered: Vec<String> = input.lines.iter().take(8).map(Line::render).collect();
    let text = rendered.join(if input.crlf { "\r\n" } else { "\n" });
    let kept = |l: &str| !l.trim().is_empty() && !l.trim().starts_with('#');
    for raw in [text.as_str(), input.raw.as_str()] {
        // `str::lines` is what splits the file: compare against its view of the lines.
        let lines: Vec<&str> = raw.lines().collect();
        match parse_url_text(raw, "--beacon.url-file") {
            Ok(urls) => {
                assert_eq!(urls.len(), lines.iter().filter(|l| kept(l)).count());
                for u in &urls {
                    assert!(u.fragment().is_none(), "{u}");
                    let loopback = u.host_str().is_some_and(|h| {
                        h == "localhost" ||
                            h == "[::1]" ||
                            h.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
                    });
                    assert!(
                        matches!(u.scheme(), "https") || (u.scheme() == "http" && loopback),
                        "{u}"
                    );
                }
            }
            Err(err) => {
                let shown = format!("{err} {err:?}");
                assert!(!shown.contains(MARK), "an error echoed the file: {shown}");
                match err {
                    ConfigError::BadUrl { line, .. } |
                    ConfigError::UrlFragment { line, .. } |
                    ConfigError::InsecureUrl { line, .. } => {
                        let l = line.expect("a file error names its line");
                        assert!(l >= 1 && kept(lines[l - 1]), "line {l} of {raw:?}");
                    }
                    ConfigError::EmptyUrlFile { .. } => {
                        assert!(!lines.iter().any(|l| kept(l)));
                    }
                    other => panic!("unexpected {other:?}"),
                }
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(input) = Input::arbitrary(&mut Unstructured::new(data)) else { return };
    sizes(&input);
    durations(&input);
    url_file(&input);
});
