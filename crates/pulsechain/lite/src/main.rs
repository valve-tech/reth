//! The `reth-lite` binary.

use reth_pulsechain_lite::{config::LiteArgs, metrics::LiteMetrics, node};
use std::process::ExitCode;

fn main() -> ExitCode {
    // Logging first: reading a URL file can warn. clap refuses an unknown flag or value with
    // exit code 2; into_config refuses the rest.
    node::init_logging();
    let cfg = match LiteArgs::parse_redacted().into_config() {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("reth-lite: {}", redact_urls(&err.to_string()));
            return ExitCode::FAILURE;
        }
    };
    let rt =
        match tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build() {
            Ok(rt) => rt,
            Err(err) => {
                eprintln!("reth-lite: cannot start the async runtime: {err}");
                return ExitCode::FAILURE;
            }
        };
    rt.block_on(async move {
        if let Err(err) = node::install_prometheus(cfg.metrics_addr) {
            eprintln!("reth-lite: cannot serve metrics: {err}");
            return ExitCode::FAILURE;
        }
        let metrics = LiteMetrics::new();
        let signals = match forward_signals() {
            Ok(signals) => signals,
            Err(err) => {
                eprintln!("reth-lite: cannot listen for signals: {err}");
                return ExitCode::FAILURE;
            }
        };
        match node::run(cfg, metrics, signals).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("reth-lite: {err}");
                ExitCode::FAILURE
            }
        }
    })
}

/// Sends one message for each SIGINT or SIGTERM. The handlers stay installed for the whole run,
/// so a second signal reaches the node while it saves its cache.
fn forward_signals() -> std::io::Result<tokio::sync::mpsc::Receiver<()>> {
    let (tx, rx) = tokio::sync::mpsc::channel(2);
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let (mut int, mut term) =
            (signal(SignalKind::interrupt())?, signal(SignalKind::terminate())?);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    Some(()) = int.recv() => {}
                    Some(()) = term.recv() => {}
                    else => return,
                }
                if tx.send(()).await.is_err() {
                    return;
                }
            }
        });
    }
    #[cfg(not(unix))]
    tokio::spawn(async move {
        while tokio::signal::ctrl_c().await.is_ok() {
            if tx.send(()).await.is_err() {
                return;
            }
        }
    });
    Ok(rx)
}

/// `text` with every word holding `://` replaced. A beacon URL may carry a key, and clap or a
/// URL-file error echoes a URL the operator put in the wrong place. Words end at whitespace and
/// quotes.
fn redact_urls(text: &str) -> String {
    let ends_word = |c: char| c.is_whitespace() || matches!(c, '\'' | '"' | '`');
    let mut out = String::with_capacity(text.len());
    for piece in text.split_inclusive(ends_word) {
        let word = piece.trim_end_matches(ends_word);
        if word.contains("://") {
            out.push_str("<redacted>");
            out.push_str(&piece[word.len()..]);
        } else {
            out.push_str(piece);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn refusal(args: &[&str]) -> String {
        let parsed =
            LiteArgs::try_parse_from(std::iter::once("reth-lite").chain(args.iter().copied()));
        let text = match parsed {
            Ok(args) => args.into_config().expect_err("refused").to_string(),
            Err(err) => err.to_string(),
        };
        redact_urls(&text)
    }

    #[test]
    fn a_misplaced_beacon_url_is_not_echoed() {
        assert_eq!(
            refusal(&[
                "--beacon.url",
                "https://a.example/KEY1",
                "https://b.example/KEY2",
                "--beacon.quorum",
                "2"
            ]),
            "error: unexpected argument '<redacted>' found\n\nUsage: reth-lite [OPTIONS]\n\n\
             For more information, try '--help'.\n"
        );
        assert_eq!(
            refusal(&["--beacon.quorum=https://b.example/KEY3"]),
            "error: invalid value '<redacted>' for '--beacon.quorum <BEACON_QUORUM>': invalid \
             digit found in string\n\nFor more information, try '--help'.\n"
        );
        assert_eq!(
            refusal(&["--beacon.url-file", "https://a.example/KEY4", "--head.confirm", "none"]),
            "--beacon.url-file: cannot read <redacted: looks like a URL>: No such file or directory (os error 2)"
        );
        assert_eq!(
            refusal(&[
                "--beacon.url",
                "https://c.example/x",
                "--head.confirm",
                "none",
                "--finalized.url-file",
                "https://a.example/KEY5"
            ]),
            "--finalized.url-file: cannot read <redacted: looks like a URL>: No such file or directory (os error 2)"
        );
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(128))]

        #[test]
        fn a_secret_url_anywhere_on_the_command_line_is_not_echoed(
            scheme in proptest::sample::select(vec!["https", "http", "wss", "enode"]),
            user in proptest::option::of("[a-z]{1,4}:SECRETU"),
            path in proptest::option::of("SECRETP[a-z/]{0,6}"),
            query in proptest::option::of("k=SECRETQ"),
            flag in proptest::sample::select(vec![
                "", "--beacon.url", "--beacon.url-file", "--beacon.quorum", "--beacon.poll",
                "--finalized.url", "--finalized.url-file", "--finalized.recheck", "--peer",
                "--http.addr", "--metrics.addr", "--chain", "--cache.size", "--head.confirm",
                "--state.on-miss", "--max-peers", "--nope",
            ]),
            joined in proptest::bool::ANY,
            at in 0usize..=4,
        ) {
            let user = user.map_or(String::new(), |u| format!("{u}@"));
            let mut url = format!("{scheme}://{user}h.example/{}", path.unwrap_or_default());
            if let Some(q) = query {
                url = format!("{url}?{q}");
            }
            let mut args = vec!["--beacon.url", "https://c.example/x", "--head.confirm", "none"];
            let both = format!("{flag}={url}");
            let tokens = match (flag, joined) {
                ("", _) => vec![url.as_str()],
                (_, true) => vec![both.as_str()],
                (_, false) => vec![flag, url.as_str()],
            };
            args.splice(at..at, tokens);
            let parsed =
                LiteArgs::try_parse_from(std::iter::once("reth-lite").chain(args.iter().copied()));
            let text = match parsed {
                Ok(args) => args.into_config().err().map(|e| e.to_string()),
                Err(err) => Some(err.to_string()),
            };
            if let Some(text) = text {
                let shown = redact_urls(&text);
                proptest::prop_assert!(!shown.contains("SECRET"), "{args:?} printed {shown}");
            }
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn every_signal_reaches_the_node_while_it_runs() {
        let mut signals = forward_signals().unwrap();
        // The second and third stand for the signal that stops the shutdown flush.
        for sig in ["-INT", "-TERM", "-INT"] {
            let sent = std::process::Command::new("kill")
                .args([sig, &std::process::id().to_string()])
                .status()
                .unwrap();
            assert!(sent.success(), "kill {sig}");
            let got = tokio::time::timeout(std::time::Duration::from_secs(5), signals.recv()).await;
            assert_eq!(got, Ok(Some(())), "after {sig}");
        }
    }

    #[test]
    fn redaction_keeps_the_rest_of_the_text() {
        assert_eq!(redact_urls("a \"x://k\" b\tc://d\n"), "a \"<redacted>\" b\t<redacted>\n");
        assert_eq!(redact_urls("no url here: /tmp/f"), "no url here: /tmp/f");
    }
}
