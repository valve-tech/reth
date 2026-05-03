//! Submit test messages to a running msgboard via `msgboard_addMessage`.
//!
//! Mines valid PoW for the chain head returned by the target node's JSON-RPC,
//! RLP-encodes the resulting `PoWMsg`, and submits it. Useful as an operator
//! smoke test after a deploy, or to seed a quiet board during testing.
//!
//! ## Usage
//!
//! ```text
//! cargo run --release -p reth-msgboard --example submit_messages -- \
//!     --url http://127.0.0.1:8545 --count 3 --category tagline
//! ```
//!
//! All arguments are optional. Defaults: URL `http://127.0.0.1:8545`,
//! count `3`, category `b256(0xCA…)` (recognisable when grepping logs).
//! Mines using the board's default work ratio (`10_000 / 1_000_000`).

use std::{
    process::Command,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use alloy_primitives::{hex, keccak256, Bytes, B256};
use alloy_rlp::Encodable;
use reth_msgboard_types::{PoWMsg, VERSION_V1};
use serde_json::{json, Value};

#[derive(Debug)]
struct Args {
    url: String,
    count: usize,
    category: B256,
    work_multiplier: u64,
    work_divisor: u64,
}

impl Args {
    fn parse() -> Self {
        let mut args = std::env::args().skip(1).peekable();
        let mut url = "http://127.0.0.1:8545".to_string();
        let mut count = 3usize;
        let mut category = {
            let mut b = [0u8; 32];
            b[0] = 0xCA;
            B256::from(b)
        };
        let mut work_multiplier = 10_000u64;
        let mut work_divisor = 1_000_000u64;

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--url" => url = args.next().expect("--url needs a value"),
                "--count" => count = args.next().expect("--count needs a value").parse().unwrap(),
                "--category" => {
                    let raw = args.next().expect("--category needs a value");
                    if let Some(stripped) = raw.strip_prefix("0x") {
                        let bytes = hex::decode(stripped).expect("hex");
                        assert_eq!(bytes.len(), 32, "category hex must be 32 bytes");
                        category = B256::from_slice(&bytes);
                    } else {
                        category = keccak256(raw.as_bytes());
                    }
                }
                "--work-multiplier" => {
                    work_multiplier = args.next().expect("value").parse().unwrap();
                }
                "--work-divisor" => {
                    work_divisor = args.next().expect("value").parse().unwrap();
                }
                "--help" | "-h" => {
                    print_help();
                    std::process::exit(0);
                }
                other => {
                    eprintln!("unknown argument: {other}");
                    print_help();
                    std::process::exit(2);
                }
            }
        }

        Self { url, count, category, work_multiplier, work_divisor }
    }
}

fn print_help() {
    eprintln!("usage: submit_messages [--url URL] [--count N] [--category HEX|TAG] [--work-multiplier N] [--work-divisor N]");
    eprintln!("  url                default http://127.0.0.1:8545");
    eprintln!("  count              default 3");
    eprintln!("  category           '0x' + 64-hex (32 bytes), or any tag (keccak256'd)");
    eprintln!("  work_multiplier    default 10_000  (matches board default)");
    eprintln!("  work_divisor       default 1_000_000  (matches board default)");
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    println!("target:    {}", args.url);
    println!("category:  {}", args.category);
    println!("count:     {}", args.count);
    println!("work:      {}/{}", args.work_multiplier, args.work_divisor);
    println!();

    // 1. Fetch chain head — we need (number, hash) to anchor our messages.
    let head = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_getBlockByNumber",
        "params": ["latest", false],
    });
    let resp = rpc_call(&args.url, &head.to_string())?;
    let head_hash = parse_hex_b256(resp["result"]["hash"].as_str().expect("hash"))?;
    let head_num = parse_hex_u64(resp["result"]["number"].as_str().expect("number"))?;
    println!("chain head: #{head_num} ({head_hash})");
    println!();

    // 2. Mine + submit `count` messages.
    for i in 0..args.count {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
        let payload = format!("hello msgboard #{i} @ {now}");
        let mut msg = PoWMsg {
            version: VERSION_V1,
            block_hash: head_hash,
            nonce: 0,
            work_multiplier: args.work_multiplier,
            work_divisor: args.work_divisor,
            category: args.category,
            data: Bytes::from(payload.into_bytes()),
        };

        let mine_start = Instant::now();
        let mut tries = 0u64;
        let nonce = loop {
            tries += 1;
            msg.nonce = tries;
            if msg.clone().to_checked(head_num, 0).is_ok() {
                break tries;
            }
            if tries > 100_000_000 {
                return Err("mining ceiling hit; check work params".into());
            }
        };
        let mine_elapsed = mine_start.elapsed();

        // 3. RLP-encode and submit.
        let mut rlp = Vec::new();
        msg.encode(&mut rlp);
        let hex_payload = format!("0x{}", hex::encode(&rlp));

        let body = json!({
            "jsonrpc": "2.0",
            "id": 100 + i,
            "method": "msgboard_addMessage",
            "params": [hex_payload],
        });
        let resp = rpc_call(&args.url, &body.to_string())?;

        match resp.get("result").and_then(|v| v.as_str()) {
            Some(hash) => println!(
                "#{i:02}  mined nonce={nonce:<10} ({tries:>10} tries, {:>5}ms)  → accepted hash={hash}",
                mine_elapsed.as_millis()
            ),
            None => println!(
                "#{i:02}  mined nonce={nonce:<10} ({tries:>10} tries, {:>5}ms)  → REJECTED: {}",
                mine_elapsed.as_millis(),
                resp.get("error").unwrap_or(&Value::Null)
            ),
        }
    }

    Ok(())
}

fn rpc_call(url: &str, body: &str) -> Result<Value, Box<dyn std::error::Error>> {
    let out = Command::new("curl")
        .args(["-s", "-S", "-X", "POST", "-H", "content-type: application/json", "-d", body, url])
        .output()?;
    if !out.status.success() {
        return Err(format!(
            "curl failed: status={:?} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        )
        .into());
    }
    Ok(serde_json::from_slice(&out.stdout)?)
}

fn parse_hex_b256(s: &str) -> Result<B256, Box<dyn std::error::Error>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s)?;
    if bytes.len() != 32 {
        return Err(format!("expected 32-byte hash, got {} bytes", bytes.len()).into());
    }
    Ok(B256::from_slice(&bytes))
}

fn parse_hex_u64(s: &str) -> Result<u64, Box<dyn std::error::Error>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    Ok(u64::from_str_radix(s, 16)?)
}
