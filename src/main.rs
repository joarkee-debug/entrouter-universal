use std::io::{self, Read};

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("entrouter-universal CLI");
        eprintln!();
        eprintln!("Usage:");
        eprintln!("  entrouter encode       Read stdin, print base64 + fingerprint as JSON");
        eprintln!("  entrouter decode        Read JSON from stdin, print original data");
        eprintln!("  entrouter verify        Read JSON from stdin, verify integrity");
        eprintln!("  entrouter raw-encode    Read stdin, print just the base64 (no JSON)");
        eprintln!("  entrouter raw-decode    Read base64 from stdin, print original data");
        eprintln!();
        eprintln!("Pipe-friendly: echo 'hello' | entrouter encode | entrouter verify");
        std::process::exit(1);
    }

    let input = read_stdin();

    match args[1].as_str() {
        "encode" => cmd_encode(&input),
        "decode" => cmd_decode(&input),
        "verify" => cmd_verify(&input),
        "raw-encode" => cmd_raw_encode(&input),
        "raw-decode" => cmd_raw_decode(&input),
        other => {
            eprintln!("Unknown command: {other}");
            eprintln!("Try: encode, decode, verify, raw-encode, raw-decode");
            std::process::exit(1);
        }
    }
}

fn read_stdin() -> String {
    let mut buf = String::new();
    io::stdin().read_to_string(&mut buf).unwrap_or_else(|e| {
        eprintln!("Failed to read stdin: {e}");
        std::process::exit(1);
    });
    // Strip trailing newline so piping works cleanly
    if buf.ends_with('\n') {
        buf.pop();
        if buf.ends_with('\r') {
            buf.pop();
        }
    }
    buf
}

/// encode: stdin → JSON { "encoded": "...", "fingerprint": "..." }
fn cmd_encode(input: &str) {
    let encoded = entrouter_universal::encode_str(input);
    let fp = entrouter_universal::fingerprint_str(input);
    println!("{{\"encoded\":\"{encoded}\",\"fingerprint\":\"{fp}\"}}");
}

/// decode: JSON stdin → original data
fn cmd_decode(input: &str) {
    let v: serde_json::Value = serde_json::from_str(input).unwrap_or_else(|e| {
        eprintln!("Invalid JSON: {e}");
        std::process::exit(1);
    });

    let encoded = v["encoded"].as_str().unwrap_or_else(|| {
        eprintln!("Missing \"encoded\" field in JSON");
        std::process::exit(1);
    });

    match entrouter_universal::decode(encoded) {
        Ok(bytes) => {
            let text = String::from_utf8_lossy(&bytes);
            print!("{text}");
        }
        Err(e) => {
            eprintln!("Decode failed: {e}");
            std::process::exit(1);
        }
    }
}

/// verify: JSON stdin → integrity check
fn cmd_verify(input: &str) {
    let v: serde_json::Value = serde_json::from_str(input).unwrap_or_else(|e| {
        eprintln!("Invalid JSON: {e}");
        std::process::exit(1);
    });

    let encoded = v["encoded"].as_str().unwrap_or_else(|| {
        eprintln!("Missing \"encoded\" field");
        std::process::exit(1);
    });

    let fp = v["fingerprint"].as_str().unwrap_or_else(|| {
        eprintln!("Missing \"fingerprint\" field");
        std::process::exit(1);
    });

    match entrouter_universal::verify(encoded, fp) {
        Ok(result) => {
            if result.intact {
                println!("INTACT");
                println!("Decoded: {}", String::from_utf8_lossy(&result.decoded));
            } else {
                eprintln!("TAMPERED");
                eprintln!("Expected fingerprint: {fp}");
                eprintln!("Actual fingerprint:   {}", result.fingerprint);
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("Verify failed: {e}");
            std::process::exit(1);
        }
    }
}

/// raw-encode: stdin → just base64 (no JSON, no fingerprint)
fn cmd_raw_encode(input: &str) {
    print!("{}", entrouter_universal::encode_str(input));
}

/// raw-decode: base64 stdin → original data
fn cmd_raw_decode(input: &str) {
    match entrouter_universal::decode(input) {
        Ok(bytes) => {
            let text = String::from_utf8_lossy(&bytes);
            print!("{text}");
        }
        Err(e) => {
            eprintln!("Decode failed: {e}");
            std::process::exit(1);
        }
    }
}
