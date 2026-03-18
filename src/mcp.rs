use entrouter_universal::chain::Chain;
use entrouter_universal::envelope::Envelope;
use entrouter_universal::signed_envelope::SignedEnvelope;
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};

/// Common SSH args: multiplexing (ControlMaster) + keepalive + timeouts.
/// ControlMaster reuses connections so the first SSH takes ~2s but subsequent
/// calls to the same host complete near-instantly. Falls back gracefully on
/// Windows where Unix sockets aren't available.
fn ssh_args() -> Vec<String> {
    let socket_dir = std::env::temp_dir().join("entrouter-ssh");
    let _ = std::fs::create_dir_all(&socket_dir);
    let control_path = socket_dir.join("%r@%h:%p");
    vec![
        "-o".into(), "BatchMode=yes".into(),
        "-o".into(), "StrictHostKeyChecking=accept-new".into(),
        "-o".into(), "ConnectTimeout=10".into(),
        "-o".into(), "ServerAliveInterval=5".into(),
        "-o".into(), "ServerAliveCountMax=3".into(),
        "-o".into(), format!("ControlPath={}", control_path.display()),
        "-o".into(), "ControlMaster=auto".into(),
        "-o".into(), "ControlPersist=300".into(),
    ]
}

/// Run the MCP stdio server.
/// Reads JSON-RPC messages (newline-delimited JSON) from stdin,
/// writes responses to stdout.
pub fn run() {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let reader = stdin.lock();
    let mut writer = stdout.lock();

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let request: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => continue,
        };

        if let Some(response) = handle_request(&request) {
            write_response(&mut writer, &response);
        }
    }
}

fn write_response(writer: &mut impl Write, message: &Value) {
    let body = serde_json::to_string(message).unwrap();
    let _ = writeln!(writer, "{}", body);
    let _ = writer.flush();
}

fn handle_request(request: &Value) -> Option<Value> {
    let method = request["method"].as_str()?;
    let id = request.get("id").cloned();

    match method {
        "initialize" => Some(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": "entrouter-universal",
                    "version": env!("CARGO_PKG_VERSION")
                }
            }
        })),
        "notifications/initialized" => None,
        "tools/list" => Some(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "tools": tools_list()
            }
        })),
        "tools/call" => {
            let tool_name = request["params"]["name"].as_str().unwrap_or("");
            let arguments = &request["params"]["arguments"];
            let result = call_tool(tool_name, arguments);
            Some(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": result
            }))
        }
        "ping" => Some(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {}
        })),
        _ => id.map(|id| {
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32601,
                    "message": format!("Method not found: {method}")
                }
            })
        }),
    }
}

fn tools_list() -> Vec<Value> {
    vec![
        json!({
            "name": "entrouter_encode",
            "description": "Encode text to base64 and compute its SHA-256 fingerprint. Returns JSON with 'encoded' and 'fingerprint' fields. Use this to safely encode data for transit through shells, SSH, containers, or any pipeline that might mangle special characters.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "text": {
                        "type": "string",
                        "description": "The text to encode"
                    }
                },
                "required": ["text"]
            }
        }),
        json!({
            "name": "entrouter_decode",
            "description": "Decode a base64-encoded string back to the original text.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "encoded": {
                        "type": "string",
                        "description": "The base64-encoded string to decode"
                    }
                },
                "required": ["encoded"]
            }
        }),
        json!({
            "name": "entrouter_verify",
            "description": "Verify the integrity of encoded data by checking its SHA-256 fingerprint. Returns whether the data is INTACT or TAMPERED.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "encoded": {
                        "type": "string",
                        "description": "The base64-encoded data"
                    },
                    "fingerprint": {
                        "type": "string",
                        "description": "The expected SHA-256 fingerprint (hex string)"
                    }
                },
                "required": ["encoded", "fingerprint"]
            }
        }),
        json!({
            "name": "entrouter_raw_encode",
            "description": "Encode text to plain base64 (no fingerprint, no JSON wrapper). Useful for quick encoding.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "text": {
                        "type": "string",
                        "description": "The text to encode"
                    }
                },
                "required": ["text"]
            }
        }),
        json!({
            "name": "entrouter_raw_decode",
            "description": "Decode a base64 string to original text (no verification).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "encoded": {
                        "type": "string",
                        "description": "The base64 string to decode"
                    }
                },
                "required": ["encoded"]
            }
        }),
        json!({
            "name": "entrouter_fingerprint",
            "description": "Compute the SHA-256 fingerprint (hex) of the given text.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "text": {
                        "type": "string",
                        "description": "The text to fingerprint"
                    }
                },
                "required": ["text"]
            }
        }),
        json!({
            "name": "entrouter_ssh",
            "description": "Execute a shell command on a remote host via SSH. The command is base64-encoded locally, sent over SSH, decoded on the remote side, and executed via sh. This avoids all shell escaping issues -- quotes, JSON, special characters all arrive intact. Requires entrouter to be installed on the remote host.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "The SSH target (e.g. root@192.168.1.1)"
                    },
                    "command": {
                        "type": "string",
                        "description": "The shell command to execute on the remote host"
                    }
                },
                "required": ["host", "command"]
            }
        }),
        json!({
            "name": "entrouter_envelope_wrap",
            "description": "Wrap text in a sealed Envelope with SHA-256 integrity fingerprint. Supports 4 modes: standard (Base64), urlsafe (URL-safe Base64), compressed (gzip+Base64), ttl (Base64 with expiry). Returns Envelope JSON.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "text": {
                        "type": "string",
                        "description": "The text to wrap"
                    },
                    "mode": {
                        "type": "string",
                        "description": "Envelope mode: standard, urlsafe, compressed, or ttl (default: standard)"
                    },
                    "ttl_secs": {
                        "type": "number",
                        "description": "TTL in seconds (required when mode is 'ttl')"
                    }
                },
                "required": ["text"]
            }
        }),
        json!({
            "name": "entrouter_envelope_unwrap",
            "description": "Unwrap and verify an Envelope. Returns the original text if integrity check passes, or an error if data was tampered or TTL expired.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "envelope_json": {
                        "type": "string",
                        "description": "The Envelope JSON string to unwrap"
                    }
                },
                "required": ["envelope_json"]
            }
        }),
        json!({
            "name": "entrouter_chain_new",
            "description": "Create a new cryptographic chain with a genesis link. Returns Chain JSON. Each link references the previous link's fingerprint, forming an unbreakable audit trail.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "data": {
                        "type": "string",
                        "description": "The data for the genesis link"
                    }
                },
                "required": ["data"]
            }
        }),
        json!({
            "name": "entrouter_chain_append",
            "description": "Append a new link to an existing chain. Returns updated Chain JSON.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "chain_json": {
                        "type": "string",
                        "description": "The existing Chain JSON"
                    },
                    "data": {
                        "type": "string",
                        "description": "The data for the new link"
                    }
                },
                "required": ["chain_json", "data"]
            }
        }),
        json!({
            "name": "entrouter_chain_verify",
            "description": "Verify the integrity of an entire chain. Returns a verification report showing whether all links are intact and properly linked.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "chain_json": {
                        "type": "string",
                        "description": "The Chain JSON to verify"
                    }
                },
                "required": ["chain_json"]
            }
        }),
        json!({
            "name": "entrouter_docker",
            "description": "Execute a shell command inside a Docker container. The command is base64-encoded, sent to the container, decoded, and executed via sh. Avoids all shell escaping issues.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "container": {
                        "type": "string",
                        "description": "The Docker container name or ID"
                    },
                    "command": {
                        "type": "string",
                        "description": "The shell command to execute inside the container"
                    }
                },
                "required": ["container", "command"]
            }
        }),
        json!({
            "name": "entrouter_kube",
            "description": "Execute a shell command inside a Kubernetes pod. The command is base64-encoded, sent to the pod, decoded, and executed via sh. Avoids all shell escaping issues.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "pod": {
                        "type": "string",
                        "description": "The Kubernetes pod name"
                    },
                    "command": {
                        "type": "string",
                        "description": "The shell command to execute inside the pod"
                    },
                    "namespace": {
                        "type": "string",
                        "description": "The Kubernetes namespace (optional, defaults to current context namespace)"
                    }
                },
                "required": ["pod", "command"]
            }
        }),
        json!({
            "name": "entrouter_multi_ssh",
            "description": "Execute a shell command on multiple remote hosts via SSH. Hosts are comma-separated. Runs sequentially, each with a 30s timeout. Returns per-host results.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "hosts": {
                        "type": "string",
                        "description": "Comma-separated SSH targets (e.g. root@host1,root@host2)"
                    },
                    "command": {
                        "type": "string",
                        "description": "The shell command to execute on each host"
                    }
                },
                "required": ["hosts", "command"]
            }
        }),
        json!({
            "name": "entrouter_signed_wrap",
            "description": "Wrap text into an HMAC-SHA256 signed envelope. Proves both integrity AND origin (anyone with the shared key can verify).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "text": {
                        "type": "string",
                        "description": "The text to wrap"
                    },
                    "key": {
                        "type": "string",
                        "description": "The HMAC shared secret key"
                    },
                    "mode": {
                        "type": "string",
                        "description": "Encoding mode: standard (default), url_safe, compressed, or ttl"
                    },
                    "ttl_secs": {
                        "type": "integer",
                        "description": "Time-to-live in seconds (required when mode is ttl)"
                    }
                },
                "required": ["text", "key"]
            }
        }),
        json!({
            "name": "entrouter_signed_unwrap",
            "description": "Unwrap and verify an HMAC-signed envelope. Checks the HMAC signature first, then TTL (if applicable), then data integrity.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "envelope_json": {
                        "type": "string",
                        "description": "The signed envelope JSON string"
                    },
                    "key": {
                        "type": "string",
                        "description": "The HMAC shared secret key used during wrapping"
                    }
                },
                "required": ["envelope_json", "key"]
            }
        }),
        json!({
            "name": "entrouter_chain_diff",
            "description": "Compare two chains and find where they diverge. Returns common prefix length, extra links in each, and the 1-based divergence point (if any).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "chain_a_json": {
                        "type": "string",
                        "description": "First chain as JSON"
                    },
                    "chain_b_json": {
                        "type": "string",
                        "description": "Second chain as JSON"
                    }
                },
                "required": ["chain_a_json", "chain_b_json"]
            }
        }),
        json!({
            "name": "entrouter_chain_merge",
            "description": "Merge two chains. One must be a prefix of the other. Returns the longer chain, or an error if they diverge.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "chain_a_json": {
                        "type": "string",
                        "description": "First chain as JSON"
                    },
                    "chain_b_json": {
                        "type": "string",
                        "description": "Second chain as JSON"
                    }
                },
                "required": ["chain_a_json", "chain_b_json"]
            }
        }),
    ]
}

fn call_tool(name: &str, args: &Value) -> Value {
    match name {
        "entrouter_encode" => {
            let text = args["text"].as_str().unwrap_or("");
            let encoded = entrouter_universal::encode_str(text);
            let fp = entrouter_universal::fingerprint_str(text);
            json!({
                "content": [{
                    "type": "text",
                    "text": format!("{{\"encoded\":\"{encoded}\",\"fingerprint\":\"{fp}\"}}")
                }]
            })
        }
        "entrouter_decode" => {
            let encoded = args["encoded"].as_str().unwrap_or("");
            match entrouter_universal::decode(encoded) {
                Ok(bytes) => json!({
                    "content": [{
                        "type": "text",
                        "text": String::from_utf8_lossy(&bytes)
                    }]
                }),
                Err(e) => tool_error(&format!("Decode failed: {e}")),
            }
        }
        "entrouter_verify" => {
            let encoded = args["encoded"].as_str().unwrap_or("");
            let fp = args["fingerprint"].as_str().unwrap_or("");
            match entrouter_universal::verify(encoded, fp) {
                Ok(result) => {
                    let decoded = String::from_utf8_lossy(&result.decoded);
                    json!({
                        "content": [{
                            "type": "text",
                            "text": format!("INTACT\nDecoded: {decoded}")
                        }]
                    })
                }
                Err(e) => tool_error(&format!("TAMPERED: {e}")),
            }
        }
        "entrouter_raw_encode" => {
            let text = args["text"].as_str().unwrap_or("");
            json!({
                "content": [{
                    "type": "text",
                    "text": entrouter_universal::encode_str(text)
                }]
            })
        }
        "entrouter_raw_decode" => {
            let encoded = args["encoded"].as_str().unwrap_or("");
            match entrouter_universal::decode(encoded) {
                Ok(bytes) => json!({
                    "content": [{
                        "type": "text",
                        "text": String::from_utf8_lossy(&bytes)
                    }]
                }),
                Err(e) => tool_error(&format!("Decode failed: {e}")),
            }
        }
        "entrouter_fingerprint" => {
            let text = args["text"].as_str().unwrap_or("");
            json!({
                "content": [{
                    "type": "text",
                    "text": entrouter_universal::fingerprint_str(text)
                }]
            })
        }
        "entrouter_ssh" => {
            let host = args["host"].as_str().unwrap_or("");
            let command = args["command"].as_str().unwrap_or("");
            if host.is_empty() || command.is_empty() {
                return tool_error("Both 'host' and 'command' are required");
            }
            let encoded = entrouter_universal::encode_str(command);
            let remote_cmd = format!("echo '{encoded}' | entrouter raw-decode | sh");

            match std::process::Command::new("ssh")
                .args(ssh_args())
                .arg(host)
                .arg(&remote_cmd)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
            {
                Ok(mut child) => {
                    let timeout = std::time::Duration::from_secs(30);
                    let start = std::time::Instant::now();
                    loop {
                        match child.try_wait() {
                            Ok(Some(status)) => {
                                let mut stdout = String::new();
                                let mut stderr = String::new();
                                if let Some(mut out) = child.stdout.take() {
                                    use std::io::Read;
                                    let _ = out.read_to_string(&mut stdout);
                                }
                                if let Some(mut err) = child.stderr.take() {
                                    use std::io::Read;
                                    let _ = err.read_to_string(&mut stderr);
                                }
                                let mut result = String::new();
                                if !stdout.is_empty() {
                                    result.push_str(&stdout);
                                }
                                if !stderr.is_empty() {
                                    if !result.is_empty() {
                                        result.push('\n');
                                    }
                                    result.push_str("[stderr] ");
                                    result.push_str(&stderr);
                                }
                                if result.is_empty() {
                                    result = format!(
                                        "Command completed with exit code {}",
                                        status.code().unwrap_or(-1)
                                    );
                                }
                                break json!({
                                    "content": [{
                                        "type": "text",
                                        "text": result
                                    }],
                                    "isError": !status.success()
                                });
                            }
                            Ok(None) => {
                                if start.elapsed() > timeout {
                                    let _ = child.kill();
                                    break tool_error("SSH command timed out after 30 seconds");
                                }
                                std::thread::sleep(std::time::Duration::from_millis(100));
                            }
                            Err(e) => {
                                break tool_error(&format!("Failed to wait on SSH process: {e}"));
                            }
                        }
                    }
                }
                Err(e) => tool_error(&format!("SSH failed: {e}")),
            }
        }
        "entrouter_envelope_wrap" => {
            let text = args["text"].as_str().unwrap_or("");
            let mode = args["mode"].as_str().unwrap_or("standard");
            let result = match mode {
                "urlsafe" => Ok(Envelope::wrap_url_safe(text)),
                "compressed" => Envelope::wrap_compressed(text),
                "ttl" => {
                    let secs = args["ttl_secs"].as_u64().unwrap_or(60);
                    Ok(Envelope::wrap_with_ttl(text, secs))
                }
                _ => Ok(Envelope::wrap(text)),
            };
            match result {
                Ok(env) => match env.to_json() {
                    Ok(j) => json!({
                        "content": [{
                            "type": "text",
                            "text": j
                        }]
                    }),
                    Err(e) => tool_error(&format!("Serialization failed: {e}")),
                },
                Err(e) => tool_error(&format!("Envelope wrap failed: {e}")),
            }
        }
        "entrouter_envelope_unwrap" => {
            let envelope_json = args["envelope_json"].as_str().unwrap_or("");
            match Envelope::from_json(envelope_json) {
                Ok(env) => match env.unwrap_verified() {
                    Ok(text) => json!({
                        "content": [{
                            "type": "text",
                            "text": text
                        }]
                    }),
                    Err(e) => tool_error(&format!("Envelope verification failed: {e}")),
                },
                Err(e) => tool_error(&format!("Invalid envelope JSON: {e}")),
            }
        }
        "entrouter_chain_new" => {
            let data = args["data"].as_str().unwrap_or("");
            let chain = Chain::new(data);
            match chain.to_json() {
                Ok(j) => json!({
                    "content": [{
                        "type": "text",
                        "text": j
                    }]
                }),
                Err(e) => tool_error(&format!("Serialization failed: {e}")),
            }
        }
        "entrouter_chain_append" => {
            let chain_json = args["chain_json"].as_str().unwrap_or("");
            let data = args["data"].as_str().unwrap_or("");
            match Chain::from_json(chain_json) {
                Ok(mut chain) => {
                    chain.append(data);
                    match chain.to_json() {
                        Ok(j) => json!({
                            "content": [{
                                "type": "text",
                                "text": j
                            }]
                        }),
                        Err(e) => tool_error(&format!("Serialization failed: {e}")),
                    }
                }
                Err(e) => tool_error(&format!("Invalid chain JSON: {e}")),
            }
        }
        "entrouter_chain_verify" => {
            let chain_json = args["chain_json"].as_str().unwrap_or("");
            match Chain::from_json(chain_json) {
                Ok(chain) => {
                    let report = chain.report();
                    json!({
                        "content": [{
                            "type": "text",
                            "text": report
                        }]
                    })
                }
                Err(e) => tool_error(&format!("Invalid chain JSON: {e}")),
            }
        }
        "entrouter_docker" => {
            let container = args["container"].as_str().unwrap_or("");
            let command = args["command"].as_str().unwrap_or("");
            if container.is_empty() || command.is_empty() {
                return tool_error("Both 'container' and 'command' are required");
            }
            let encoded = entrouter_universal::encode_str(command);
            let decode_cmd = format!("echo '{encoded}' | base64 -d | sh");

            match std::process::Command::new("docker")
                .args(["exec", container, "sh", "-c", &decode_cmd])
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
            {
                Ok(mut child) => {
                    let timeout = std::time::Duration::from_secs(30);
                    let start = std::time::Instant::now();
                    loop {
                        match child.try_wait() {
                            Ok(Some(status)) => {
                                let mut stdout = String::new();
                                let mut stderr = String::new();
                                if let Some(mut out) = child.stdout.take() {
                                    use std::io::Read;
                                    let _ = out.read_to_string(&mut stdout);
                                }
                                if let Some(mut err) = child.stderr.take() {
                                    use std::io::Read;
                                    let _ = err.read_to_string(&mut stderr);
                                }
                                let mut result = String::new();
                                if !stdout.is_empty() {
                                    result.push_str(&stdout);
                                }
                                if !stderr.is_empty() {
                                    if !result.is_empty() {
                                        result.push('\n');
                                    }
                                    result.push_str("[stderr] ");
                                    result.push_str(&stderr);
                                }
                                if result.is_empty() {
                                    result = format!(
                                        "Command completed with exit code {}",
                                        status.code().unwrap_or(-1)
                                    );
                                }
                                break json!({
                                    "content": [{
                                        "type": "text",
                                        "text": result
                                    }],
                                    "isError": !status.success()
                                });
                            }
                            Ok(None) => {
                                if start.elapsed() > timeout {
                                    let _ = child.kill();
                                    break tool_error("Docker exec timed out after 30 seconds");
                                }
                                std::thread::sleep(std::time::Duration::from_millis(100));
                            }
                            Err(e) => {
                                break tool_error(&format!(
                                    "Failed to wait on docker process: {e}"
                                ));
                            }
                        }
                    }
                }
                Err(e) => tool_error(&format!("Docker exec failed: {e}")),
            }
        }
        "entrouter_kube" => {
            let pod = args["pod"].as_str().unwrap_or("");
            let command = args["command"].as_str().unwrap_or("");
            if pod.is_empty() || command.is_empty() {
                return tool_error("Both 'pod' and 'command' are required");
            }
            let encoded = entrouter_universal::encode_str(command);
            let decode_cmd = format!("echo '{encoded}' | base64 -d | sh");

            let mut cmd_args: Vec<String> = vec!["exec".into(), pod.into()];
            if let Some(ns) = args["namespace"].as_str() {
                if !ns.is_empty() {
                    cmd_args.push("-n".into());
                    cmd_args.push(ns.into());
                }
            }
            cmd_args.extend(["--".into(), "sh".into(), "-c".into(), decode_cmd.clone()]);

            match std::process::Command::new("kubectl")
                .args(&cmd_args)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
            {
                Ok(mut child) => {
                    let timeout = std::time::Duration::from_secs(30);
                    let start = std::time::Instant::now();
                    loop {
                        match child.try_wait() {
                            Ok(Some(status)) => {
                                let mut stdout = String::new();
                                let mut stderr = String::new();
                                if let Some(mut out) = child.stdout.take() {
                                    use std::io::Read;
                                    let _ = out.read_to_string(&mut stdout);
                                }
                                if let Some(mut err) = child.stderr.take() {
                                    use std::io::Read;
                                    let _ = err.read_to_string(&mut stderr);
                                }
                                let mut result = String::new();
                                if !stdout.is_empty() {
                                    result.push_str(&stdout);
                                }
                                if !stderr.is_empty() {
                                    if !result.is_empty() {
                                        result.push('\n');
                                    }
                                    result.push_str("[stderr] ");
                                    result.push_str(&stderr);
                                }
                                if result.is_empty() {
                                    result = format!(
                                        "Command completed with exit code {}",
                                        status.code().unwrap_or(-1)
                                    );
                                }
                                break json!({
                                    "content": [{
                                        "type": "text",
                                        "text": result
                                    }],
                                    "isError": !status.success()
                                });
                            }
                            Ok(None) => {
                                if start.elapsed() > timeout {
                                    let _ = child.kill();
                                    break tool_error("kubectl exec timed out after 30 seconds");
                                }
                                std::thread::sleep(std::time::Duration::from_millis(100));
                            }
                            Err(e) => {
                                break tool_error(&format!(
                                    "Failed to wait on kubectl process: {e}"
                                ));
                            }
                        }
                    }
                }
                Err(e) => tool_error(&format!("kubectl exec failed: {e}")),
            }
        }
        "entrouter_multi_ssh" => {
            let hosts_str = args["hosts"].as_str().unwrap_or("");
            let command = args["command"].as_str().unwrap_or("");
            if hosts_str.is_empty() || command.is_empty() {
                return tool_error("Both 'hosts' and 'command' are required");
            }
            let hosts: Vec<&str> = hosts_str.split(',').map(|h| h.trim()).collect();
            let encoded = entrouter_universal::encode_str(command);
            let remote_cmd = format!("echo '{encoded}' | entrouter raw-decode | sh");
            let mut results = Vec::new();

            for host in &hosts {
                let result = match std::process::Command::new("ssh")
                    .args(ssh_args())
                    .arg(host)
                    .arg(&remote_cmd)
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()
                {
                    Ok(mut child) => {
                        let timeout = std::time::Duration::from_secs(30);
                        let start = std::time::Instant::now();
                        loop {
                            match child.try_wait() {
                                Ok(Some(status)) => {
                                    let mut stdout = String::new();
                                    let mut stderr = String::new();
                                    if let Some(mut out) = child.stdout.take() {
                                        use std::io::Read;
                                        let _ = out.read_to_string(&mut stdout);
                                    }
                                    if let Some(mut err) = child.stderr.take() {
                                        use std::io::Read;
                                        let _ = err.read_to_string(&mut stderr);
                                    }
                                    let mut output = String::new();
                                    if !stdout.is_empty() {
                                        output.push_str(&stdout);
                                    }
                                    if !stderr.is_empty() {
                                        if !output.is_empty() {
                                            output.push('\n');
                                        }
                                        output.push_str("[stderr] ");
                                        output.push_str(&stderr);
                                    }
                                    if output.is_empty() {
                                        output = format!("exit {}", status.code().unwrap_or(-1));
                                    }
                                    break output;
                                }
                                Ok(None) => {
                                    if start.elapsed() > timeout {
                                        let _ = child.kill();
                                        break "TIMEOUT after 30s".to_string();
                                    }
                                    std::thread::sleep(std::time::Duration::from_millis(100));
                                }
                                Err(e) => break format!("ERROR: {e}"),
                            }
                        }
                    }
                    Err(e) => format!("SSH failed: {e}"),
                };
                results.push(format!("[{host}]\n{result}"));
            }

            json!({
                "content": [{
                    "type": "text",
                    "text": results.join("\n\n")
                }]
            })
        }
        "entrouter_signed_wrap" => {
            let text = args["text"].as_str().unwrap_or("");
            let key = args["key"].as_str().unwrap_or("");
            let mode = args["mode"].as_str().unwrap_or("standard");
            let env_result: Result<SignedEnvelope, String> = match mode {
                "url_safe" => Ok(SignedEnvelope::wrap_url_safe(text, key)),
                #[cfg(feature = "compression")]
                "compressed" => {
                    SignedEnvelope::wrap_compressed(text, key).map_err(|e| e.to_string())
                }
                "ttl" => {
                    let ttl = args["ttl_secs"].as_u64().unwrap_or(300);
                    Ok(SignedEnvelope::wrap_with_ttl(text, key, ttl))
                }
                _ => Ok(SignedEnvelope::wrap(text, key)),
            };
            match env_result {
                Ok(env) => match env.to_json() {
                    Ok(j) => json!({
                        "content": [{
                            "type": "text",
                            "text": j
                        }]
                    }),
                    Err(e) => tool_error(&format!("Serialization failed: {e}")),
                },
                Err(e) => tool_error(&format!("Wrap failed: {e}")),
            }
        }
        "entrouter_signed_unwrap" => {
            let envelope_json = args["envelope_json"].as_str().unwrap_or("");
            let key = args["key"].as_str().unwrap_or("");
            match SignedEnvelope::from_json(envelope_json) {
                Ok(env) => match env.unwrap_verified(key) {
                    Ok(data) => json!({
                        "content": [{
                            "type": "text",
                            "text": data
                        }]
                    }),
                    Err(e) => tool_error(&format!("Verification failed: {e}")),
                },
                Err(e) => tool_error(&format!("Invalid signed envelope JSON: {e}")),
            }
        }
        "entrouter_chain_diff" => {
            let a_json = args["chain_a_json"].as_str().unwrap_or("");
            let b_json = args["chain_b_json"].as_str().unwrap_or("");
            let a = match Chain::from_json(a_json) {
                Ok(c) => c,
                Err(e) => return tool_error(&format!("Invalid chain A JSON: {e}")),
            };
            let b = match Chain::from_json(b_json) {
                Ok(c) => c,
                Err(e) => return tool_error(&format!("Invalid chain B JSON: {e}")),
            };
            let diff = Chain::diff(&a, &b);
            let diff_json = serde_json::to_string(&diff).unwrap_or_default();
            json!({
                "content": [{
                    "type": "text",
                    "text": diff_json
                }]
            })
        }
        "entrouter_chain_merge" => {
            let a_json = args["chain_a_json"].as_str().unwrap_or("");
            let b_json = args["chain_b_json"].as_str().unwrap_or("");
            let a = match Chain::from_json(a_json) {
                Ok(c) => c,
                Err(e) => return tool_error(&format!("Invalid chain A JSON: {e}")),
            };
            let b = match Chain::from_json(b_json) {
                Ok(c) => c,
                Err(e) => return tool_error(&format!("Invalid chain B JSON: {e}")),
            };
            match Chain::merge(&a, &b) {
                Ok(merged) => {
                    let merged_json = merged.to_json().unwrap_or_default();
                    json!({
                        "content": [{
                            "type": "text",
                            "text": merged_json
                        }]
                    })
                }
                Err(e) => tool_error(&format!("Merge failed: {e}")),
            }
        }
        _ => tool_error(&format!("Unknown tool: {name}")),
    }
}

fn tool_error(message: &str) -> Value {
    json!({
        "content": [{
            "type": "text",
            "text": message
        }],
        "isError": true
    })
}
