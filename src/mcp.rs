use serde_json::{json, Value};
use std::io::{self, BufRead, Write};

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
                .args([
                    "-o",
                    "BatchMode=yes",
                    "-o",
                    "StrictHostKeyChecking=accept-new",
                    "-o",
                    "ConnectTimeout=10",
                ])
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
