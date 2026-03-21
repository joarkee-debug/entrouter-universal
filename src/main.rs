// Copyright 2026 John A Keeney - Entrouter
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::io::{self, Read, Write};
use std::process::Command;

mod mcp;

/// Common SSH args: keepalive + timeouts.
/// On non-Windows platforms, enables ControlMaster multiplexing.
#[allow(unused_mut)]
fn ssh_args() -> Vec<String> {
    let mut args = vec![
        "-o".into(),
        "ServerAliveInterval=5".into(),
        "-o".into(),
        "ServerAliveCountMax=3".into(),
    ];
    #[cfg(not(target_os = "windows"))]
    {
        let socket_dir = std::env::temp_dir().join("entrouter-ssh");
        let _ = std::fs::create_dir_all(&socket_dir);
        let control_path = socket_dir.join("%r@%h:%p");
        args.extend([
            "-o".into(),
            format!("ControlPath={}", control_path.display()),
            "-o".into(),
            "ControlMaster=auto".into(),
            "-o".into(),
            "ControlPersist=300".into(),
        ]);
    }
    args
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("entrouter-universal CLI");
        eprintln!();
        eprintln!("Usage:");
        eprintln!("  entrouter encode              Read stdin, print base64 + fingerprint as JSON");
        eprintln!("  entrouter decode               Read JSON from stdin, print original data");
        eprintln!("  entrouter verify               Read JSON from stdin, verify integrity");
        eprintln!("  entrouter raw-encode           Read stdin, print just the base64 (no JSON)");
        eprintln!("  entrouter raw-decode           Read base64 from stdin, print original data");
        eprintln!(
            "  entrouter ssh <host>           Encode + execute command on remote host via SSH"
        );
        eprintln!(
            "  entrouter docker <container>   Encode + execute command inside a Docker container"
        );
        eprintln!(
            "  entrouter kube <pod> [-n ns]   Encode + execute command inside a Kubernetes pod"
        );
        eprintln!("  entrouter cron [schedule]      Encode command into a cron-safe line");
        eprintln!("  entrouter exec                 Decode base64 from stdin and execute locally");
        eprintln!(
            "  entrouter multi-ssh <h1,h2>    Encode + execute command on multiple hosts via SSH"
        );
        eprintln!(
            "  entrouter scp <f> <h:path>     Transfer a local file to a remote host via SSH"
        );
        eprintln!(
            "  entrouter mcp                  Start MCP server for VS Code Copilot integration"
        );
        eprintln!();
        eprintln!("Pipe-friendly: echo 'hello' | entrouter encode | entrouter verify");
        eprintln!("SSH example:   echo 'curl ...' | entrouter ssh root@your-vps");
        eprintln!("Multi-SSH:     echo 'uptime' | entrouter multi-ssh root@h1,root@h2");
        eprintln!("SCP:           entrouter scp config.json root@vps:/etc/app/config.json");
        eprintln!("Docker:        echo 'nginx -t' | entrouter docker my-nginx");
        eprintln!("Cron:          echo 'backup.sh' | entrouter cron '0 2 * * *'");
        std::process::exit(1);
    }

    match args[1].as_str() {
        "mcp" => mcp::run(),
        "ssh" => {
            if args.len() < 3 {
                eprintln!("Usage: entrouter ssh <user@host>");
                eprintln!("  Reads the command to run from stdin.");
                eprintln!("  Example: echo 'curl -s http://localhost:3000/health' | entrouter ssh root@your-vps");
                std::process::exit(1);
            }
            let host = &args[2];
            let input = read_stdin();
            cmd_ssh(host, &input);
        }
        "multi-ssh" => {
            if args.len() < 3 {
                eprintln!("Usage: entrouter multi-ssh <host1,host2,...>");
                eprintln!("  Reads the command to run from stdin.");
                eprintln!("  Example: echo 'uptime' | entrouter multi-ssh root@h1,root@h2");
                std::process::exit(1);
            }
            let hosts = &args[2];
            let input = read_stdin();
            cmd_multi_ssh(hosts, &input);
        }
        "scp" => {
            if args.len() < 4 {
                eprintln!("Usage: entrouter scp <local-file> <user@host>:<remote-path>");
                eprintln!("  Transfers a local file to a remote host via SSH.");
                eprintln!(
                    "  Example: entrouter scp config.json root@your-vps:/etc/myapp/config.json"
                );
                std::process::exit(1);
            }
            let local_file = &args[2];
            let dest = &args[3];
            cmd_scp(local_file, dest);
        }
        "docker" => {
            if args.len() < 3 {
                eprintln!("Usage: entrouter docker <container>");
                eprintln!("  Reads the command to run from stdin.");
                eprintln!("  Example: echo 'nginx -t' | entrouter docker my-nginx");
                std::process::exit(1);
            }
            let container = &args[2];
            let input = read_stdin();
            cmd_docker(container, &input);
        }
        "kube" => {
            if args.len() < 3 {
                eprintln!("Usage: entrouter kube <pod> [-n <namespace>]");
                eprintln!("  Reads the command to run from stdin.");
                eprintln!(
                    "  Example: echo 'cat /etc/config' | entrouter kube my-pod -n production"
                );
                std::process::exit(1);
            }
            let pod = &args[2];
            let namespace = if args.len() >= 5 && args[3] == "-n" {
                Some(args[4].as_str())
            } else {
                None
            };
            let input = read_stdin();
            cmd_kube(pod, namespace, &input);
        }
        "cron" => {
            let schedule = if args.len() >= 3 {
                Some(args[2..].join(" "))
            } else {
                None
            };
            let input = read_stdin();
            cmd_cron(schedule.as_deref(), &input);
        }
        cmd => {
            let input = read_stdin();
            match cmd {
                "encode" => cmd_encode(&input),
                "decode" => cmd_decode(&input),
                "verify" => cmd_verify(&input),
                "raw-encode" => cmd_raw_encode(&input),
                "raw-decode" => cmd_raw_decode(&input),
                "exec" => cmd_exec(&input),
                other => {
                    eprintln!("Unknown command: {other}");
                    eprintln!("Try: encode, decode, verify, raw-encode, raw-decode, ssh, multi-ssh, scp, docker, kube, cron, exec");
                    std::process::exit(1);
                }
            }
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

/// ssh: encode a command locally, send it over SSH, decode and execute on remote
fn cmd_ssh(host: &str, command: &str) {
    let encoded = entrouter_universal::encode_str(command);

    // The remote side decodes the base64 and pipes it into sh
    // The base64 string is shell-safe -- no quotes, braces, or special chars
    let remote_cmd = format!("echo '{}' | entrouter raw-decode | sh", encoded);

    let status = Command::new("ssh")
        .args(ssh_args())
        .arg(host)
        .arg(&remote_cmd)
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status()
        .unwrap_or_else(|e| {
            eprintln!("Failed to run ssh: {e}");
            std::process::exit(1);
        });

    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
}

/// multi-ssh: execute the same command on multiple hosts sequentially
fn cmd_multi_ssh(hosts_str: &str, command: &str) {
    let encoded = entrouter_universal::encode_str(command);
    let remote_cmd = format!("echo '{}' | entrouter raw-decode | sh", encoded);
    let hosts: Vec<&str> = hosts_str.split(',').map(|h| h.trim()).collect();

    let mut any_failed = false;
    for host in &hosts {
        eprintln!("[{}]", host);
        let status = Command::new("ssh")
            .args(ssh_args())
            .arg(host)
            .arg(&remote_cmd)
            .stdin(std::process::Stdio::inherit())
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .status();

        match status {
            Ok(s) => {
                if !s.success() {
                    eprintln!("[{}] exited with code {}", host, s.code().unwrap_or(-1));
                    any_failed = true;
                }
            }
            Err(e) => {
                eprintln!("[{}] SSH failed: {}", host, e);
                any_failed = true;
            }
        }
    }

    if any_failed {
        std::process::exit(1);
    }
}

/// scp: transfer a local file to a remote host via SSH
/// Reads the file as bytes, base64-encodes it, pipes through SSH to
/// `entrouter raw-decode` on the remote side which writes the file.
fn cmd_scp(local_file: &str, dest: &str) {
    let (host, remote_path) = match dest.split_once(':') {
        Some((h, p)) if !h.is_empty() && !p.is_empty() => (h, p),
        _ => {
            eprintln!("Invalid destination. Use: user@host:/remote/path");
            std::process::exit(1);
        }
    };

    let content = std::fs::read(local_file).unwrap_or_else(|e| {
        eprintln!("Failed to read '{}': {}", local_file, e);
        std::process::exit(1);
    });

    let encoded = entrouter_universal::encode(&content);
    let escaped_path = format!("'{}'", remote_path.replace('\'', "'\\''"));
    let remote_cmd = format!("entrouter raw-decode > {}", escaped_path);

    let mut child = Command::new("ssh")
        .args(ssh_args())
        .arg(host)
        .arg(&remote_cmd)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .unwrap_or_else(|e| {
            eprintln!("Failed to run ssh: {e}");
            std::process::exit(1);
        });

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(encoded.as_bytes()).unwrap_or_else(|e| {
            eprintln!("Failed to write to ssh stdin: {e}");
            std::process::exit(1);
        });
    }

    let status = child.wait().unwrap_or_else(|e| {
        eprintln!("Failed to wait on ssh: {e}");
        std::process::exit(1);
    });

    if status.success() {
        eprintln!(
            "Transferred {} bytes to {}:{}",
            content.len(),
            host,
            remote_path
        );
    } else {
        std::process::exit(status.code().unwrap_or(1));
    }
}

/// docker: encode a command locally, decode and execute inside a container
fn cmd_docker(container: &str, command: &str) {
    let encoded = entrouter_universal::encode_str(command);

    // base64 -d is available in virtually every container image - zero dependencies
    let remote_cmd = format!("echo '{}' | base64 -d | sh", encoded);

    let status = Command::new("docker")
        .args(["exec", container, "sh", "-c", &remote_cmd])
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status()
        .unwrap_or_else(|e| {
            eprintln!("Failed to run docker: {e}");
            std::process::exit(1);
        });

    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
}

/// kube: encode a command locally, decode and execute inside a Kubernetes pod
fn cmd_kube(pod: &str, namespace: Option<&str>, command: &str) {
    let encoded = entrouter_universal::encode_str(command);

    let remote_cmd = format!("echo '{}' | base64 -d | sh", encoded);

    let mut cmd = Command::new("kubectl");
    cmd.arg("exec");
    if let Some(ns) = namespace {
        cmd.args(["-n", ns]);
    }
    cmd.args([pod, "--", "sh", "-c", &remote_cmd]);
    cmd.stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit());

    let status = cmd.status().unwrap_or_else(|e| {
        eprintln!("Failed to run kubectl: {e}");
        std::process::exit(1);
    });

    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
}

/// cron: encode a command into a cron-safe line (no % or special chars to break crontab)
fn cmd_cron(schedule: Option<&str>, command: &str) {
    let encoded = entrouter_universal::encode_str(command);
    let execution = format!("echo '{}' | base64 -d | sh", encoded);

    match schedule {
        Some(sched) => println!("{} {}", sched, execution),
        None => println!("{}", execution),
    }
}

/// exec: decode base64 from stdin and execute it locally
fn cmd_exec(input: &str) {
    match entrouter_universal::decode(input) {
        Ok(bytes) => {
            let command = String::from_utf8_lossy(&bytes);
            let status = if cfg!(windows) {
                Command::new("cmd")
                    .args(["/C", &command])
                    .stdin(std::process::Stdio::inherit())
                    .stdout(std::process::Stdio::inherit())
                    .stderr(std::process::Stdio::inherit())
                    .status()
            } else {
                Command::new("sh")
                    .args(["-c", &command])
                    .stdin(std::process::Stdio::inherit())
                    .stdout(std::process::Stdio::inherit())
                    .stderr(std::process::Stdio::inherit())
                    .status()
            };

            match status {
                Ok(s) => {
                    if !s.success() {
                        std::process::exit(s.code().unwrap_or(1));
                    }
                }
                Err(e) => {
                    eprintln!("Failed to execute: {e}");
                    std::process::exit(1);
                }
            }
        }
        Err(e) => {
            eprintln!("Decode failed: {e}");
            std::process::exit(1);
        }
    }
}
