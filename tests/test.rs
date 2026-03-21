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

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Entrouter Universal v0.3 - Full Integration Test Suite
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

use entrouter_universal::{
    decode_str, encode_str, fingerprint_str, Chain, ChainDiff, Envelope, Guardian, SignedEnvelope,
    UniversalStruct,
};
use std::thread::sleep;
use std::time::Duration;

static NIGHTMARE: &str = concat!(
    "'; DROP TABLE users; -- UNION SELECT * FROM passwords; ",
    r#"{"key":"val\"ue","arr":[1,2,3],"evil":{"a":"b\\\\c"}}"#,
    "\x00\x01\x02\x03\x07\x08\x09\x0a\x0d\x0e\x0f",
    "héllo wörld 日本語 中文 한국어 العربية",
    "🔥💀🚀🎯⚡🖤🔑🛡️⚔️🏆",
    "%00%01%20%2F%3F%26%3D%23%25%2B",
    "<script>alert('xss')</script>",
    "*3\r\n$3\r\nSET\r\n$6\r\nmykey\r\n",
    "../../../../etc/passwd",
    "%s%s%s%n%n%n%x%x%x",
    "000001739850123456-000004521890000-a3f1b2-user\"john\"",
    "\u{200B}\u{200C}\u{200D}\u{FEFF}",
);

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  SUITE 1 - All Envelope Modes
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[test]
fn suite_envelope_all_modes() {
    println!("\n━━━━ SUITE 1: All Envelope Modes ━━━━\n");

    // Standard
    let env = Envelope::wrap(NIGHTMARE);
    let result = env.unwrap_verified().unwrap();
    assert_eq!(NIGHTMARE, result);
    println!("✅ Standard: nightmare payload survived");

    // URL safe - no + or / characters
    let env_url = Envelope::wrap_url_safe(NIGHTMARE);
    assert!(env_url
        .d
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_'));
    assert_eq!(NIGHTMARE, env_url.unwrap_verified().unwrap());
    println!("✅ URL-safe: no + or / in encoded, nightmare survived");

    // Compressed
    #[cfg(feature = "compression")]
    {
        let large = NIGHTMARE.repeat(50);
        let env_comp = Envelope::wrap_compressed(&large).unwrap();
        assert!(
            env_comp.d.len() < large.len(),
            "compressed should be smaller"
        );
        assert_eq!(large, env_comp.unwrap_verified().unwrap());
        println!("✅ Compressed: {}x payload, smaller on wire, survived", 50);
    }

    // TTL valid
    let env_ttl = Envelope::wrap_with_ttl(NIGHTMARE, 60);
    assert!(!env_ttl.is_expired());
    assert!(env_ttl.ttl_remaining().unwrap() > 0);
    assert_eq!(NIGHTMARE, env_ttl.unwrap_verified().unwrap());
    println!(
        "✅ TTL valid: nightmare survived, {} secs remaining",
        env_ttl.ttl_remaining().unwrap()
    );

    // TTL expired
    let env_expired = Envelope::wrap_with_ttl("stale", 0);
    sleep(Duration::from_millis(10));
    assert!(env_expired.is_expired());
    assert!(env_expired.unwrap_verified().is_err());
    println!("✅ TTL expired: correctly rejected after expiry");

    // Double JSON serialisation (worst offender)
    let json1 = env.to_json().unwrap();
    let json2 = serde_json::to_string(&json1).unwrap();
    let json1_back: String = serde_json::from_str(&json2).unwrap();
    let restored = Envelope::from_json(&json1_back).unwrap();
    assert_eq!(NIGHTMARE, restored.unwrap_verified().unwrap());
    println!("✅ Double JSON: survived double serialisation");
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  SUITE 2 - Chain Verification
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[test]
fn suite_chain() {
    println!("\n━━━━ SUITE 2: Chain Verification ━━━━\n");

    // Build a race audit chain
    let mut chain = Chain::new("race:listing_abc123 - OPENED");
    chain.append("user_john joined - token: 000001739850000001");
    chain.append("user_jane joined - token: 000001739850000002");
    chain.append("user_bob  joined - token: 000001739850000003");
    chain.append(&format!(
        "WINNER: user_john - token: 000001739850000001 - payload: {}",
        NIGHTMARE
    ));
    chain.append("race:listing_abc123 - CLOSED");

    let result = chain.verify();
    assert!(result.valid);
    assert_eq!(result.total_links, 6);
    println!("✅ Chain built and verified: {} links", result.total_links);
    println!("{}", chain.report());

    // Tamper with middle link
    let mut tampered = chain.clone();
    tampered.links[3].d = encode_str("TAMPERED - user_bob wins instead");
    let tampered_result = tampered.verify();
    assert!(!tampered_result.valid);
    assert_eq!(tampered_result.broken_at, Some(4));
    println!(
        "✅ Tampering detected at link {}",
        tampered_result.broken_at.unwrap()
    );

    // Serialise and restore
    let json = chain.to_json().unwrap();
    let restored = Chain::from_json(&json).unwrap();
    assert!(restored.verify().valid);
    println!("✅ Chain serialised and restored: still valid");
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  SUITE 3 - Per-Field Struct Wrapping
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[test]
fn suite_universal_struct() {
    println!("\n━━━━ SUITE 3: Per-Field Struct Wrapping ━━━━\n");

    // Real Entrouter race winner struct
    let wrapped = UniversalStruct::wrap_fields(&[
        (
            "token",
            "000001739850123456-000004521890000-a3f1b2-user_john",
        ),
        ("user_id", "john's account \"special\""),
        ("amount", "299.99"),
        ("listing_id", "listing:abc\\123"),
        ("proof", NIGHTMARE),
    ]);

    // All fields intact
    let result = wrapped.verify_all();
    assert!(result.all_intact);
    assert_eq!(result.violations.len(), 0);
    println!("✅ All 5 fields verified intact");
    println!("{}", wrapped.report());

    // Mutate just the amount - simulates financial data tampering
    let mut tampered = wrapped.clone();
    tampered.fields[2].d = encode_str("999999.99");
    let result = tampered.verify_all();
    assert!(!result.all_intact);
    assert!(result.violations.contains(&"amount".to_string()));
    // Other fields unaffected
    assert!(result.fields[0].intact); // token still good
    assert!(result.fields[1].intact); // user_id still good
    assert!(!result.fields[2].intact); // amount VIOLATED
    assert!(result.fields[3].intact); // listing_id still good
    println!("✅ Field mutation detected - only 'amount' violated");
    println!("{}", tampered.report());

    // to_map
    let map = wrapped.to_map().unwrap();
    assert_eq!(map["amount"], "299.99");
    assert_eq!(map["user_id"], "john's account \"special\"");
    println!("✅ to_map(): all fields accessible by name");

    // Serialise round trip
    let json = wrapped.to_json().unwrap();
    let restored = UniversalStruct::from_json(&json).unwrap();
    restored.assert_intact();
    assert_eq!(restored.get("proof").unwrap(), NIGHTMARE);
    println!("✅ Serialised and restored: nightmare proof field survived");
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  SUITE 4 - Guardian Full Pipeline
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[test]
fn suite_guardian() {
    println!("\n━━━━ SUITE 4: Guardian Full Pipeline ━━━━\n");

    // Clean pipeline
    let mut g = Guardian::new(NIGHTMARE);
    let clean = g.encoded().to_string();
    g.checkpoint("http_ingress", &clean);
    g.checkpoint("json_parse", &clean);
    g.checkpoint("rust_processing", &clean);
    g.checkpoint("redis_write", &clean);
    g.checkpoint("redis_read", &clean);
    g.checkpoint("postgres_write", &clean);
    g.checkpoint("postgres_read", &clean);
    g.checkpoint("http_egress", &clean);
    g.assert_intact();
    println!("✅ 8-layer clean pipeline: all intact");

    // Redis mangles it
    let mut g2 = Guardian::new(NIGHTMARE);
    let clean2 = g2.encoded().to_string();
    g2.checkpoint("http_ingress", &clean2);
    g2.checkpoint("json_parse", &clean2);
    g2.checkpoint("rust_processing", &clean2);
    g2.checkpoint("redis_write", &encode_str("redis mangled it 💀"));
    g2.checkpoint("postgres_write", &encode_str("postgres made it worse"));
    assert!(!g2.is_intact());
    assert_eq!(g2.first_violation().unwrap().layer, "redis_write");
    println!("✅ Mutation pinpointed at redis_write");
    println!("{}", g2.report());
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  SUITE 5 - Cross-machine simulation
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[test]
fn suite_cross_machine() {
    println!("\n━━━━ SUITE 5: Cross-Machine Simulation ━━━━\n");

    // Simulate: Windows PC wraps → SSH → Ubuntu VPS unwraps
    // Same crate on both = identical Base64 and SHA-256

    // "PC side"
    let env = Envelope::wrap(NIGHTMARE);
    let wire_payload = env.to_json().unwrap();

    // "VPS side" - receives wire_payload over SSH/network
    let received = Envelope::from_json(&wire_payload).unwrap();
    let verified = received.unwrap_verified().unwrap();
    assert_eq!(NIGHTMARE, verified);
    println!("✅ Cross-machine: PC wrapped → VPS verified - identical");

    // With per-field struct
    let wrapped = UniversalStruct::wrap_fields(&[("token", NIGHTMARE), ("user_id", "john")]);
    let wire = wrapped.to_json().unwrap();

    // VPS side
    let restored = UniversalStruct::from_json(&wire).unwrap();
    restored.assert_intact();
    assert_eq!(restored.get("token").unwrap(), NIGHTMARE);
    println!("✅ Cross-machine struct: per-field integrity verified on VPS");

    // Chain across machines
    let mut chain = Chain::new("PC: race started");
    chain.append("PC: winner determined");
    let wire_chain = chain.to_json().unwrap();

    // VPS verifies
    let vps_chain = Chain::from_json(&wire_chain).unwrap();
    assert!(vps_chain.verify().valid);
    println!("✅ Cross-machine chain: audit trail verified on VPS");
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  SUITE 6 - Low-Level Primitives (encode_str, decode_str, fingerprint_str)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[test]
fn suite_primitives() {
    println!("\n━━━━ SUITE 6: Low-Level Primitives ━━━━\n");

    // Basic round-trip
    let decoded = decode_str(&encode_str("some data")).unwrap();
    assert_eq!(decoded, "some data");
    println!("✅ encode_str/decode_str round-trip: basic string survived");

    // Fingerprint is always 64 hex chars (SHA-256)
    let fp = fingerprint_str("some data");
    assert_eq!(fp.len(), 64);
    assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    println!("✅ fingerprint_str: 64 hex chars - {}", fp);

    // Same input = same fingerprint (deterministic)
    assert_eq!(fingerprint_str("hello"), fingerprint_str("hello"));
    println!("✅ fingerprint_str: deterministic - same input = same hash");

    // Different input = different fingerprint
    assert_ne!(fingerprint_str("hello"), fingerprint_str("world"));
    println!("✅ fingerprint_str: different input = different hash");

    // Nightmare payload round-trip through primitives
    let encoded = encode_str(NIGHTMARE);
    let decoded_nightmare = decode_str(&encoded).unwrap();
    assert_eq!(decoded_nightmare, NIGHTMARE);
    println!("✅ encode_str/decode_str: nightmare payload survived");

    // Fingerprint of nightmare is stable
    let fp1 = fingerprint_str(NIGHTMARE);
    let fp2 = fingerprint_str(NIGHTMARE);
    assert_eq!(fp1, fp2);
    assert_eq!(fp1.len(), 64);
    println!(
        "✅ fingerprint_str: nightmare fingerprint stable - {}",
        &fp1[..16]
    );

    // Empty string
    let empty_decoded = decode_str(&encode_str("")).unwrap();
    assert_eq!(empty_decoded, "");
    let empty_fp = fingerprint_str("");
    assert_eq!(empty_fp.len(), 64);
    println!("✅ Primitives handle empty string");
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  SUITE 7 - Signed Envelopes (HMAC-SHA256)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[test]
fn suite_signed_envelope() {
    println!("\n━━━━ SUITE 7: Signed Envelopes ━━━━\n");
    let key = "super-secret-key-2024";

    // Standard mode round-trip
    let env = SignedEnvelope::wrap(NIGHTMARE, key);
    let result = env.unwrap_verified(key).unwrap();
    assert_eq!(NIGHTMARE, result);
    println!("✅ Standard signed: nightmare payload survived");

    // URL-safe mode
    let env_url = SignedEnvelope::wrap_url_safe(NIGHTMARE, key);
    assert_eq!(NIGHTMARE, env_url.unwrap_verified(key).unwrap());
    println!("✅ URL-safe signed: nightmare survived");

    // Compressed mode
    #[cfg(feature = "compression")]
    {
        let large = NIGHTMARE.repeat(50);
        let env_comp = SignedEnvelope::wrap_compressed(&large, key).unwrap();
        assert!(env_comp.d.len() < large.len());
        assert_eq!(large, env_comp.unwrap_verified(key).unwrap());
        println!("✅ Compressed signed: survived");
    }

    // TTL mode - valid
    let env_ttl = SignedEnvelope::wrap_with_ttl("time-limited", key, 300);
    assert_eq!("time-limited", env_ttl.unwrap_verified(key).unwrap());
    println!("✅ TTL signed: valid within window");

    // TTL mode - expired
    let env_expired = SignedEnvelope::wrap_with_ttl("expired-data", key, 0);
    sleep(Duration::from_millis(50));
    assert!(env_expired.unwrap_verified(key).is_err());
    println!("✅ TTL signed: correctly rejected after expiry");

    // Wrong key
    let env_wrong = SignedEnvelope::wrap("secret payload", key);
    assert!(env_wrong.unwrap_verified("wrong-key").is_err());
    println!("✅ Wrong key: correctly rejected");

    // JSON round-trip
    let env_json = SignedEnvelope::wrap(NIGHTMARE, key);
    let json_str = env_json.to_json().unwrap();
    let restored = SignedEnvelope::from_json(&json_str).unwrap();
    assert_eq!(NIGHTMARE, restored.unwrap_verified(key).unwrap());
    println!("✅ JSON round-trip: signed envelope survived serialization");

    // Tamper detection -- modify the data after signing
    let mut env_tamper = SignedEnvelope::wrap("original", key);
    env_tamper.d = entrouter_universal::encode_str("tampered");
    assert!(env_tamper.unwrap_verified(key).is_err());
    println!("✅ Tamper detection: modified data correctly rejected");
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  SUITE 8 - Chain Diff & Merge
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[test]
fn suite_chain_diff_merge() {
    println!("\n━━━━ SUITE 8: Chain Diff & Merge ━━━━\n");

    // Identical chains
    let mut a = Chain::new("genesis");
    a.append("link 2");
    a.append("link 3");

    let a_json = a.to_json().unwrap();
    let b = Chain::from_json(&a_json).unwrap();

    let diff = Chain::diff(&a, &b);
    assert_eq!(diff.common_length, 3);
    assert_eq!(diff.a_extra, 0);
    assert_eq!(diff.b_extra, 0);
    assert_eq!(diff.diverges_at, None);
    println!("✅ Identical chains: common=3, no divergence");

    // Prefix chain -- B is longer
    let mut b_longer = Chain::from_json(&a_json).unwrap();
    b_longer.append("link 4");
    b_longer.append("link 5");

    let diff2 = Chain::diff(&a, &b_longer);
    assert_eq!(diff2.common_length, 3);
    assert_eq!(diff2.a_extra, 0);
    assert_eq!(diff2.b_extra, 2);
    assert_eq!(diff2.diverges_at, None);
    println!("✅ Prefix chain: A(3) is prefix of B(5)");

    // Merge prefix -- should return the longer
    let merged = Chain::merge(&a, &b_longer).unwrap();
    assert_eq!(merged.len(), 5);
    assert!(merged.verify().valid);
    println!("✅ Merge prefix: returned longer chain (5 links), valid");

    // Divergent chains -- both extend differently
    let mut c = Chain::new("different genesis");
    c.append("link 2 alt");
    let diff3 = Chain::diff(&a, &c);
    assert_eq!(diff3.common_length, 0);
    assert!(diff3.diverges_at.is_some());
    println!(
        "✅ Divergent chains: diverge at link {}",
        diff3.diverges_at.unwrap()
    );

    // Merge divergent -- should error
    let merge_err = Chain::merge(&a, &c);
    assert!(merge_err.is_err());
    println!("✅ Merge divergent: correctly rejected");

    // ChainDiff serialization
    let diff_json = serde_json::to_string(&diff).unwrap();
    let diff_restored: ChainDiff = serde_json::from_str(&diff_json).unwrap();
    assert_eq!(diff, diff_restored);
    println!("✅ ChainDiff: JSON round-trip");
}
