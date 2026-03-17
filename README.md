# Entrouter-Universal

> **What goes in, comes out identical.**

Your data goes through HTTP. Then JSON. Then Rust. Then Redis. Then Postgres.  
Each layer thinks it's helping. Each layer is lying.  
By the time your data arrives it's been touched by five strangers.

`entrouter-universal` puts it in a box nobody can open.  
**Base64 at entry. SHA-256 fingerprint travels with it. Verify at exit. Done.**

```bash
cargo add entrouter-universal
```

---

## The Problem You've Been Living With

```
You send:     {"token":"abc\"def","user":"john's data"}
HTTP gets it: {"token":"abc\\"def","user":"john\\'s data"}
JSON gets it: {"token":"abc\\\\"def","user":"john\\\\'s data"}
Redis gets it: ...
Postgres gets it: ...
You receive:  what the fuck is this
```

Senior devs have been chasing this for decades.  
You fix it in one line.

---

## One Line Fix

```rust
// Entry point - wrap it
let env = Envelope::wrap(your_data);

// Pass env.to_json() through literally everything
// HTTP ✅  JSON ✅  Rust ✅  Redis ✅  Postgres ✅

// Exit point - verify it
let original = env.unwrap_verified().unwrap();
// Identical. Every time. Or it errors and tells you exactly why.
```

That's it. That's the whole thing.

---

## Five Tools

### 1. Envelope - Four Flavours

**Standard** - works everywhere
```rust
let env = Envelope::wrap(data);
let original = env.unwrap_verified()?;
```

**URL-Safe** - headers, query params, URLs
```rust
// Uses - and _ instead of + and /
// Zero breakage in URLs, HTTP headers, query strings
let env = Envelope::wrap_url_safe(data);
let original = env.unwrap_verified()?;
```

**Compressed** - large payloads
```rust
// Gzip first, then Base64
// Smaller on the wire. Transparent to you.
let env = Envelope::wrap_compressed(data)?;
let original = env.unwrap_verified()?; // auto-decompresses
```

**TTL - self-expiring data**
```rust
// Race tokens, session data, anything time-sensitive
let env = Envelope::wrap_with_ttl(data, 300); // dies in 5 minutes

println!("{} secs left", env.ttl_remaining().unwrap());

// 5 minutes later...
env.unwrap_verified() // Err(Expired) - cannot be replayed
```

**Where to store it:**
```rust
// Redis
redis.set("key", env.to_json()?).await?;

// Postgres
db.execute("INSERT INTO table (envelope) VALUES ($1)", &[&env.to_json()?]).await?;

// HTTP response
Response::json(env) // serde-compatible, ships as-is
```

---

### 2. Chain - Cryptographic Audit Trail

Each link references the previous link's fingerprint.  
Tamper with any link - everything after it breaks.  
You know exactly where the chain was cut.

```rust
let mut chain = Chain::new("race:listing_abc - OPENED");
chain.append("user_john joined - token: 000001739850000001");
chain.append("user_jane joined - token: 000001739850000002");
chain.append("WINNER: user_john - mathematically proven");
chain.append("race:listing_abc - CLOSED");

// Is the entire sequence intact?
let result = chain.verify();
assert!(result.valid);

// Someone tampers with link 3
chain.links[2].d = encode_str("TAMPERED");
let result = chain.verify();
println!("Broken at link: {}", result.broken_at.unwrap()); // 3

// Full report
println!("{}", chain.report());
// ━━━━ Entrouter Universal Chain Report ━━━━
// Links: 5 | Valid: false
//   Link 1: ✅ | fp: a3f1b2...
//   Link 2: ✅ | fp: 9f8e7d...
//   Link 3: ❌ VIOLATED
//   Link 4: ❌ VIOLATED
//   Link 5: ❌ VIOLATED
```

**Where to store it:**
```rust
let json = chain.to_json()?;

// Redis
redis.set("race:abc:audit", &json).await?;

// Postgres
db.execute("INSERT INTO audit_log (chain) VALUES ($1)", &[&json]).await?;

// Restore and verify anywhere, anytime
let restored = Chain::from_json(&json)?;
assert!(restored.verify().valid);
```

**Use case:** Legal proof of who won a race, in what order, with mathematical certainty. Download it. Verify it in court. Nobody argues with SHA-256.

---

### 3. UniversalStruct - Per-Field Integrity

Not "something broke somewhere."  
**"`amount` was tampered with between Redis and Postgres."**

```rust
let wrapped = UniversalStruct::wrap_fields(&[
    ("token",      "000001739850123456-000004521890000-a3f1b2-user_john"),
    ("user_id",    "john"),
    ("amount",     "299.99"),
    ("listing_id", "listing:abc123"),
]);

// Everything intact
let result = wrapped.verify_all();
assert!(result.all_intact);

// Get a specific field - verified on access
let token = wrapped.get("token")?;

// Get everything as a HashMap
let map = wrapped.to_map()?;

// Simulate Redis mangling the amount field
wrapped.fields[2].d = encode_str("999999.99");

let result = wrapped.verify_all();
// token      ✅
// user_id    ✅
// amount     ❌  ← you know exactly which field
// listing_id ✅

println!("{}", wrapped.report());
// ━━━━ Entrouter Universal Field Report ━━━━
//   token:      ✅ - 000001739850123456...
//   user_id:    ✅ - john
//   amount:     ❌ VIOLATED
//   listing_id: ✅ - listing:abc123
```

**Where to store it:**
```rust
let json = wrapped.to_json()?;

// Redis
redis.set("winner:abc", &json).await?;

// Postgres
db.execute("INSERT INTO race_winners (fields) VALUES ($1)", &[&json]).await?;

// Restore and verify field-by-field on the other side
let restored = UniversalStruct::from_json(&json)?;
let amount = restored.get("amount")?; // verified or Err
```

---

### 4. Guardian - Find The Exact Layer That Broke It

```rust
let mut g = Guardian::new(data);
let encoded = g.encoded().to_string();

g.checkpoint("http_ingress",    &value_at_http);
g.checkpoint("json_parse",      &value_at_json);
g.checkpoint("redis_write",     &value_at_redis);
g.checkpoint("postgres_write",  &value_at_postgres);

println!("Broken at: {}", g.first_violation().unwrap().layer);
// "redis_write"

println!("{}", g.report());
// ━━━━ Entrouter Universal Pipeline Report ━━━━
//   Layer 1: http_ingress   - ✅
//   Layer 2: json_parse     - ✅
//   Layer 3: redis_write    - ❌ VIOLATED
//   Layer 4: postgres_write - ❌ VIOLATED

g.assert_intact(); // panics with layer name in tests
```

---

### 5. Core Primitives

```rust
use entrouter_universal::{encode_str, decode_str, fingerprint_str, verify};

let encoded  = encode_str(data);
let original = decode_str(&encoded)?;
let fp       = fingerprint_str(data);
let result   = verify(&encoded, &fp)?;
```

---

## Why Base64

| Layer | Breaks on | Base64 safe? |
|---|---|---|
| HTTP | `"`, `\`, newlines | ✅ |
| JSON | `"`, `\`, control chars | ✅ |
| Rust | `"`, `\`, null bytes | ✅ |
| Redis | newlines, spaces | ✅ |
| Postgres | `'`, `\`, null bytes | ✅ |
| URLs | `+`, `/`, `=` (use url_safe) | ✅ |

Every layer sees a boring alphanumeric string. Nothing to escape. Problem solved at the encoding level - not the escaping level.

---

## Cross-Machine

Both boxes. One crate. Base64 and SHA-256 are universal standards - identical on Windows, Linux, Mac, ARM, x86, anywhere.

```
Your PC                         Ubuntu VPS
Envelope::wrap(data)    →SSH→   Envelope::from_json(wire)
                                .unwrap_verified() ✅
```

---

## Tested Against The Worst

```
SQL injection        ✅  '; DROP TABLE users; --
JSON breaking        ✅  {"key":"val\"ue","nested":"b\\\\c"}
Null bytes           ✅  \x00\x01\x02\x03
Unicode hellscape    ✅  日本語 中文 한국어 العربية
Emoji overload       ✅  🔥💀🚀🎯⚡🖤
XSS attempts         ✅  <script>alert('xss')</script>
Redis protocol       ✅  *3\r\n$3\r\nSET\r\n
Path traversal       ✅  ../../../../etc/passwd
Format strings       ✅  %s%s%s%n%n%n
Zero-width chars     ✅  ​‌‍
```

**21 tests. Zero failures.**

---

## License
Apache-2.0 - Free for open-source.
Commercial license available for closed-source / proprietary use.
Contact hello@entrouter.com

*Part of the Entrouter suite - [entrouter.com](https://entrouter.com)*