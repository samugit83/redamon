"""
RedAmon Cryptographic Attack Skill Prompts

Built-in attack skill workflow for breaking cryptographic constructions the
target trusts: decrypting or forging an attacker-controllable ciphertext, cookie,
token, signature, or MAC by exploiting a flaw in HOW it is encrypted, signed,
hashed, or seeded - padding oracles, CBC/stream malleability, ECB structure, JWT
signature attacks, hash length extension, weak or predictable keys/randomness, and
the classic RSA / asymmetric weaknesses.

CRYPTO_ATTACK_TOOLS is injected VERBATIM (no .format()) by
build_builtin_skill_workflow when attack_path_type == "crypto_attack". Because it
is never run through str.format(), it may contain literal { and } (Python dicts,
JSON, byte reprs) freely. Do NOT add a .format() call for this constant, and if
you ever do, double every literal brace first.

The content is a GENERIC playbook written with NO target knowledge: every value,
key, endpoint, cookie name, error string, and length below is a placeholder or a
universally-true property of the construction (e.g. "a length that is a multiple
of the block size", "the server answers differently for a padding error than for
a content error"). The agent must DISCOVER the target's real token, cipher, error
behaviour, and objective from the live target; never hard-code them here.

Tool accuracy: this skill only names crypto tooling verified present in the
execution environments - Python via `execute_code` (PyCryptodome as `Crypto` /
`Cryptodome`, `cryptography`, pwntools as `pwn`, PyJWT as `jwt`, `hashlib`/`hmac`,
`requests`, `base64`/`binascii`/`secrets`) and CLI via `kali_shell` (`openssl`,
`jwt_tool`, `hashcat`, `john`). Tools that are NOT installed (padbuster, hashpump,
sage, xortool, gmpy2, sympy) are deliberately not relied on: padding oracles and
length extension are SCRIPTED in Python rather than shelled out to a missing CLI.
The skill is written to name only GENERAL cryptographic tradecraft and to steer
the agent to a crypto surface WITHOUT ever describing any target's specific
weakness or the wrong turns to avoid. Keep it that way if you edit this file.
"""

CRYPTO_ATTACK_TOOLS = """
## Cryptographic Attack Workflow

Goal: when the app hands you a value it later DECRYPTS, VERIFIES, or otherwise
trusts cryptographically - a cookie, token, signature, MAC, parameter, or file -
attack the CONSTRUCTION directly. A secret you cannot read
directly is very often recoverable or forgeable through a flaw in how it is
encrypted, signed, hashed, or generated. Work measurement-first: prove each
property against the LIVE target before escalating, and script every byte-level
attack with `execute_code` (Python) - never hand-guess ciphertext bytes.

### STOP checks (avoid the classic wasted session)
- If a secret you need is ALSO carried in an encrypted / encoded / signed token
  you control, attack THAT token directly. Recovering it INDIRECTLY - guessing it,
  brute-forcing it, or deriving it from a side channel - can be slow or impossible,
  while attacking the token's construction is deterministic. Commit to the direct
  cryptographic path instead of lingering on indirect recovery.
- A decrypt / verify / login endpoint that answers DIFFERENTLY for a MALFORMED
  token (bad padding, bad signature, decode error) than for a WELL-FORMED but
  WRONG one (wrong content, failed auth) is leaking an ORACLE. That difference -
  in status code, body text, response length, redirect, or TIMING - is the single
  highest-value signal in this whole skill. Hunt for it early and deliberately.
- Encryption is not integrity. If you can flip bits of a ciphertext / IV and the
  plaintext changes predictably (no MAC rejects you), the token is MALLEABLE and
  you can often forge it without any key.
- Reuse the SAME session / auth the endpoint requires (authenticate first if it
  sits behind a login), and resend tokens through the exact request that consumes
  them - `execute_curl`, or `requests` inside `execute_code`, or replay a REAL
  captured request via `redamon.to_curl` -> `redamon.replay` when capture is on.
- Do not conclude "not vulnerable" from one probe. Decrypt-oracle, forge-oracle,
  malleability, weak-key, and predictable-token are DIFFERENT flaws; a token can
  be broken through only one of them. Satisfy the abandonment gate first.

### Step 1 - Inventory attacker-controlled cryptographic material
Enumerate every value you can resend that the server parses cryptographically:
cookies (session, "auth", "remember", CSRF), hidden form fields, URL / POST
params, `Authorization` / custom headers, and any "token" / "sig" / "state" /
"data" blob. For each: url-decode, then decode the encoding (base64, base64url,
hex, sometimes double-encoded) with `execute_code`. Record the RAW BYTE LENGTH and
whether it changes across issues of the same token. Reuse recon: `query_graph` for
already-mapped Endpoints / Parameters / Cookies; `redamon.search` / `redamon.params` /
`redamon.grep` to mine captured traffic for token-bearing requests.

### Step 2 - Fingerprint the construction from structure alone
- Raw length a multiple of 8 or 16, high entropy, no delimiters -> a BLOCK CIPHER
  (DES=8-byte blocks, AES=16). A leading block that changes on every issue while
  the tail is stable suggests CBC with a PREPENDED IV (first 16 bytes = IV).
- IDENTICAL plaintext blocks producing IDENTICAL ciphertext blocks (repeat a long
  run of one character in any field that gets encrypted and look for a repeated
  16-byte block) -> ECB.
- Three base64url parts split by dots -> a JWT: decode header + payload, read the
  `alg`. Go to Step 6.
- `data` value + a fixed-length trailer (16 / 20 / 32 / 64 bytes) -> a keyed MAC
  (`H(secret || data)` or HMAC). Note digest size to guess the hash. Go to Step 7.
- A big integer / two integers (n, e, c) or a `.pem` / modulus -> asymmetric. Step 8.
- Short, low-entropy, or human-ish after one decode -> classical / encoding. Step 10.

### Step 3 - Oracle detection and PADDING ORACLE (the primary lead)
Resubmit the token with SINGLE BYTES flipped (especially the last byte of the last
block, and bytes of the IV / preceding block) and CLASSIFY every response into
buckets: (a) decrypt / padding / format FAILURE, (b) decrypts-but-content-or-authz
REJECTED, (c) ACCEPTED. Compare status, body, length, and timing. If bucket (a) is
DISTINGUISHABLE from bucket (b), you have a CBC padding oracle:
- DECRYPT: recover the token's full plaintext block-by-block with the standard
  padding-oracle algorithm - for target block C_i, vary the preceding block (or the
  IV for the first block) byte-by-byte until the oracle reports VALID padding, which
  yields the intermediate D(C_i); XOR with the REAL preceding block to get the
  plaintext. This reveals secrets the app never meant to return, WITHOUT the key.
- FORGE / ENCRYPT: run the oracle in reverse to craft a ciphertext that decrypts to
  a plaintext YOU choose (e.g. a value that passes the check), again with no key.
Script it in `execute_code` (padbuster is NOT installed) - a ~40-line Python loop
over `requests` is enough; batch requests and be mindful of request volume /
noise. Timing-only oracles: measure many samples per byte and threshold.

### Step 4 - Malleability without an oracle (no key needed)
- CBC BIT-FLIPPING: to change plaintext byte j of block i, XOR byte j of the
  PRECEDING ciphertext block (or the IV, for block 0) by (known_pt ^ desired_pt).
  Corrupts block i-1, so target a block whose corruption the app ignores. Great for
  flipping a role / id / flag byte in an unauthenticated CBC token.
- ECB CUT-AND-PASTE: rearrange, duplicate, or splice equal-size ciphertext blocks
  to assemble a token the app accepts (e.g. move an "admin"-containing block into an
  authorization slot). Align your controllable input to block boundaries.
- ECB BYTE-AT-A-TIME decryption: if the app encrypts (attacker_input || secret)
  under ECB, recover the secret one byte at a time by prefixing crafted-length input
  and matching the first unknown byte against a dictionary of guesses.
- IV / nonce abuse: predictable, fixed, or attacker-settable IVs collapse CBC
  secrecy for the first block; IV = key is a known footgun.

### Step 5 - Stream cipher / CTR / GCM (keystream is the weakness)
- KEYSTREAM / NONCE REUSE (two-time pad): if two ciphertexts were produced with the
  same key+nonce (fixed nonce, or the same value re-encrypted), C1 XOR C2 = P1 XOR
  P2 - the keystream cancels. Recover plaintext by crib-dragging known structure, or
  recover the keystream directly from any one known plaintext then decrypt all
  others. Applies to RC4, AES-CTR, ChaCha, and AES-GCM used with a repeated nonce.
- Stream ciphers are MALLEABLE like Step 4: XOR a ciphertext byte to flip the same
  plaintext byte (no block boundary), so tamper tokens even without recovering the key.
- AES-GCM nonce reuse additionally leaks the auth key (forbidden attack) enabling
  tag forgery; at minimum, reuse breaks confidentiality via the two-time pad above.

### Step 6 - JWT attacks
Decode header + payload first. Then, in order of cheapness:
- `alg:none`: set header `alg` to `none` / `None` / `NONE`, drop the signature
  (keep the trailing dot), and see if the token is accepted. Naive dispatch-on-alg
  verifiers skip the check entirely.
- WEAK HS256/384/512 SECRET: crack the HMAC secret offline from a captured token
  with `hashcat -m 16500 <jwt> <wordlist>` or `john`, or `jwt_tool -C -d <wordlist>`.
  If it cracks, forge ANY claims (role/admin/id) and re-sign with that secret.
- ALGORITHM CONFUSION (RS256 -> HS256): if the server verifies asymmetrically,
  fetch its PUBLIC key (`/.well-known/jwks.json`, a `/publickey`/cert endpoint, or
  reconstruct it from two tokens), then forge a token with `alg:HS256` signed using
  that public key BYTES as the HMAC secret; a server that reuses one key field for
  both verifies it.
- `kid` / `jku` / `jwk` header injection: `kid` may be a path (point it at a known
  fixed-content file such as an empty/null-byte file and sign with the empty key) or
  an injection sink (SQLi / path traversal); `jku` may fetch an attacker-hosted JWKS;
  `jwk` may embed an attacker public key the server trusts. Use `jwt_tool` to
  automate these (`jwt_tool <token> -X <attack>`).

### Step 7 - Hash and MAC attacks
- HASH LENGTH EXTENSION: if a signature is `MAC = H(secret || message)` with a
  Merkle-Damgard hash (MD5, SHA1, SHA-256/512) - NOT HMAC - you can APPEND data and
  compute a valid MAC for (message || glue-padding || your-data) WITHOUT the secret,
  given the original MAC and the secret length (brute-force the length). No tool is
  preinstalled (hashpump/hashpumpy absent): script the Merkle-Damgard state-restore
  in `execute_code`, or `pip install hashpumpy` / build `hash_extender` if the
  sandbox has network. Signature over URL/query params (`?...&mac=`) is the classic sink.
- WEAK / MISSING MAC: if integrity rests on a plain hash or a guessable key, crack
  it (`hashcat`/`john`) or recompute it yourself once you learn the scheme.
- Recognise the hash by digest length (MD5=16, SHA1=20, SHA256=32) before choosing
  `hashcat -m`.

### Step 8 - RSA and asymmetric weaknesses (when you see n, e, c or a public key)
Use `execute_code` with `Crypto.Util.number` (inverse, GCD, isPrime, long_to_bytes)
and `openssl` to inspect keys. gmpy2/sympy are NOT installed - use integer math,
`Crypto.Util.number`, or query `http://factordb.com/api?query=<n>` via `requests`
for known factorisations. Classic breaks:
- Small `e` (e=3) with no padding and small message -> integer cube root of `c`.
- Shared prime between two moduli -> `gcd(n1, n2)` reveals `p`, then decrypt both.
- Close primes -> Fermat factorisation of `n`.
- Small private `d` -> Wiener continued-fraction attack.
- Same message under small `e` to `e` recipients -> Hastad broadcast (CRT + root).
- Textbook RSA malleability (multiply `c` by `s^e`) and Bleichenbacher PKCS#1 v1.5
  padding oracles (a decrypt endpoint that leaks padding validity - see Step 3).

### Step 9 - Predictable randomness and token generation
If tokens (session ids, password-reset tokens, OTPs, IVs, nonces) look
generated rather than encrypted: collect several consecutive samples and test for
PREDICTABILITY. LCG state is recoverable from a few outputs; Python's Mersenne
Twister state can be reconstructed from 624 consecutive 32-bit outputs (`pwn`
helps); time-seeded or counter-seeded generators are reproducible - reconstruct the
seed (try the server `Date` header as the seed) and regenerate the target value.
Sequential / incrementing tokens are simply enumerable.

### Step 10 - Classical and encoding quick wins (always try first, cheap)
Before assuming strong crypto, rule out ENCODING and classical ciphers: base64 /
base32 / hex / url / rot13 layers, single-byte and repeating-key XOR (recover the
key from known plaintext or english-frequency), Caesar / Vigenere / substitution,
Morse / baconian. `pwn` (`xor`), `openssl enc -d`, and `CyberChef`-style layered
decoding in `execute_code` handle these in seconds and prevent over-thinking.

### Tooling (verified available)
- `execute_code` (Python) is the primary weapon: `Crypto` / `Cryptodome`
  (PyCryptodome), `cryptography`, `pwn` (pwntools), `jwt` (PyJWT), `hashlib`,
  `hmac`, `requests`, `base64`, `binascii`, `secrets`. Script every oracle,
  bit-flip, keystream, JWT-forge, and RSA attack here.
- `kali_shell`: `openssl` (enc/dgst/rsa/x509 inspection), `jwt_tool` (JWT attack
  automation), `hashcat` / `john` (crack HMAC/JWT secrets, hashes, keys).
- `execute_curl` for single probes; `job_spawn` for long oracle sweeps; `redamon.to_curl`
  -> `redamon.replay` to resend a REAL captured token-bearing request; `fs_write` /
  `fs_read` to stage helper scripts and offloaded output.
- Not installed (do not depend on them): padbuster, hashpump, sage, xortool,
  gmpy2, sympy, PIL/numpy. Script the equivalent in Python instead.

### When to transition phases
The construction fingerprint (Step 1-2) is informational recon. The MOMENT the live
token reveals a concrete cryptographic weakness (a block-aligned length, an ECB
block repeat, a `alg` you can change, an error differential, an `n/e/c` triple, a
predictable token), request transition to exploitation and commit to the matching
step - do not keep re-describing the token. If you have named the weakness in your
thought but are still in recon, `switch_skill`/transition now.

### Reporting guidelines
Report: the token / material attacked and where it lived; the construction you
fingerprinted (cipher, mode, block size, hash, alg); the specific weakness and the
oracle / malleability / weak-key / predictability that enabled it; the exact
scripted attack (as a reproducible `execute_code` snippet); the recovered plaintext
or forged token; and the objective reached (the literal flag / secret, verbatim).

### Abandonment gate - do NOT declare a crypto target unsolved until:
1. Every attacker-controlled token was decoded and its construction fingerprinted
   (Step 1-2), including a block-repeat probe for ECB and a length check for CBC.
2. The decrypt / verify / login endpoint was probed for an ERROR DIFFERENTIAL
   (Step 3) - padding/format vs content/authz vs success buckets, including a
   TIMING comparison - and the buckets were recorded, not assumed absent.
3. At least one CONSTRUCTION-SPECIFIC attack was actually EXECUTED, not just
   proposed: padding oracle, bit-flip/malleability, ECB cut-and-paste or
   byte-at-a-time, keystream/nonce reuse, a JWT attack, hash length extension, an
   RSA break, or predictable-token reconstruction - whichever the fingerprint fits.
4. Classical/encoding layers (Step 10) were ruled out.
Only after all four, with the evidence logged, may you conclude the crypto is sound.
"""
