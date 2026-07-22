# BIP85 Deterministic Password Generator — Core Algorithm

## Overview

This program generates per-site deterministic passwords from a single BIP39 mnemonic.
Given the same mnemonic and site name, it always produces the same password.

## Prerequisites / Dependencies

The following BIP standards must be implemented (or provided by a library):

| Standard | Purpose                        |
|----------|--------------------------------|
| BIP39    | Mnemonic ↔ seed conversion     |
| BIP32    | Hierarchical deterministic keys|
| BIP85    | Application-specific child key derivation + encoding |

## Constants

```
MASTER_KEY_FILE       = "D:\password\key"       # UTF-16 encoded file
Mnemonic file encoding = UTF-16
Mnemonic passphrase   = ""                       # empty string

Valid mnemonic word counts: 12, 15, 18, 21, 24
Language: English

BIP85 app codes:
  base85  → "707785"
  base64  → "707764"

BIP85 path root: m/83696968'

Length ranges:
  base85  → [10, 80]
  base64  → [20, 86]

Default encoding  = base85
Default length    = 12
```

## Algorithm Step-by-Step

### Step 1 — Load & Validate Mnemonic

1. Read the file at `MASTER_KEY_FILE` as UTF-16 text.
2. Split by whitespace into a list of words.
3. Assert the word count is one of {12, 15, 18, 21, 24}.
4. Validate the mnemonic checksum against the English BIP39 wordlist.
5. Convert the mnemonic words (plus empty passphrase `""`) into a BIP39 master seed (64 bytes).

### Step 2 — Derive BIP32 Master Key

1. From the 64-byte seed, derive a BIP32 master key (private, mainnet).
2. This master key is the root of all subsequent derivations.

### Step 3 — Convert Site Name to Child Index

1. Take the UTF-8 bytes of the site identifier string (e.g. `"github"`).
2. Compute SHA256 hash of those bytes.
3. Take the **first 4 bytes** of the hash.
4. Interpret those 4 bytes as a big-endian unsigned integer.
5. Take that integer **modulo 2^31** (i.e. modulo 2147483648).
6. The result is the BIP32 child index `idx` (ensuring it is non-hardened, < 2^31).

Pseudocode:
```
hash   = SHA256(site.encode("utf-8"))
idx    = int.from_bytes(hash[0:4], "big") % 2147483648
```

### Step 4 — Construct BIP85 Derivation Path

Build the path string:

```
m/83696968'/{app_code}'/{length}'/{idx}'
```

Where:

| Component      | Source                                  |
|----------------|-----------------------------------------|
| `83696968'`    | BIP85 purpose code (hardened)           |
| `{app_code}'`  | Encoding app code (hardened)            |
| `{length}'`    | Desired password length (hardened)      |
| `{idx}'`       | Site index from Step 3 (hardened: add 2^31) |

**Important**: Each segment except `m` is a **hardened** index. The index `idx` from Step 3 is in the range [0, 2^31-1] (non-hardened). For the BIP85 path it must be hardened: `idx_hardened = idx + 2147483648`.

### Step 5 — BIP85 Derivation

1. Derive the child private key from the master key along the path.
2. Apply the BIP85 encoding function to the derived key:
   - For **base85**: use the bip85 base85 encoding (yields a string using 85 printable ASCII characters).
   - For **base64**: use the bip85 base64 encoding (yields a Base64 string).
3. The application data field of the result is the generated password.

### Step 6 — Length Handling

The generated password may be longer than the length encoded in the path (some BIP85 implementations pad). Therefore:

1. If the requested length is **below** the encoding's minimum range:
   - Generate at the **minimum** allowed length.
   - Truncate the resulting password to the requested length.
2. If the requested length is **above** the encoding's maximum range: **error**, exit.
3. Otherwise, generate at the requested length.

### Step 7 — Output

Print the final password string to stdout. Nothing else.

## Usage

```
pwgen <site> [-l <length>] [-e <encoding>]
```

| Argument        | Description                                      |
|-----------------|--------------------------------------------------|
| `site`          | Site identifier string (e.g. `github`, `google`) |
| `-l`, `--length`| Password length (default: 12)                    |
| `-e`, `--encoding`| `base85` (default) or `base64`                 |

## Encoding Details

| Encoding | App Code | Char Range | Example Characters            |
|----------|----------|------------|-------------------------------|
| base85   | 707785   | [10, 80]   | 85 printable ASCII (no quotes, no backslash) |
| base64   | 707764   | [20, 86]   | A–Z, a–z, 0–9, +, /, =        |

## Security Notes

- The mnemonic file should be protected (readable only by the user).
- The same mnemonic + site name always produces the same password.
- The site name is case-sensitive — treat it as an exact identifier.
- If the mnemonic is lost, ALL derived passwords are irrecoverable.
