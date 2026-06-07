# crumble

Extract the crumbs browsers leave behind.

`crumble` is a cross-platform browser artifact and credential extractor for
**authorized** red team engagements, penetration tests and DFIR work. It
enumerates installed browsers and profiles, then extracts (and, where the
platform allows, decrypts) stored logins, cookies, payment cards, OAuth
tokens, autofill, history, downloads, bookmarks and extensions.

Supported browsers: Chrome, Edge, Brave, Chromium, Opera, Vivaldi, Firefox
(+ Safari inventory on macOS). Supported platforms: Windows, macOS, Linux.

> [!WARNING]
> Only run `crumble` on systems you are explicitly authorized to assess.
> Extracting credentials and session tokens you do not own is illegal in most
> jurisdictions. The authors do not condone unauthorized use.

## What it does

- **Discovery:** finds browser installs and profiles across all interactive
  users (on Windows, elevated runs see every user's hive, not just the
  operator's).
- **Decryption:**
  - *Windows*: Chromium `v10` (DPAPI) and `v20` (App-Bound Encryption)
    blobs. ABE unwrap goes through the browser's own `IElevator` COM
    elevation service, invoked from inside a suspended instance of the
    browser itself ("same-image" execution), so the service's caller
    validation passes.
  - *macOS*: Chromium `v10` via the login Keychain "Safe Storage" secret,
    read only when the login keychain is already unlocked (it never triggers
    the system unlock dialog).
  - *Linux*: legacy `v10` via the well-known hardcoded key; keyring-wrapped
    `v11` values are reported unsupported.
  - Firefox logins are NSS-encrypted and are reported as metadata only
    (hostname plus presence of a stored secret). Firefox cookie values are
    plaintext.
- **Clean reads:** live databases are never opened in place. Every store is
  byte-copied (with WAL sidecars) into a private, owner-only temp directory
  under a neutral name and queries run against the copy.
- **Operator-configurable OPSEC:** decryption and in-browser extraction can
  be skipped outright (`--no-decrypt`) or made EDR-aware (`--respect-edr`
  skips intrusive key retrieval when an EDR/AV product is detected).

Everything a store yields is emitted: there is no post-collection field
filtering. Your selection decides what is *attempted*; the output reports
what was actually *collected*.

## Usage

```console
$ crumble --help
```

```console
# Everything it can find, decrypted, pretty JSON on stdout
$ crumble

# Same, one record per line
$ crumble --format jsonl > crumbs.jsonl

# One browser, one artifact class, last 30 days, max 100 rows per class
$ crumble -b firefox -a history --history-days 30 --max-items 100

# Inventory and counts only: no keychain read, no DPAPI/ABE unwrap,
# no in-browser extraction
$ crumble --no-decrypt

# Cautious engagements: skip intrusive key retrieval if EDR/AV is present
$ crumble --respect-edr
```

## Configuration

All configuration is command-line flags (repeatable flags stack). Selection
is fail-closed: a browser or artifact name that matches nothing known makes
the whole selection match nothing, rather than widening to "all".

| flag | default | meaning |
|------|---------|---------|
| `-b, --browser <id>` | all detected | target browser: `chrome` `edge` `brave` `chromium` `opera` `vivaldi` `firefox` `safari` |
| `-a, --artifact <id>` | all | artifact class: `profiles` `credentials` `history` `downloads` `cookies` `autofill` `bookmarks` `extensions` (`credentials` also covers payment cards, IBANs and OAuth tokens) |
| `--decrypt` / `--no-decrypt` | `--decrypt` | resolve master keys and decrypt secret values; `--no-decrypt` collects counts and plaintext artifacts only: no Keychain read, no DPAPI/ABE unwrap, no in-browser extraction |
| `--respect-edr` / `--no-respect-edr` | `--no-respect-edr` | with `--respect-edr`, skip intrusive key retrieval (process manipulation on Windows, the Keychain read on macOS, the DPAPI unwrap) when an EDR/AV product is detected; counts are still collected |
| `--history-days <n>` | `0` (all) | limit history/download lookback to the last n days |
| `--max-items <n>` | `0` (unlimited) | cap rows emitted per artifact class across the whole run; per-store counts always reflect the full store |
| `--format <json\|jsonl>` | `json` | output format |

Notes on the knobs:

- **`--no-decrypt`** is the fast, quiet mode: profile inventory, exact counts,
  plaintext artifacts (history, downloads, bookmarks, extensions, Firefox
  cookies) and credential-store rows with sealed values. It performs zero
  key retrieval.
- **`--respect-edr`** exists so an authorized operator can avoid reading as
  an infostealer to the customer's SOC during sensitive engagements. When it
  triggers, the run's `key_status` reports exactly which products were seen.
- **`--max-items`** caps the row sample, never the exposure counts. The
  counts are the finding.
- The macOS Keychain read happens only on the decryption path and only when
  the login keychain is already unlocked; a locked keychain (or a denied
  per-item ACL) is reported as `unavailable` in `key_status`, never prompted.

## Output

One JSON report (or JSONL: a summary record, then one record per row with a
`kind` discriminator). Top-level sections:

- `profiles`: one summary per profile (display name, path, exact per-store
  counts (`credential_count`, `cookie_count`, `history_count`).
- `credentials`, `cookies`, `credit_cards`, `iban_entries`, `oauth_tokens`
  and `autofill`: the secret/payment classes. `password_stored` and the card
  ciphertext `number_enc` are the always-present exposure proofs; decrypted
  values are empty when no key resolved.
- `history`, `downloads`, `bookmarks` and `extensions`: the plaintext classes.
- `findings`: one per browser, a counts-only exposure summary with severity
  (`medium` when decryptable secret material is present, `low` when a store
  existed but could not be read, else `info`).
- `key_status`: per-browser master-key outcome (`abe`, `dpapi`, `keychain`,
  `peanuts`, `not-applicable: …`, `unavailable: …`, `error: …`).
- `collection_errors`: store-level failures as `browser/profile/store:
  reason`; an unreadable store is recorded, never reported as empty.

## Building

```console
$ cargo build --release
```

Pure Rust dependencies (SQLite is compiled from source); the Windows build
adds `windows-sys`. Cross-compile with `cargo-zigbuild`/`cross` as usual:

```console
$ cargo zigbuild --release --target x86_64-pc-windows-msvc
$ cargo zigbuild --release --target x86_64-unknown-linux-gnu
```

## FAQ

**Is this an infostealer?** It is the same primitive, operated under
authorization: it reads what browsers store locally for their own user.
Every such machine is readable by software running as that user. That is
the finding `crumble` is built to demonstrate to a customer.

**Why is Firefox login decryption unsupported?** Firefox protects logins
with NSS (3DES/AES under a `key4.db` master key, itself optionally
password-wrapped by a primary password). Decrypting without the primary
password is not implemented; the metadata (hostname, `password_stored`) is
still reported.

**Why does macOS report the key as unavailable?** The login keychain is
locked or its per-item ACL denied the read. `crumble` never triggers
Keychain UI; an unlocked keychain (or an ACL grant) is required.

**What happens when Chrome's elevation service rejects the unwrap?** The
in-browser attempt is recorded as an error in `key_status` and the run falls
back to plaintext stores; it never degrades to reading the stores from the
wrong identity.

## Legal

Use responsibly and only under authorization covered by your engagement's
rules of engagement and applicable law. You are liable for your own
compliance. See [LICENSE](LICENSE).
