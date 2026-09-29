# Key Management & Cold-Storage Guidance

Issue #115. This is the operational half of the toolkit's key handling: how keys
are generated, where they may live, how a deploy is signed, and what to do when
one is lost or exposed. The automated half is
`stellar-toolkit security secrets`, which enforces the "never committed" rule.

---

## 1. Threat model for key material

The toolkit holds exactly one kind of secret: the **Ed25519 private key** behind
a Stellar account, in one of two encodings.

| Material | Encoding | Compromise impact |
|----------|----------|-------------------|
| Secret key | `S…` strkey, 32-byte seed | Full control of the account: transfer, sign, deploy, change signers |
| Recovery phrase | 24-word BIP-39 mnemonic | Derives the same secret key at `m/44'/148'/0'` — equal impact |

Both are *bearer* credentials: possession is authority, there is no second
factor on-chain and no way to revoke a signature after the fact. Therefore the
only effective controls are (a) keeping the material out of places it can be
copied from, and (b) making a single key insufficient to move funds.

### Attack surface

| Surface | How a key leaks | Control |
|---------|-----------------|---------|
| Source control | A key pasted into a config, test, or doc | `security secrets` (CI gate), `.gitignore` |
| Shell history | `wallet recover "<phrase>"` typed at a prompt | Prefer `--phrase-file`/env input; clear history in shared shells |
| Process arguments | `wallet sign <S…>` visible in `ps`, `/proc/<pid>/cmdline` | Redacting `Debug` prevents logging it; args are still visible to the same user |
| Logs and CI output | `{:?}` of a command or wallet struct | Redacting `Debug` impls in `wallet.rs` and `cli.rs` |
| Error messages | A rejected key echoed back in the error | `decode_secret` masks the input |
| Build output | `target/` copied into a release artifact | `target/` is build-only; publish `dist/*.wasm` from `scripts/reproducible-build.sh` |
| Developer laptops | Plaintext key file in a synced folder | Cold storage (see §4) |

### What is explicitly *not* covered

* A compromised developer machine with the key unlocked. Cold storage exists
  because this case has no software control.
* Third-party RPC providers observing which account signs what. Use the
  endpoints in `config/<env>.toml` knowingly.
* Recovery from a lost key with no on-chain signer rotation configured. See §5.

---

## 2. Key tiers

| Tier | Where the key lives | Allowed operations |
|------|--------------------|--------------------|
| **Hot (dev/local)** | `.env` on a developer machine, Friendbot-funded | `dev` config only; no value |
| **Warm (test)** | GitHub Environment `test` secret, deployer account | Testnet deploys, contract upgrades |
| **Cold (prod)** | Air-gapped signer or hardware wallet, multisig | Mainnet deploys and upgrades only, via `prod` Environment approval |

`config/prod.toml` asserts the cold tier in data, and `env validate` fails if
`[security]` is missing or says otherwise:

```toml
[security]
require_multisig = true
cold_storage_signing = true
audit_log_retention_days = 365
```

---

## 3. Handling the recovery phrase

`stellar-toolkit wallet generate` prints a 24-word phrase **once** and warns that
it is shown only once. It is the backup: the `S…` key can be re-derived from it,
and nothing can re-derive the phrase.

Rules:

1. Write the phrase down on paper (or a steel backup) before funding the
   account. A funded account whose phrase was never recorded is unrecoverable.
2. Never store the phrase in a repository, an issue, a chat message, or a
   screenshot. `security secrets` detects committed phrases by validating the
   BIP-39 checksum, so a real phrase fails CI; a phrase-shaped string raises a
   warning.
3. Never type the phrase into a shared shell. If you must, clear history
   afterwards.
4. Treat the phrase and the `S…` key as the same secret at the same tier — the
   phrase is not "the backup tier" while the key is the "hot tier".

Derivation is fixed and documented: BIP-39 seed, SLIP-0010 hardened derivation
at `m/44'/148'/0'`. `wallet recover` verifies the checksum before deriving, so a
mistyped phrase is rejected rather than producing a different account.

---

## 4. Cold-storage signing

The toolkit **never** requires the production key to be online. The signing
boundary is the WASM artifact, not the key.

```bash
# 1. On an online machine: produce the artifact and its hashes.
./scripts/reproducible-build.sh
sha256sum target/wasm32v1-none/release/*.wasm > wasm-checksums.txt

# 2. Move wasm-checksums.txt + dist/*.wasm to the offline signer.
# 3. On the offline signer: verify the artifact is the one that was reviewed.
./scripts/verify-bytecode.sh --reference wasm-checksums.txt

# 4. Build and sign the deploy envelope offline, then carry the signed
#    envelope (never the key) back to a networked machine to submit.
```

The `deploy-prod-gate` job in `.github/workflows/release.yml` refuses to deploy
from a non-manual trigger, and GitHub Environment protection requires an
approver who is not the requester. Between them, no single person can deploy to
mainnet alone.

### Multisig

For a production account, `require_multisig = true` means the deployer account
has more than one signer and a medium/high threshold. The toolkit's own
`count_distinct_voters` / `quorum_status` helpers (and the m-of-n checks in
`contracts/payment-channel-contract`) exist because duplicate confirmations from
one signer must not reach quorum — the same reasoning applies to account-level
multisig thresholds.

---

## 5. Rotation and revocation

Order matters: **add the new signer, then remove the old one.** A key must never
be able to strand an account.

1. Generate the replacement key offline (`wallet generate` on the air-gapped
   machine).
2. Add it as a signer and raise the thresholds if needed.
3. Verify that transactions can be signed with the new signer and that the
   intended policy still holds.
4. Remove the old signer.
5. Record the change in the deployment audit log
   (`logs/deployment-audit.log`, appended by the release workflow).

**If a key is exposed (assume it is compromised):**

1. Immediately move any operator-controlled assets with a *fresh* key — do not
   reuse the exposed one to "clean up".
2. Remove the exposed signer from every account and contract-admin role.
3. Rotate anything the key could authorize, including contract admin keys, and
   re-run `scripts/verify-bytecode.sh` on the deployed contracts to confirm the
   deployed code is the code that was reviewed.
4. Record the incident; the audit log retention in `config/prod.toml` is 365
   days precisely so this is possible after the fact.

---

## 6. Automated checks

```bash
# Scan the repository (or specific roots) for secret material.
cargo run -p stellar-toolkit -- security secrets
cargo run -p stellar-toolkit -- security secrets --path crates --path contracts --json
```

What it detects:

| Kind | Confidence | Behaviour |
|------|-----------|-----------|
| `stellar_secret_key` — a `S…` strkey | high | error |
| `recovery_phrase` — 12/15/18/21/24 words with a **valid** BIP-39 checksum | high | error |
| `recovery_phrase_candidate` — phrase-shaped, checksum invalid | medium | warning |
| `secret_assignment` — `STELLAR_SECRET_KEY`, `SECRET_KEY`, `PRIVATE_KEY`, `SEED_PHRASE`, `MNEMONIC`, `SIGNING_KEY` set to a literal | high | error |
| `env_file` — a committed `.env` (templates excluded) | high | error |

Findings never contain the secret: values are masked (`S…AB12`) so running the
scanner cannot leak a key into a CI transcript. Placeholders
(`<your-secret-key>`, `${STELLAR_SECRET_KEY}`, `changeme`) are not findings, and
a line carrying `// key-hygiene: allow` is skipped for documentation that must
show a real shape.

Wired into CI in the `automated-checks` job, and asserted by the unit tests
`key_hygiene::*`, including one that scans this repository and fails if any key
material appears in it.

---

## 7. Audit guidance

For an external review of key handling, the evidence to request is:

1. `stellar-toolkit security secrets` output from the reviewed commit, plus the
   unit test `key_hygiene::tests::the_workspace_itself_is_clean`.
2. `config/prod.toml` and `stellar-toolkit env validate --env prod` — multisig
   and cold-storage flags are validated, not just documented.
3. `.github/workflows/release.yml` — the approval gate and the absence of any
   secret in the workflow file itself.
4. `logs/deployment-audit.log` for the period under review.
5. `docs/REPRODUCIBLE_BUILDS.md` plus the checksum manifest, to show the
   deployed WASM is the reviewed WASM.
6. Redaction tests: `wallet::tests::debug_never_prints_the_phrase_or_the_secret`
   and `wallet::tests::rejected_secret_key_is_not_echoed_in_the_error`.

### Known limitations

* The scanner is text-based and has no git-history mode: a key deleted in a
  later commit is still in the history. Rotate the key; do not rely on deletion.
  For history scanning use a dedicated tool (`gitleaks`, `trufflehog`) as a
  second opinion — this check is a guard rail, not a replacement.
* Process arguments are visible to the same user via `/proc`. Redacting `Debug`
  protects logs, not `ps`.
* `.env` files are detected by name. A secret in an arbitrarily named local file
  is only caught if it is key-shaped or assigned to a known field name.

## See also

- [`docs/THREAT_MODEL.md`](THREAT_MODEL.md) — contract-level attack surface
- [`docs/INFRA_RUNBOOK.md`](INFRA_RUNBOOK.md) — release and deploy runbook
- [`SECURITY.md`](../SECURITY.md) — disclosure policy and SLA
