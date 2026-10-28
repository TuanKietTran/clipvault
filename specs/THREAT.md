# Vault threat model

## Scope and status

This document reviews the complete `specs/STORE.md` contract confirmed by both managers in its Agreement section. This review does not itself authorize implementation. It describes required security properties, threats, mitigations to validate, and residual limitations; it is not an assertion that an implementation has been audited or that these mitigations already exist. No implementation changes are specified here as completed work.

Exactly two providers ship behind `VaultProvider`: `LocalEncryptedProvider` (AES-GCM files, with its encryption key in macOS Keychain) and `AppleKeychainProvider` (Security framework generic-password items with `kSecAttrSynchronizable = true`). References are stable `clip://<UUID>` identifiers, including across provider moves.

The package boundary is `vault/`, with production components (including the importer) under `Sources/ClipVault` and tests under `Tests/ClipVaultTests`. `VaultStore` accepts providers by tag and owns reference parsing, sensitivity classification, optional TTL/expiry, provider selection/moves, and resolve auditing. Its agent-facing operations expose metadata and pasteboard-only resolution with a `Void` result; content-bearing `put` and provider `get` remain app/storage-internal.

## Assets

- Credential contents, other sensitive clipboard items, and transient plaintext in application memory.
- Local-provider encryption keys, AES-GCM nonces/tags, encrypted records, and the integrity of provider storage.
- Keychain items, their access controls, and synchronizable copies on authorized devices.
- Reference-to-item/provider mappings and their integrity; a reference must never silently resolve to a different item.
- Metadata: type, size, source app, timestamp, sensitivity label, and provider tag. These can reveal usage patterns even without content.
- Human-selected CSV exports, their paths, temporary parser buffers, and any source copies or backups.
- The integrity of human import consent, destination selection, and pasteboard actions.

## Attacker capabilities and exclusions

Consider an agent or CLI caller that can enumerate references, submit arbitrary or replayed requests, and observe command output; a local process that attempts socket impersonation or reads the pasteboard; a malicious CSV author; and an attacker who obtains encrypted files, backups, or a lost device. Also consider accidental disclosure through diagnostics, crash reporting, clipboard history, mistaken imports, or provider moves.

A compromised GUI/vault process can observe plaintext it handles. Malware running with sufficient user privileges, accessibility permissions, debugging access, an unlocked authorized Keychain, or kernel/root control may bypass application boundaries. Full protection against those capabilities is not promised. An agent capable of running arbitrary local commands may independently read the system pasteboard; the pasteboard-only resolve API is an output boundary, not process-wide isolation from such an agent.

## Trust boundaries

| Boundary | Allowed flow | Threat and required treatment |
| --- | --- | --- |
| Agent process ↔ CLI/socket | Metadata, opaque references, and content-free status/errors | Never serialize content through stdout, stderr, socket replies, traces, or error descriptions. Treat every request as untrusted. A UUID is an identifier, not authorization. |
| CLI/socket ↔ GUI/vault service | Validated metadata queries and reference-based copy/paste requests | Authenticate/authorize local peers, restrict endpoint ownership/permissions, validate framing and request sizes, and resist socket substitution and replay. Locality alone is not trust. |
| Human ↔ GUI/importer | Explicit selection of a supported official CSV export and import action | Import remains human-only; do not expose it through `clipctl` or accept an agent-supplied path as human consent. Do not inspect browser profile databases or decrypt browser-managed stores. |
| GUI/vault ↔ providers | Internal plaintext access via `put`/`get`; metadata via `metadata` | Provider APIs are internal, not agent APIs. Keychain denial, lock state, corruption, and provider errors must not trigger plaintext fallback. |
| Vault ↔ system pasteboard | Resolved content written to `NSPasteboard` | Resolution returns no content to the caller. Other processes, clipboard managers, and OS clipboard-sharing facilities may see the pasteboard afterward. |
| Local encrypted provider ↔ filesystem/Keychain | Authenticated ciphertext on disk; key in Keychain | Protect keys and storage permissions, reject tampering, and avoid plaintext files, journals, caches, and crash diagnostics. |
| Apple Keychain ↔ iCloud/other devices | Synchronizable generic-password items | Sync expands the trust boundary to the Apple account, platform services, authorized devices, and their access controls. It is not local-only storage. |
| Selected CSV ↔ parser/vault | Bounded parsing directly into vault storage | The file is untrusted plaintext even when produced by a supported exporter; avoid raw-row logging, intermediate plaintext persistence, and clipboard/history writes. |

## Security invariants

1. Agent-facing listing returns only the contracted metadata, never content, previews, decrypted fields, or content-bearing errors. References and status responses must not embed secrets.
2. Reference resolution writes to the system pasteboard without returning content to the caller or agent process. Internal `VaultProvider.get` is not remotely exposed.
3. Imported credentials go directly from bounded in-memory parsing into a provider. They never enter plaintext clipboard history or an intermediate plaintext file. The user-selected source CSV is an explicit pre-existing plaintext exception.
4. New application-managed persisted content uses the selected encrypted provider; encryption/key-access failures fail closed. Metadata persistence must not become an indirect content store.
5. Every item has a provider tag. Moves preserve the UUID and update routing consistently without losing the only durable copy or resolving the reference to an unrelated item.
6. Import is GUI/human initiated and limited to user-selected official exports from Chrome, Edge, Brave, Firefox, Safari, or Apple Passwords. Neither browser profile database access nor browser-store decryption is permitted.
7. Logs, telemetry, diagnostics, and errors contain no credentials, raw CSV rows, decrypted payloads, or key material. Metadata exposure is minimized, including in failure paths.
8. Secure deletion of the selected CSV is offered after import, but no irreversible-erasure guarantee is made. TTL expiry and deletion must not claim removal from all replicas, backups, or past consumers.

## Risks and mitigations to validate

### Local encrypted storage and transient plaintext

Use AES-GCM with a unique nonce for every encryption under a given key, validate authentication before using plaintext, and fail closed on malformed or altered records. Bind record identity and relevant routing context through authenticated data or equivalently protected mappings to prevent record substitution. Limit file permissions and protect atomic writes/recovery paths; temporary and replacement records must remain encrypted. Keychain access controls must match the intended app and avoid broadly shared access groups. Do not place encryption keys in preferences, arguments, logs, or alongside ciphertext.

Encryption at rest does not protect unlocked process memory. Minimize plaintext lifetime and copies; avoid content in crash reports and diagnostic snapshots. Memory clearing is best effort in managed/runtime buffers, and paging, crash dumps, backups, and historical copies prevent an absolute claim that plaintext can never reach persistent media.

### Reference resolution, pasteboard, and history

Authorize resolution independently of possession of a reference. Validate UUIDs and provider routing; do not accept arbitrary paths or provider selectors as authority. Ensure errors and command exit reporting remain content-free. Test both successful and failed resolution for leakage.

The system pasteboard is an intentional plaintext disclosure surface. Mark sensitive/transient content where supported, avoid retaining resolved secrets in the app's own history, and suppress recapture of the app's secret pasteboard writes. Clearing after a configured interval can reduce exposure, but must check pasteboard ownership/change state so it does not erase newer user content. Applications may already have read or synchronized the value; clearing cannot revoke it. Automated paste also trusts the destination application and current focus.

### Logs and metadata

Never log payloads, parser rows, password fields, raw provider errors containing values, or encryption keys. Treat paths, source names, reference IDs, item sizes, and timestamps as sensitive metadata; redact or minimize diagnostic copies. Do not infer that generic-password attributes or filesystem indexes provide the same confidentiality as encrypted secret data. Verify what provider attributes remain visible, and keep content out of labels, descriptions, filenames, and indexes. Listing intentionally reveals the contracted metadata to authorized callers; it is not anonymous access.

Resolve auditing must be injectable and record only opaque reference/action/result metadata, never content. Audit callbacks, serialization, and failure paths are part of the disclosure boundary; avoid passing payloads or content-bearing errors to the audit sink.

### CSV/parser handling

Validate supported header/schema variants and encoding without executing file content, formulas, URLs, or external references. Enforce limits on file size, row count, field length, and parser work; handle quoted multiline fields and malformed input without unbounded allocation or raw-data error messages. Treat all fields as untrusted text, including labels displayed in the GUI. Do not invoke a shell or spreadsheet application to parse imports.

Bind the import to the user-selected file, handle symlinks/file replacement races, and avoid accidental directory traversal or reading additional files. Stream/batch within bounded memory where practical; do not spool plaintext. Clearly report partial success without revealing credentials. Do not delete the CSV automatically on parse failure or before successful persistence is established. Offer deletion after import with explicit human consent and truthful limitations. Duplicate/retry handling must not silently overwrite unrelated entries. Imported records must not pass through ordinary clipboard-history capture.

### Provider moves and iCloud Keychain

Keep the stable reference while committing destination content, routing metadata, and source removal recoverably. On interruption or partial failure, retain a valid recoverable copy and reconcile duplicates without exposing plaintext or losing routing integrity. Report incomplete source cleanup; a successful destination write does not prove source erasure.

`AppleKeychainProvider` uses `kSecAttrSynchronizable = true`: explain that choosing it permits iCloud Keychain synchronization when available. Do not silently fall back to an unsynchronized item or a local plaintext store. Verify access controls and supported synchronizable attributes against actual Security framework behavior. Account/device compromise and an already unlocked authorized device can expose synced credentials. Sync availability, conflict handling, deletion propagation, and offline replicas are outside an instantaneous local transaction. Moving from Keychain to local storage does not prove removal of all earlier synced copies.

### TTL, deletion, and secure deletion limits

The current STORE API includes `ttl`, `expiresAt`, and VaultStore ownership of TTL/expiry, but does not fully define timing semantics. Define when TTL starts and enforce expiry at access as well as background cleanup, including after sleep, restart, or clock changes. Keep expiry consistent across provider moves and avoid exposing expired items through listing or resolution. Expiring a reference is not equivalent to physical erasure, pasteboard clearing, or revocation of credentials already copied elsewhere.

Provider deletion and CSV deletion must distinguish logical removal from physical erasure. Keychain synchronization and backups can retain historical copies or delay removal. Local-provider key destruction is only meaningful if the relevant key and all copies are actually unavailable; deleting one record does not destroy a shared key and is not cryptographic erasure of that record.

APFS copy-on-write, snapshots, clones, Time Machine/backups, SSD wear leveling, and TRIM mean overwriting or unlinking the CSV cannot guarantee secure physical deletion. An exported CSV may also exist in Downloads backups, cloud storage, or other user copies. Present the offered secure-deletion action as best effort with these limitations; do not promise forensic irrecoverability or destroy unrelated snapshots/backups.

## Verification targets and residual limitations

Review implementation and tests for metadata-only responses, content-free failures, unauthorized socket requests, malicious/oversized CSV input, no import history entry, AES-GCM tamper rejection, provider-move interruption recovery, denied Keychain access, and expiry/deletion races where applicable. Use synthetic fixtures only, never real secrets. Align tests with the published `VaultProvider` contract and concrete `VaultStore`, without a test-only store implementation. Cover all six official-export format identifiers, malformed/invalid rows, duplicate reporting, and secret-free diagnostics; do not invent file-selection/import-service APIs. Assert that synthetic marker secrets are absent from metadata, error descriptions, audit serialization, and persisted local-provider bytes. These are review targets, not results of this document task.

Documentation checkpoint: rechecked this document against the fully agreed STORE contract and `B-THREAT-BRIEF.md`. Coverage includes both providers, stable references and moves, metadata-only listing, pasteboard-only resolution, internal content APIs, injectable content-free auditing, human-only direct-to-vault CSV import, sync implications, TTL/deletion, and APFS/SSD limitations. Only `specs/THREAT.md` was changed during this verification; no code or implementation tests were run.

Residual risks remain: authorized metadata disclosure; plaintext in memory and the pasteboard; local privileged malware; disclosure by paste destinations or clipboard consumers; an already exported CSV; synced devices/accounts and backups; and imperfect deletion on modern storage. The design reduces unintended exposure within the application boundary but cannot revoke information already read or guarantee erasure outside that boundary.
