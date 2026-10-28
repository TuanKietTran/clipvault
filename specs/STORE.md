# Store Contract

This contract is shared by Manager A (clipboard app/CLI) and Manager B (vault). Both managers agreed before implementation.

## Providers

`VaultProvider` is the pluggable storage interface. Exactly two providers ship:

1. `LocalEncryptedProvider`: AES-GCM encrypted file storage. The encryption key is stored in macOS Keychain.
2. `AppleKeychainProvider`: Security framework generic-password items with `kSecAttrSynchronizable = true` for iCloud Keychain sync.

Each vault item has a provider tag. Moving an item between providers must preserve its stable reference.

## References and agent boundary

- Item references use `clip://<UUID>` and remain stable across provider moves.
- Listing returns each item's opaque `clip://UUID` reference plus metadata: type, size, source app, timestamp, sensitivity label, and provider tag. It must not return item content.
- Resolving a reference is pasteboard-only: it writes the secret/item to the system pasteboard and returns no content to the caller or agent process.
- `clipctl` may list metadata and copy/paste by opaque reference only. Credential import is not exposed through `clipctl`.

## Credential import

- Import is initiated by a human in the GUI using a user-selected official CSV export for Chrome, Edge, Brave, Firefox, Safari, or Apple Passwords.
- Do not read browser profile databases or decrypt browser-managed stores.
- Parse and write imported credentials directly into the vault; never place them in plaintext clipboard history.
- Offer secure deletion of the selected CSV after import.

## Swift package and source boundary

The vault implementation is a Swift package named `ClipVault`, rooted at `vault/`. The public library target is `ClipVault` under `Sources/ClipVault`; package tests live under `Tests/ClipVaultTests`. Provider `get` remains an internal storage operation; agent-facing access is limited to metadata and pasteboard-only resolution through `VaultStore`.

## API shape

The concrete Swift names may be namespaced as needed, but the shared semantic interface is:

```swift
protocol VaultProvider {
    func put(id: UUID, item: VaultItem) throws
    func get(id: UUID) throws -> VaultItem
    func delete(id: UUID) throws
    func metadata(id: UUID) throws -> VaultMetadata
}

struct VaultItem: Codable {
    let type: String
    let payload: Data             // Internal storage value; never exposed to agent-facing APIs.
    let sourceApp: String?
    let timestamp: Date
    let sensitivityLabel: String
    let expiresAt: Date?
}

struct VaultMetadata {
    let id: UUID
    let type: String
    let size: Int
    let sourceApp: String?
    let timestamp: Date
    let sensitivityLabel: String
    let providerTag: String
}

protocol VaultStore {
    // App/UI/importer internal use only; imported credentials bypass plain history.
    func put(content: Data, type: String, sourceApp: String?, sensitivityLabel: String, ttl: TimeInterval?, providerTag: String) throws -> URL
    func listMetadata() throws -> [VaultMetadata]
    // Writes the value to NSPasteboard and returns no value/content to caller.
    func resolveToPasteboard(_ ref: URL) throws
    func delete(_ ref: URL) throws
    func move(_ ref: URL, to providerTag: String) throws
}

// Providers implement CRUD by stable UUID. A VaultStore layer owns clip:// parsing,
// sensitivity classification, TTL/expiry, provider selection/moves and resolve audit.
// Agent-facing APIs (including clipctl/socket) expose refs and metadata only; resolve
// writes to NSPasteboard and returns no content. Import is GUI-only, never clipctl.
```

## Agreement

- Manager A confirms the complete contract, including `ClipVault` package/source boundary, `VaultStore` interface and metadata-only/pasteboard-only agent boundary.
- Manager B agrees to the complete contract above.

## Integration build findings (Manager A coordination)

Manager A is building `app/` against the agreed Vault package. Current integration errors observed:

- ~~`vault/Sources/ClipVault/VaultStore.swift:62`: `auditSink.record` receives a `String`, but `VaultAuditRecord` is expected.~~ Resolved in `vault/Sources/ClipVault/VaultStoreService.swift` by passing a content-free `VaultAuditRecord`.
- `app/Sources/ClipVaultApp/main.swift:30`: `pendingImport` uses private `PendingImport` with broader property access.

The vault-owned audit compile issue and test-owned CSV deletion API mismatch are resolved. A fresh full run reports `VaultStoreTests.testAutomaticSensitivityRoutingAndDeterministicProviderMoves` failing at `VaultStoreTests.swift:137` (the `password` sensitivity-label assertion). A direct rerun passed, indicating a flaky classifier false positive; `SensitivityAndLifecycleTests.testClassification` also failed at line 12 when alphabetic separators were present in digits. `SensitivityClassifier.cardNumber(in:)` concatenates all digits across arbitrary text. b-detect owns classifier/card-number behavior; do not change its source or tests from this worker. b-test's reported passing full run is separate from this failing run. Wait for b-detect's fix, then rerun the full suite. Manager A will resolve remaining app-owned build issues in `app/`; no shared Package.swift changes are needed.
