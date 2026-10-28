import Foundation
import CryptoKit
import Security
import AppKit

public struct VaultItem: Codable {
    public let type: String
    public let payload: Data
    public let sourceApp: String?
    public let timestamp: Date
    public let sensitivityLabel: String
    public let expiresAt: Date?

    public init(type: String, payload: Data, sourceApp: String? = nil,
                timestamp: Date = Date(), sensitivityLabel: String, expiresAt: Date? = nil) {
        self.type = type
        self.payload = payload
        self.sourceApp = sourceApp
        self.timestamp = timestamp
        self.sensitivityLabel = sensitivityLabel
        self.expiresAt = expiresAt
    }

    public var metadataSize: Int { payload.count }
}

public struct VaultMetadata: Codable {
    public let id: UUID
    public let type: String
    public let size: Int
    public let sourceApp: String?
    public let timestamp: Date
    public let sensitivityLabel: String
    public let providerTag: String

    public var reference: String { "clip://\(id.uuidString)" }
}

/// Providers are an internal storage boundary. Never expose get() to agent-facing APIs.
public protocol VaultProvider {
    var providerTag: String { get }
    func put(id: UUID, item: VaultItem) throws
    func get(id: UUID) throws -> VaultItem
    func delete(id: UUID) throws
    func metadata(id: UUID) throws -> VaultMetadata
    func listMetadata() throws -> [VaultMetadata]
}

/// Application-side orchestration contract. Implementation is owned by the app/store layer.
public protocol VaultStore {
    func put(content: Data, type: String, sourceApp: String?, sensitivityLabel: String,
             ttl: TimeInterval?, providerTag: String) throws -> URL
    func listMetadata() throws -> [VaultMetadata]
    func resolveToPasteboard(_ ref: URL) throws
    func delete(_ ref: URL) throws
    func move(_ ref: URL, to providerTag: String) throws
}

/// Audit records contain only canonical opaque references, action names and outcome labels.
public struct VaultAuditRecord: Codable, Equatable {
    public let reference: String
    public let action: String
    public let outcome: String
    public let timestamp: Date

    public init(reference: String, action: String, outcome: String, timestamp: Date = Date()) {
        self.reference = reference
        self.action = action
        self.outcome = outcome
        self.timestamp = timestamp
    }
}

public protocol VaultAuditSink {
    func record(_ record: VaultAuditRecord)
}

/// Thread-safe in-memory default. It intentionally retains no content or untrusted URL text.
public final class InMemoryVaultAuditSink: VaultAuditSink {
    private let lock = NSLock()
    private var records: [VaultAuditRecord] = []

    public init() {}

    public func record(_ record: VaultAuditRecord) {
        lock.lock()
        records.append(record)
        lock.unlock()
    }

    public func snapshot() -> [VaultAuditRecord] {
        lock.lock()
        defer { lock.unlock() }
        return records
    }
}

public enum VaultError: Error {
    case notFound
    case invalidReference
    case invalidTTL
    case expired
    case keychainFailure
    case storageFailure
    case pasteboardFailure
    case duplicateReference
    case ambiguousReference
}

private struct StoredRecord: Codable {
    let item: VaultItem
    let metadata: VaultMetadata
}

private func makeMetadata(id: UUID, item: VaultItem, tag: String) -> VaultMetadata {
    VaultMetadata(id: id, type: item.type, size: item.metadataSize,
                  sourceApp: item.sourceApp, timestamp: item.timestamp,
                  sensitivityLabel: item.sensitivityLabel, providerTag: tag)
}

private enum KeychainSupport {
    static func read(service: String, account: String, synchronizable: Bool = false) throws -> Data? {
        var query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                    kSecAttrService as String: service,
                                    kSecAttrAccount as String: account,
                                    kSecReturnData as String: true,
                                    kSecMatchLimit as String: kSecMatchLimitOne]
        if synchronizable { query[kSecAttrSynchronizable as String] = true }
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data else { throw VaultError.keychainFailure }
        return data
    }

    static func write(_ data: Data, service: String, account: String,
                      synchronizable: Bool = false) throws {
        var query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                    kSecAttrService as String: service,
                                    kSecAttrAccount as String: account]
        if synchronizable { query[kSecAttrSynchronizable as String] = true }
        let attrs: [String: Any] = [kSecValueData as String: data,
                                    kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlocked]
        let status = SecItemUpdate(query as CFDictionary, attrs as CFDictionary)
        if status == errSecItemNotFound {
            query.merge(attrs) { _, new in new }
            guard SecItemAdd(query as CFDictionary, nil) == errSecSuccess else { throw VaultError.keychainFailure }
        } else if status != errSecSuccess { throw VaultError.keychainFailure }
    }

    static func remove(service: String, account: String, synchronizable: Bool = false) throws {
        var query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                    kSecAttrService as String: service,
                                    kSecAttrAccount as String: account]
        if synchronizable { query[kSecAttrSynchronizable as String] = true }
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw VaultError.keychainFailure }
    }
}

public final class LocalEncryptedProvider: VaultProvider {
    public let providerTag = "local-encrypted"
    private let directory: URL
    private let service = "com.clipvault.local-encryption"
    private let account = "vault-master-key"

    public init(directory: URL) throws {
        self.directory = directory
        do { try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true) }
        catch { throw VaultError.storageFailure }
        _ = try encryptionKey()
    }

    private func encryptionKey() throws -> SymmetricKey {
        if let data = try KeychainSupport.read(service: service, account: account) {
            guard data.count == 32 else { throw VaultError.keychainFailure }
            return SymmetricKey(data: data)
        }
        let bytes = Data((0..<32).map { _ in UInt8.random(in: .min ... .max) })
        try KeychainSupport.write(bytes, service: service, account: account)
        return SymmetricKey(data: bytes)
    }

    private func file(_ id: UUID) -> URL { directory.appendingPathComponent(id.uuidString + ".vault") }

    public func put(id: UUID, item: VaultItem) throws {
        do {
            let record = StoredRecord(item: item, metadata: makeMetadata(id: id, item: item, tag: providerTag))
            let clear = try JSONEncoder().encode(record)
            let sealed = try AES.GCM.seal(clear, using: encryptionKey()).combined!
            try sealed.write(to: file(id), options: .atomic)
        } catch let error as VaultError { throw error }
        catch { throw VaultError.storageFailure }
    }

    private func record(_ id: UUID) throws -> StoredRecord {
        do {
            let sealed = try Data(contentsOf: file(id))
            let box = try AES.GCM.SealedBox(combined: sealed)
            let clear = try AES.GCM.open(box, using: encryptionKey())
            return try JSONDecoder().decode(StoredRecord.self, from: clear)
        } catch let error as VaultError { throw error }
        catch { throw VaultError.notFound }
    }

    public func get(id: UUID) throws -> VaultItem { try record(id).item }
    public func metadata(id: UUID) throws -> VaultMetadata { try record(id).metadata }
    public func listMetadata() throws -> [VaultMetadata] {
        do {
            return try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)
                .filter { $0.pathExtension == "vault" }
                .compactMap { UUID(uuidString: $0.deletingPathExtension().lastPathComponent) }
                .map { try record($0).metadata }
        } catch let error as VaultError { throw error }
        catch { throw VaultError.storageFailure }
    }
    public func delete(id: UUID) throws {
        do { try FileManager.default.removeItem(at: file(id)) }
        catch { throw VaultError.notFound }
    }
}

public final class AppleKeychainProvider: VaultProvider {
    public let providerTag = "apple-keychain"
    private let service = "com.clipvault.synchronizable-vault"
    public init() {}
    private func account(_ id: UUID) -> String { id.uuidString }

    public func put(id: UUID, item: VaultItem) throws {
        do {
            let record = StoredRecord(item: item, metadata: makeMetadata(id: id, item: item, tag: providerTag))
            try KeychainSupport.write(JSONEncoder().encode(record), service: service,
                                      account: account(id), synchronizable: true)
        } catch let error as VaultError { throw error }
        catch { throw VaultError.storageFailure }
    }
    private func record(_ id: UUID) throws -> StoredRecord {
        guard let data = try KeychainSupport.read(service: service, account: account(id), synchronizable: true) else {
            throw VaultError.notFound
        }
        do { return try JSONDecoder().decode(StoredRecord.self, from: data) }
        catch { throw VaultError.storageFailure }
    }
    public func get(id: UUID) throws -> VaultItem { try record(id).item }
    public func metadata(id: UUID) throws -> VaultMetadata { try record(id).metadata }
    public func listMetadata() throws -> [VaultMetadata] {
        // Enumerate only this provider's synchronizable records; return no payloads.
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                    kSecAttrService as String: service,
                                    kSecAttrSynchronizable as String: true,
                                    kSecReturnAttributes as String: true,
                                    kSecReturnData as String: false,
                                    kSecMatchLimit as String: kSecMatchLimitAll]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return [] }
        guard status == errSecSuccess, let rows = result as? [[String: Any]] else { throw VaultError.keychainFailure }
        return try rows.compactMap { row in
            guard let idText = row[kSecAttrAccount as String] as? String,
                  let id = UUID(uuidString: idText) else { return nil }
            return try metadata(id: id)
        }
    }
    public func delete(id: UUID) throws {
        try KeychainSupport.remove(service: service, account: account(id), synchronizable: true)
    }
}

