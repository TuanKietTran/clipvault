import Foundation
import AppKit

/// Concrete orchestration layer. Sensitive values enter a provider directly and are
/// never returned to callers or routed through clipboard history.
public final class VaultStoreService: VaultStore {
    private let providers: [String: VaultProvider]
    public let auditSink: VaultAuditSink
    private let classifier: SensitivityClassifier
    private let clock: () -> Date

    public init(providers: [VaultProvider], auditSink: VaultAuditSink = InMemoryVaultAuditSink(),
                classifier: SensitivityClassifier = SensitivityClassifier(), clock: @escaping () -> Date = Date.init) throws {
        var indexed: [String: VaultProvider] = [:]
        for provider in providers {
            guard indexed[provider.providerTag] == nil else { throw VaultError.duplicateReference }
            indexed[provider.providerTag] = provider
        }
        guard !indexed.isEmpty else { throw VaultError.storageFailure }
        self.providers = indexed
        self.auditSink = auditSink
        self.classifier = classifier
        self.clock = clock
    }

    @discardableResult
    public func put(content: Data, type: String, sourceApp: String?, sensitivityLabel: String,
                    ttl: TimeInterval?, providerTag: String) throws -> URL {
        guard let provider = providers[providerTag] else { throw VaultError.storageFailure }
        if let ttl, (!ttl.isFinite || ttl < 0) { throw VaultError.invalidTTL }
        let classification = classifier.classify(content, declaredType: type)
        let label = classification.requiresVault ? classification.rawValue : sensitivityLabel
        let id = UUID()
        let now = clock()
        let item = VaultItem(type: type, payload: content, sourceApp: sourceApp,
                             timestamp: now, sensitivityLabel: label,
                             expiresAt: VaultExpiry.expiry(from: now, ttl: ttl))
        try provider.put(id: id, item: item)
        return URL(string: "clip://\(id.uuidString)")!
    }

    public func listMetadata() throws -> [VaultMetadata] {
        let now = clock()
        var result: [VaultMetadata] = []
        var seen = Set<UUID>()
        for key in providers.keys.sorted() {
            guard let provider = providers[key] else { continue }
            for metadata in try provider.listMetadata() {
                guard seen.insert(metadata.id).inserted else { throw VaultError.ambiguousReference }
                let item = try provider.get(id: metadata.id)
                if VaultExpiry.isExpired(expiresAt: item.expiresAt, now: now) {
                    try? provider.delete(id: metadata.id)
                } else {
                    result.append(metadata)
                }
            }
        }
        return result
    }

    public func resolveToPasteboard(_ ref: URL) throws {
        var outcome = "failure"
        let auditReference = Self.auditReference(ref)
        defer {
            auditSink.record(VaultAuditRecord(reference: auditReference, action: "resolve",
                                              outcome: outcome, timestamp: clock()))
        }
        let id = try parse(ref)
        let (provider, item) = try locate(id)
        if VaultExpiry.isExpired(expiresAt: item.expiresAt, now: clock()) {
            try? provider.delete(id: id)
            throw VaultError.expired
        }
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        guard pasteboard.setData(item.payload, forType: NSPasteboard.PasteboardType(item.type)) else {
            throw VaultError.pasteboardFailure
        }
        outcome = "success"
    }

    public func delete(_ ref: URL) throws {
        let id = try parse(ref)
        let (provider, _) = try locate(id)
        try provider.delete(id: id)
    }

    public func move(_ ref: URL, to providerTag: String) throws {
        let id = try parse(ref)
        guard let destination = providers[providerTag] else { throw VaultError.storageFailure }
        let (source, item) = try locate(id)
        if source.providerTag == providerTag { return }
        if VaultExpiry.isExpired(expiresAt: item.expiresAt, now: clock()) {
            try? source.delete(id: id)
            throw VaultError.expired
        }
        try destination.put(id: id, item: item)
        do { try source.delete(id: id) }
        catch { try? destination.delete(id: id); throw VaultError.storageFailure }
    }

    private func locate(_ id: UUID) throws -> (VaultProvider, VaultItem) {
        var matches: [(VaultProvider, VaultItem)] = []
        for provider in providers.values.sorted(by: { $0.providerTag < $1.providerTag }) {
            if let item = try? provider.get(id: id) { matches.append((provider, item)) }
        }
        guard matches.count < 2 else { throw VaultError.ambiguousReference }
        guard let match = matches.first else { throw VaultError.notFound }
        return match
    }

    private func parse(_ ref: URL) throws -> UUID {
        guard ref.scheme?.lowercased() == "clip", ref.query == nil, ref.fragment == nil,
              ref.user == nil, ref.password == nil, ref.port == nil, ref.path.isEmpty,
              let host = ref.host, let id = UUID(uuidString: host) else {
            throw VaultError.invalidReference
        }
        return id
    }

    private static func auditReference(_ ref: URL) -> String {
        // Canonicalize only a valid UUID; never retain raw input, path, query or fragment.
        guard ref.scheme?.lowercased() == "clip", let host = ref.host,
              let id = UUID(uuidString: host), ref.path.isEmpty,
              ref.query == nil, ref.fragment == nil, ref.user == nil,
              ref.password == nil, ref.port == nil else { return "clip://invalid" }
        return "clip://\(id.uuidString)"
    }
}
