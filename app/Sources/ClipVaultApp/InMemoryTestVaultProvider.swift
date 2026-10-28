import ClipVault
import Foundation

/// Enabled only by CLIPVAULT_TEST_MODE=1. Contents exist only in process memory.
final class InMemoryTestVaultProvider: VaultProvider {
    let providerTag = "local-encrypted"
    private let lock = NSLock()
    private var items: [UUID: VaultItem] = [:]

    func put(id: UUID, item: VaultItem) throws {
        lock.lock()
        defer { lock.unlock() }
        items[id] = item
    }

    func get(id: UUID) throws -> VaultItem {
        lock.lock()
        defer { lock.unlock() }
        guard let item = items[id] else { throw VaultError.notFound }
        return item
    }

    func delete(id: UUID) throws {
        lock.lock()
        defer { lock.unlock() }
        guard items.removeValue(forKey: id) != nil else { throw VaultError.notFound }
    }

    func metadata(id: UUID) throws -> VaultMetadata {
        lock.lock()
        defer { lock.unlock() }
        guard let item = items[id] else { throw VaultError.notFound }
        return try makeMetadata(id: id, item: item)
    }

    func listMetadata() throws -> [VaultMetadata] {
        lock.lock()
        defer { lock.unlock() }
        return try items.map { try makeMetadata(id: $0.key, item: $0.value) }
            .sorted { $0.timestamp > $1.timestamp }
    }

    func removeAll() {
        lock.lock()
        items.removeAll(keepingCapacity: false)
        lock.unlock()
    }

    private func makeMetadata(id: UUID, item: VaultItem) throws -> VaultMetadata {
        let representation = MetadataRepresentation(id: id, type: item.type, size: item.metadataSize,
                                                    sourceApp: item.sourceApp, timestamp: item.timestamp,
                                                    sensitivityLabel: item.sensitivityLabel,
                                                    providerTag: providerTag)
        return try JSONDecoder().decode(VaultMetadata.self, from: JSONEncoder().encode(representation))
    }
}

private struct MetadataRepresentation: Codable {
    let id: UUID
    let type: String
    let size: Int
    let sourceApp: String?
    let timestamp: Date
    let sensitivityLabel: String
    let providerTag: String
}
