import Foundation
import XCTest
@testable import ClipVault

private final class MemoryProvider: VaultProvider {
    let providerTag: String
    private var items: [UUID: VaultItem] = [:]

    init(_ providerTag: String) { self.providerTag = providerTag }
    func put(id: UUID, item: VaultItem) throws { items[id] = item }
    func get(id: UUID) throws -> VaultItem {
        guard let item = items[id] else { throw VaultError.notFound }
        return item
    }
    func delete(id: UUID) throws {
        guard items.removeValue(forKey: id) != nil else { throw VaultError.notFound }
    }
    func metadata(id: UUID) throws -> VaultMetadata {
        guard let item = items[id] else { throw VaultError.notFound }
        return VaultMetadata(id: id, type: item.type, size: item.payload.count,
                             sourceApp: item.sourceApp, timestamp: item.timestamp,
                             sensitivityLabel: item.sensitivityLabel, providerTag: providerTag)
    }
    func listMetadata() throws -> [VaultMetadata] { try items.keys.map { try metadata(id: $0) } }
}

private final class RecordingAudit: VaultAuditSink {
    private(set) var records: [VaultAuditRecord] = []
    func record(_ record: VaultAuditRecord) {
        records.append(record)
    }
}

final class VaultStoreTests: XCTestCase {
    func testPutListsMetadataAndMovePreservesOpaqueReference() throws {
        let local = MemoryProvider("local-encrypted")
        let cloud = MemoryProvider("apple-keychain")
        let store = try VaultStoreService(providers: [local, cloud])
        let reference = try store.put(content: Data("fixture".utf8), type: "public.data",
                                      sourceApp: "tests", sensitivityLabel: "private",
                                      ttl: nil, providerTag: local.providerTag)
        XCTAssertEqual(reference.scheme, "clip")
        XCTAssertEqual(try store.listMetadata().first?.providerTag, local.providerTag)

        try store.move(reference, to: cloud.providerTag)
        let metadata = try XCTUnwrap(store.listMetadata().first)
        XCTAssertEqual(metadata.reference, "clip://\(metadata.id.uuidString)")
        XCTAssertEqual(metadata.providerTag, cloud.providerTag)
        XCTAssertEqual(try local.listMetadata().count, 0)
    }

    func testTTLExpiresAndDeleteRemovesMetadata() throws {
        var now = Date(timeIntervalSince1970: 1_700_000_000)
        let provider = MemoryProvider("local-encrypted")
        let store = try VaultStoreService(providers: [provider], clock: { now })
        let reference = try store.put(content: Data([1]), type: "public.data",
                                      sourceApp: nil, sensitivityLabel: "private",
                                      ttl: 10, providerTag: provider.providerTag)
        XCTAssertEqual(try store.listMetadata().count, 1)
        now = now.addingTimeInterval(11)
        XCTAssertEqual(try store.listMetadata().count, 0)
        XCTAssertThrowsError(try store.resolveToPasteboard(reference))

        let permanent = try store.put(content: Data([2]), type: "public.data",
                                      sourceApp: nil, sensitivityLabel: "private",
                                      ttl: nil, providerTag: provider.providerTag)
        try store.delete(permanent)
        XCTAssertEqual(try store.listMetadata().count, 0)
    }

    func testURLParserRejectsMalformedRefsAndAuditsWithoutRawInput() throws {
        let audit = RecordingAudit()
        let store = try VaultStoreService(providers: [MemoryProvider("local-encrypted")], auditSink: audit)
        let raw = "https://example.test/path?token=synthetic-marker-secret"
        XCTAssertThrowsError(try store.resolveToPasteboard(URL(string: raw)!))
        XCTAssertThrowsError(try store.resolveToPasteboard(URL(string: "clip://not-a-uuid?token=synthetic-marker-secret")!))

        XCTAssertEqual(audit.records.count, 2)
        XCTAssertTrue(audit.records.allSatisfy { $0.reference == "clip://invalid" && $0.action == "resolve" })
        let serialized = try JSONEncoder().encode(audit.records)
        XCTAssertNil(serialized.range(of: Data("synthetic-marker-secret".utf8)))
    }

    func testDuplicateUUIDAcrossProvidersIsAmbiguous() throws {
        let local = MemoryProvider("local-encrypted")
        let cloud = MemoryProvider("apple-keychain")
        let id = UUID()
        let item = VaultItem(type: "test", payload: Data([1]), sensitivityLabel: "private")
        try local.put(id: id, item: item)
        try cloud.put(id: id, item: item)
        let store = try VaultStoreService(providers: [cloud, local])
        XCTAssertThrowsError(try store.delete(URL(string: "clip://\(id.uuidString)")!))
    }


    func testDefaultResolveAuditsNotFoundAndExpiredFailuresWithoutPayload() throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let provider = MemoryProvider("local-encrypted")
        let store = try VaultStoreService(providers: [provider], clock: { now })
        let marker = "synthetic-secret-\(UUID().uuidString)"
        let missing = URL(string: "clip://\(UUID().uuidString)")!
        let audit = try XCTUnwrap(store.auditSink as? InMemoryVaultAuditSink)

        XCTAssertThrowsError(try store.resolveToPasteboard(missing))
        let first = try XCTUnwrap(audit.snapshot().first)
        XCTAssertEqual(first.reference, missing.absoluteString)
        XCTAssertEqual(first.action, "resolve")
        XCTAssertEqual(first.outcome, "failure")

        let expiredID = UUID()
        let expiredRef = URL(string: "clip://\(expiredID.uuidString)")!
        try provider.put(id: expiredID, item: VaultItem(type: "credential", payload: Data(marker.utf8),
                                                        sensitivityLabel: "password",
                                                        expiresAt: now.addingTimeInterval(-1)))
        XCTAssertThrowsError(try store.resolveToPasteboard(expiredRef))
        let records = audit.snapshot()
        XCTAssertEqual(records.count, 2)
        XCTAssertEqual(records[1].reference, expiredRef.absoluteString)
        XCTAssertEqual(records[1].outcome, "failure")

        let auditText = String(describing: records)
        let serialized = try JSONEncoder().encode(records)
        XCTAssertFalse(auditText.contains(marker))
        XCTAssertNil(serialized.range(of: Data(marker.utf8)))
        XCTAssertFalse(auditText.contains("payload"))
    }

    func testAutomaticSensitivityRoutingAndDeterministicProviderMoves() throws {
        let local = MemoryProvider("local-encrypted")
        let cloud = MemoryProvider("apple-keychain")
        let store = try VaultStoreService(providers: [cloud, local])
        let marker = "password=synthetic-\(UUID().uuidString)"
        let reference = try store.put(content: Data(marker.utf8), type: "text/plain",
                                      sourceApp: "synthetic-test", sensitivityLabel: "publicData",
                                      ttl: nil, providerTag: local.providerTag)
        let id = try XCTUnwrap(UUID(uuidString: reference.host ?? ""))
        XCTAssertEqual(try local.metadata(id: id).sensitivityLabel, SensitivityLabel.password.rawValue)
        XCTAssertEqual(try local.listMetadata().map { $0.id }, [id])
        XCTAssertTrue(try cloud.listMetadata().isEmpty)

        try store.move(reference, to: cloud.providerTag)
        XCTAssertEqual(reference.absoluteString, "clip://\(id.uuidString)")
        XCTAssertTrue(try local.listMetadata().isEmpty)
        XCTAssertEqual(try cloud.metadata(id: id).providerTag, cloud.providerTag)
        XCTAssertEqual(try cloud.get(id: id).payload, Data(marker.utf8))

        let ordinary = try store.put(content: Data("ordinary note".utf8), type: "text/plain",
                                     sourceApp: nil, sensitivityLabel: "publicData", ttl: nil,
                                     providerTag: local.providerTag)
        let ordinaryID = try XCTUnwrap(UUID(uuidString: ordinary.host ?? ""))
        XCTAssertEqual(try local.metadata(id: ordinaryID).sensitivityLabel, "publicData")
    }
}
