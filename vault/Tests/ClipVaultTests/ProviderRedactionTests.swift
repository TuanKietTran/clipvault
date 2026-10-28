import Foundation
import XCTest
@testable import ClipVault

final class ProviderRedactionTests: XCTestCase {
    func testLocalEncryptedPersistenceAndMetadataDoNotExposePayload() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("ClipVaultTests-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let provider: LocalEncryptedProvider
        do {
            provider = try LocalEncryptedProvider(directory: directory)
        } catch {
            throw XCTSkip("Local provider unavailable on this host")
        }

        let marker = Data("synthetic-secret-\(UUID().uuidString)".utf8)
        let id = UUID()
        let item = VaultItem(type: "credential", payload: marker,
                             sourceApp: "synthetic-test", sensitivityLabel: "password")
        try provider.put(id: id, item: item)

        let files = try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)
        XCTAssertFalse(files.isEmpty)
        for file in files {
            let persisted = try Data(contentsOf: file)
            XCTAssertFalse(persisted.range(of: marker) != nil, "Encrypted file contains plaintext marker")
        }

        let metadata = try provider.metadata(id: id)
        let serializedMetadata = try JSONEncoder().encode(metadata)
        XCTAssertNil(serializedMetadata.range(of: marker))
        XCTAssertEqual(metadata.size, marker.count)
        XCTAssertEqual(try provider.listMetadata().map(\.id), [id])
        try provider.delete(id: id)
    }

    func testLocalProviderSatisfiesSharedProviderContract() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("ClipVaultContractTests-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let provider = try LocalEncryptedProvider(directory: directory)
        try VaultProviderContractTests().assertProviderContract(provider)
    }

    func testSynchronizableAppleKeychainProviderRoundTripWhenExplicitlyOptedIn() throws {
        guard ProcessInfo.processInfo.environment["CLIPVAULT_TEST_SYNC_KEYCHAIN"] == "1" else {
            throw XCTSkip("Set CLIPVAULT_TEST_SYNC_KEYCHAIN=1 to opt in to iCloud Keychain sync testing")
        }

        let provider = AppleKeychainProvider()
        let id = UUID()
        defer { try? provider.delete(id: id) }
        let payload = Data("synthetic-keychain-test-\(UUID().uuidString)".utf8)
        let item = VaultItem(type: "synthetic-test", payload: payload,
                             sourceApp: "ProviderRedactionTests", timestamp: Date(timeIntervalSince1970: 1_700_000_000),
                             sensitivityLabel: "test-only")

        try provider.put(id: id, item: item)
        XCTAssertEqual(try provider.get(id: id).payload, payload)
        let metadata = try provider.metadata(id: id)
        XCTAssertEqual(metadata.id, id)
        XCTAssertEqual(metadata.type, item.type)
        XCTAssertEqual(metadata.size, payload.count)
        XCTAssertEqual(metadata.sourceApp, item.sourceApp)
        XCTAssertEqual(metadata.timestamp, item.timestamp)
        XCTAssertEqual(metadata.sensitivityLabel, item.sensitivityLabel)
        XCTAssertEqual(metadata.providerTag, provider.providerTag)

        try provider.delete(id: id)
        XCTAssertThrowsError(try provider.get(id: id))
    }
}
