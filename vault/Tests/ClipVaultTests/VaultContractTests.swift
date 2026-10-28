import XCTest
@testable import ClipVault

/// Provider contract checks shared by both implementations. These tests use only the
/// documented CRUD surface and synthetic payloads; provider integration tests can reuse
/// `assertProviderContract` once production constructors are finalized.
final class VaultProviderContractTests: XCTestCase {
    func assertProviderContract(_ provider: any VaultProvider, file: StaticString = #filePath, line: UInt = #line) throws {
        let id = UUID()
        let marker = Data("synthetic-secret-\(UUID())".utf8)
        let item = VaultItem(
            type: "test",
            payload: marker,
            sourceApp: "VaultContractTests",
            timestamp: Date(timeIntervalSince1970: 1_700_000_000),
            sensitivityLabel: "sensitive",
            expiresAt: nil
        )

        try provider.put(id: id, item: item)
        let fetched = try provider.get(id: id)
        XCTAssertEqual(fetched.payload, marker, file: file, line: line)
        XCTAssertEqual(fetched.type, item.type, file: file, line: line)

        let metadata = try provider.metadata(id: id)
        XCTAssertEqual(metadata.id, id, file: file, line: line)
        XCTAssertEqual(metadata.type, item.type, file: file, line: line)
        XCTAssertEqual(metadata.size, marker.count, file: file, line: line)
        XCTAssertEqual(metadata.sourceApp, item.sourceApp, file: file, line: line)
        XCTAssertEqual(metadata.sensitivityLabel, item.sensitivityLabel, file: file, line: line)
        XCTAssertEqual(metadata.providerTag, provider.providerTag, file: file, line: line)
        XCTAssertTrue(try provider.listMetadata().contains { $0.id == id }, file: file, line: line)
        try provider.delete(id: id)
        XCTAssertThrowsError(try provider.get(id: id), file: file, line: line)
    }
}

/// VaultStore behavioral checks. Implementations are injected by the package's
/// integration suite; no concrete initializer or platform-specific setup is assumed.
final class VaultStoreContractTests: XCTestCase {
    func assertOpaqueReference(_ ref: URL, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertEqual(ref.scheme, "clip", file: file, line: line)
        XCTAssertNotNil(UUID(uuidString: ref.host ?? ""), file: file, line: line)
        XCTAssertNil(ref.query, file: file, line: line)
        XCTAssertNil(ref.fragment, file: file, line: line)
    }

    func assertMovePreservesReference(
        _ store: any VaultStore,
        ref: URL,
        destinationProviderTag: String,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        try store.move(ref, to: destinationProviderTag)
        XCTAssertEqual(ref.scheme, "clip", file: file, line: line)
        try store.resolveToPasteboard(ref)
    }

    func assertResolveReturnsNoValue(
        _ store: any VaultStore,
        ref: URL,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        // The documented signature is Void: payload data cannot be returned to callers.
        let result: Void = try store.resolveToPasteboard(ref)
        _ = result
    }
}
