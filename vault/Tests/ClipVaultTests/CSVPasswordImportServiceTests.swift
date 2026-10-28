import Foundation
import XCTest
@testable import ClipVault

private final class ImportRecordingVault: VaultStore {
    private(set) var writes: [(Data, String, String?, String, TimeInterval?, String)] = []
    var shouldFail = false

    func put(content: Data, type: String, sourceApp: String?, sensitivityLabel: String,
             ttl: TimeInterval?, providerTag: String) throws -> URL {
        if shouldFail { throw ImportTestError.secretBearingFailure }
        writes.append((content, type, sourceApp, sensitivityLabel, ttl, providerTag))
        return URL(string: "clip://\(UUID().uuidString)")!
    }
    func listMetadata() throws -> [VaultMetadata] { [] }
    func resolveToPasteboard(_ ref: URL) throws {}
    func delete(_ ref: URL) throws {}
    func move(_ ref: URL, to providerTag: String) throws {}
}

private enum ImportTestError: Error, CustomStringConvertible {
    case secretBearingFailure
    var description: String { "internal synthetic-secret-should-not-escape" }
}

final class CSVPasswordImportServiceTests: XCTestCase {
    func testSelectedSyntheticExportWritesCredentialsDirectlyToVault() throws {
        let marker = "synthetic-secret-\(UUID().uuidString)"
        let csv = "url,username,password\nhttps://example.test,fixture-user,\(marker)\n"
        let file = FileManager.default.temporaryDirectory.appendingPathComponent("clipvault-import-\(UUID()).csv")
        try Data(csv.utf8).write(to: file)
        defer { try? FileManager.default.removeItem(at: file) }
        let vault = ImportRecordingVault()

        let report = try CSVPasswordImportService.importSelectedExport(
            at: file, format: .chrome, vault: vault, providerTag: "local-encrypted")

        XCTAssertEqual(report.importedCount, 1)
        XCTAssertTrue(report.offersSelectedFileDeletion)
        XCTAssertEqual(vault.writes.count, 1)
        let write = try XCTUnwrap(vault.writes.first)
        XCTAssertEqual(write.1, "application/vnd.clipvault.credential+json")
        XCTAssertEqual(write.2, "password-csv:chrome")
        XCTAssertEqual(write.3, "credential")
        XCTAssertNil(write.4)
        XCTAssertEqual(write.5, "local-encrypted")
        XCTAssertTrue(String(decoding: write.0, as: UTF8.self).contains(marker))
    }

    func testVaultWriteDiagnosticsDoNotLeakSecret() throws {
        let marker = "synthetic-secret-\(UUID().uuidString)"
        let file = FileManager.default.temporaryDirectory.appendingPathComponent("clipvault-import-\(UUID()).csv")
        try Data("url,username,password\nhttps://example.test,user,\(marker)\n".utf8).write(to: file)
        defer { try? FileManager.default.removeItem(at: file) }
        let vault = ImportRecordingVault()
        vault.shouldFail = true

        XCTAssertThrowsError(try CSVPasswordImportService.importSelectedExport(
            at: file, format: .chrome, vault: vault, providerTag: "local-encrypted")) { error in
            XCTAssertFalse(String(describing: error).contains(marker))
            XCTAssertFalse(String(reflecting: error).contains(marker))
        }
    }

    func testSelectedExportDeletionRequiresConfirmation() throws {
        let file = FileManager.default.temporaryDirectory.appendingPathComponent("clipvault-delete-\(UUID()).csv")
        try Data("url,username,password\nhttps://example.test,user,synthetic\n".utf8).write(to: file)
        defer { try? FileManager.default.removeItem(at: file) }
        let report = try CSVPasswordImportService.importSelectedExport(
            at: file, format: .chrome, vault: ImportRecordingVault(), providerTag: "local-encrypted")
        XCTAssertFalse(try CSVPasswordImportService.deleteSelectedExportAfterConfirmation(at: file, after: report, confirmed: false))
        XCTAssertTrue(FileManager.default.fileExists(atPath: file.path))
        XCTAssertTrue(try CSVPasswordImportService.deleteSelectedExportAfterConfirmation(at: file, after: report, confirmed: true))
        XCTAssertFalse(FileManager.default.fileExists(atPath: file.path))
    }
}
