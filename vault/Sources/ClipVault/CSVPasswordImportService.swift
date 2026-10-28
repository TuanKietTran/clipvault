import Foundation

/// Human/UI-only orchestration for a user-selected official CSV export. This type does
/// not discover files and must not be surfaced by clipctl or agent-facing APIs.
public enum CSVPasswordImportService {
    public struct Report {
        public let references: [URL]
        public let duplicateRows: [Int]
        public let rejectedRows: [Int]
        /// The GUI should present this offer after a successful import and require explicit confirmation.
        public let offersSelectedFileDeletion: Bool
        public var importedCount: Int { references.count }
    }

    /// Reads only `selectedURL`, parses it, then writes each credential directly to the
    /// VaultStore. Payloads never pass through clipboard/history APIs.
    public static func importSelectedExport(at selectedURL: URL, format: PasswordCSVFormat,
                                             vault: VaultStore, providerTag: String) throws -> Report {
        let input: Data
        do { input = try readBounded(selectedURL) }
        catch let error as ImportError { throw error }
        catch { throw ImportError.cannotReadSelectedExport }
        guard let csv = String(data: input, encoding: .utf8) ?? String(data: input, encoding: .utf16) else {
            throw ImportError.invalidEncoding
        }
        let result: PasswordCSVParseResult
        do { result = try PasswordCSVImporter.parse(csv, format: format) }
        catch { throw ImportError.invalidExport }

        var references: [URL] = []
        for credential in result.credentials {
            do {
                let payload = try JSONEncoder().encode(credential)
                let ref = try vault.put(content: payload, type: "application/vnd.clipvault.credential+json",
                                        sourceApp: "password-csv:\(format.rawValue)",
                                        sensitivityLabel: "credential", ttl: nil,
                                        providerTag: providerTag)
                references.append(ref)
            } catch {
                // Do not propagate storage errors that may embed implementation details.
                throw ImportError.vaultWriteFailed(importedCount: references.count)
            }
        }
        return Report(references: references, duplicateRows: result.duplicateRows,
                      rejectedRows: result.rejectedRows, offersSelectedFileDeletion: true)
    }

    private static func readBounded(_ url: URL) throws -> Data {
        let handle: FileHandle
        do { handle = try FileHandle(forReadingFrom: url) }
        catch { throw ImportError.cannotReadSelectedExport }
        defer { try? handle.close() }
        var data = Data()
        let maximum = PasswordCSVImporter.Limits.maximumFileBytes
        while true {
            let remaining = maximum + 1 - data.count
            guard remaining > 0 else { throw ImportError.selectedExportTooLarge }
            let chunk: Data
            do { chunk = try handle.read(upToCount: min(64 * 1024, remaining)) ?? Data() }
            catch { throw ImportError.cannotReadSelectedExport }
            if chunk.isEmpty { break }
            data.append(chunk)
            if data.count > maximum { throw ImportError.selectedExportTooLarge }
        }
        return data
    }

    /// Invoke only after the GUI has explicitly confirmed the deletion offer. This is
    /// ordinary filesystem removal, not guaranteed secure erasure on APFS/SSD.
    @discardableResult
    public static func deleteSelectedExportAfterConfirmation(at selectedURL: URL,
                                                              after report: Report,
                                                              confirmed: Bool) throws -> Bool {
        guard report.offersSelectedFileDeletion, confirmed else { return false }
        do { try FileManager.default.removeItem(at: selectedURL) }
        catch { throw ImportError.selectedFileDeletionFailed }
        return !FileManager.default.fileExists(atPath: selectedURL.path)
    }

    public enum ImportError: Error, Equatable, CustomStringConvertible {
        case cannotReadSelectedExport
        case invalidEncoding
        case selectedExportTooLarge
        case invalidExport
        case vaultWriteFailed(importedCount: Int)
        case selectedFileDeletionFailed
        public var description: String {
            switch self {
            case .cannotReadSelectedExport: return "Unable to read the selected CSV export."
            case .invalidEncoding: return "The selected CSV export has an unsupported text encoding."
            case .selectedExportTooLarge: return "The selected CSV export exceeds the supported size limit."
            case .invalidExport: return "The selected file is not a valid supported password CSV export."
            case .vaultWriteFailed(let count): return "Vault import failed after storing \(count) item(s)."
            case .selectedFileDeletionFailed: return "Unable to remove the selected CSV export."
            }
        }
    }
}
