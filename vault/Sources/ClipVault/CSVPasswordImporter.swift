import Foundation

/// Parsed credential from a human-selected official CSV export. Secrets are omitted from descriptions and errors.
public struct ImportedCredential: Codable, Equatable {
    public let url: String
    public let username: String
    public let password: String
    public let title: String?
    public init(url: String, username: String, password: String, title: String? = nil) {
        self.url = url; self.username = username; self.password = password; self.title = title
    }
}

public enum PasswordCSVFormat: String, CaseIterable { case chrome, edge, brave, firefox, safari, applePasswords }

public struct PasswordCSVParseError: Error, Equatable, CustomStringConvertible {
    public let row: Int
    public let reason: Reason
    public enum Reason: Equatable { case invalidCSV, missingHeaders, fileTooLarge, tooManyRows, fieldTooLong }
    public var description: String { "CSV row \(row): \(reason)" }
    public init(row: Int, reason: Reason) { self.row = row; self.reason = reason }
}

public struct PasswordCSVParseResult {
    public let credentials: [ImportedCredential]
    public let duplicateRows: [Int]
    public let rejectedRows: [Int]
}

public enum PasswordCSVImporter {
    public enum Limits {
        public static let maximumFileBytes = 10 * 1024 * 1024
        public static let maximumRows = 100_000
        public static let maximumFieldBytes = 64 * 1024
    }

    private static let aliases: [String: Set<String>] = [
        "url": ["url", "login uri", "login_uri", "website", "web site", "site", "origin", "hostname"],
        "username": ["username", "user name", "user_name", "login", "email"],
        "password": ["password", "pass"],
        "title": ["name", "title", "website name", "item name"]
    ]

    public static func parse(_ csv: String, format: PasswordCSVFormat) throws -> PasswordCSVParseResult {
        guard csv.utf8.count <= Limits.maximumFileBytes else {
            throw PasswordCSVParseError(row: 1, reason: .fileTooLarge)
        }
        let rows: [[String]]
        do { rows = try RFC4180.read(csv, maximumRows: Limits.maximumRows, maximumFieldBytes: Limits.maximumFieldBytes) }
        catch let error as PasswordCSVParseError { throw error }
        catch { throw PasswordCSVParseError(row: 1, reason: .invalidCSV) }
        guard let headerIndex = rows.firstIndex(where: { !$0.allSatisfy { $0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty } }) else {
            throw PasswordCSVParseError(row: 1, reason: .missingHeaders)
        }
        let headers = rows[headerIndex].map { $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased().replacingOccurrences(of: "\u{feff}", with: "") }
        func column(_ name: String) -> Int? {
            guard let names = aliases[name] else { return nil }
            return headers.firstIndex(where: names.contains)
        }
        guard let u = column("url"), let n = column("username"), let p = column("password") else {
            throw PasswordCSVParseError(row: headerIndex + 1, reason: .missingHeaders)
        }
        let titleColumn = column("title")
        var credentials: [ImportedCredential] = [], duplicates: [Int] = [], rejected: [Int] = []
        var seen = Set<String>()
        for (index, row) in rows.enumerated() where index > headerIndex {
            if row.allSatisfy({ $0.isEmpty }) { continue }
            guard row.count == headers.count else { rejected.append(index + 1); continue }
            let url = row[u].trimmingCharacters(in: .whitespacesAndNewlines), username = row[n], password = row[p]
            guard !url.isEmpty, !username.isEmpty, !password.isEmpty,
                  let parsed = URL(string: url), let scheme = parsed.scheme?.lowercased(),
                  ["http", "https"].contains(scheme), parsed.host != nil else { rejected.append(index + 1); continue }
            let key = "\(url.lowercased())\u{0}\(username)"
            guard seen.insert(key).inserted else { duplicates.append(index + 1); continue }
            let title = titleColumn.flatMap { $0 < row.count ? row[$0] : nil }.flatMap { $0.isEmpty ? nil : $0 }
            credentials.append(ImportedCredential(url: url, username: username, password: password, title: title))
        }
        _ = format
        return PasswordCSVParseResult(credentials: credentials, duplicateRows: duplicates, rejectedRows: rejected)
    }
}

private enum RFC4180 {
    static func read(_ text: String, maximumRows: Int, maximumFieldBytes: Int) throws -> [[String]] {
        var rows: [[String]] = [], row: [String] = [], field = "", fieldBytes = 0
        let chars = Array(text.unicodeScalars); var i = 0; var quoted = false
        func append(_ character: Unicode.Scalar) throws {
            field.unicodeScalars.append(character)
            fieldBytes += String(character).utf8.count
            if fieldBytes > maximumFieldBytes {
                throw PasswordCSVParseError(row: rows.count + 1, reason: .fieldTooLong)
            }
        }
        func finishRow() throws {
            row.append(field); field = ""; fieldBytes = 0
            rows.append(row); row = []
            if rows.count > maximumRows { throw PasswordCSVParseError(row: rows.count, reason: .tooManyRows) }
        }
        while i < chars.count {
            let c = chars[i]
            if quoted {
                if c == "\"" {
                    if i + 1 < chars.count && chars[i + 1] == "\"" { try append("\""); i += 1 }
                    else { quoted = false }
                } else { try append(c) }
            } else {
                switch c {
                case "\"": guard field.isEmpty else { throw PasswordCSVParseError(row: rows.count + 1, reason: .invalidCSV) }; quoted = true
                case ",": row.append(field); field = ""; fieldBytes = 0
                case "\n": try finishRow()
                case "\r": if i + 1 < chars.count && chars[i + 1] == "\n" { i += 1 }; try finishRow()
                default: try append(c)
                }
            }
            i += 1
        }
        guard !quoted else { throw PasswordCSVParseError(row: rows.count + 1, reason: .invalidCSV) }
        if !field.isEmpty || !row.isEmpty { try finishRow() }
        return rows
    }
}
