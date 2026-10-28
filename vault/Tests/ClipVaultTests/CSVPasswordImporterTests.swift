import XCTest
@testable import ClipVault

final class CSVPasswordImporterTests: XCTestCase {
    func testChromiumQuotedFieldsAndDuplicateDetection() throws {
        let csv = "name,url,username,password\r\n\"Work, mail\",https://example.test,alice,\"p,ass\"\r\nOther,https://example.test,alice,second\r\n"
        let result = try PasswordCSVImporter.parse(csv, format: .chrome)
        XCTAssertEqual(result.credentials.count, 1)
        XCTAssertEqual(result.credentials[0].title, "Work, mail")
        XCTAssertEqual(result.credentials[0].password, "p,ass")
        XCTAssertEqual(result.duplicateRows, [3])
    }

    func testFirefoxHeadersAndMultilineQuotedPassword() throws {
        let csv = "url,username,password,httpRealm\nhttps://example.test,bob,\"line one\nline two\",\n"
        let result = try PasswordCSVImporter.parse(csv, format: .firefox)
        XCTAssertEqual(result.credentials.first?.password, "line one\nline two")
    }

    func testSafariAndApplePasswordsHeaderVariants() throws {
        let safari = try PasswordCSVImporter.parse("Title,URL,Username,Password\nExample,https://example.test,alice,secret\n", format: .safari)
        let apple = try PasswordCSVImporter.parse("Website,User Name,Password\nhttps://example.test,bob,secret\n", format: .applePasswords)
        XCTAssertEqual(safari.credentials.count, 1)
        XCTAssertEqual(apple.credentials.count, 1)
    }

    func testInvalidRowsAreReportedWithoutValues() throws {
        let result = try PasswordCSVImporter.parse("url,username,password\nnot-a-url,user,secret\nhttps://example.test,,secret\n", format: .edge)
        XCTAssertTrue(result.credentials.isEmpty)
        XCTAssertEqual(result.rejectedRows, [2, 3])
    }

    func testMissingRequiredHeadersRejected() {
        XCTAssertThrowsError(try PasswordCSVImporter.parse("site,login\nhttps://example.test,user\n", format: .brave))
    }

    func testMalformedQuotingRejected() {
        XCTAssertThrowsError(try PasswordCSVImporter.parse("url,username,password\nhttps://example.test,user,\"unfinished\n", format: .chrome))
    }

    func testOfficialFormatIdentifiersAcceptSyntheticHeaderVariants() throws {
        let fixtures: [(PasswordCSVFormat, String)] = [
            (.chrome, "name,url,username,password\nChrome,https://example.test,u,p\n"),
            (.edge, "name,url,username,password\nEdge,https://example.test,u,p\n"),
            (.brave, "name,url,username,password\nBrave,https://example.test,u,p\n"),
            (.firefox, "url,username,password\nhttps://example.test,u,p\n"),
            (.safari, "Title,URL,Username,Password\nSafari,https://example.test,u,p\n"),
            (.applePasswords, "Website,User Name,Password\nhttps://example.test,u,p\n")
        ]
        for (format, csv) in fixtures {
            let result = try PasswordCSVImporter.parse(csv, format: format)
            XCTAssertEqual(result.credentials.count, 1, "format: \(format)")
        }
    }

    func testFileSizeLimit() {
        let csv = String(repeating: "x", count: PasswordCSVImporter.Limits.maximumFileBytes + 1)
        XCTAssertThrowsError(try PasswordCSVImporter.parse(csv, format: .chrome)) { error in
            XCTAssertEqual((error as? PasswordCSVParseError)?.reason, .fileTooLarge)
            XCTAssertFalse(String(describing: error).contains(String(repeating: "x", count: 100)))
        }
    }

    func testRowCountAndFieldLengthLimits() {
        let rowOverflow = "url,username,password\n" + String(repeating: "https://e.test,u,p\n", count: PasswordCSVImporter.Limits.maximumRows)
        XCTAssertThrowsError(try PasswordCSVImporter.parse(rowOverflow, format: .chrome)) { error in
            XCTAssertEqual((error as? PasswordCSVParseError)?.reason, .tooManyRows)
        }
        let longField = "url,username,password\nhttps://e.test,u,\"" + String(repeating: "x", count: PasswordCSVImporter.Limits.maximumFieldBytes + 1) + "\"\n"
        XCTAssertThrowsError(try PasswordCSVImporter.parse(longField, format: .chrome)) { error in
            XCTAssertEqual((error as? PasswordCSVParseError)?.reason, .fieldTooLong)
        }
    }

    func testParserDiagnosticsNeverIncludeSyntheticSecretValues() throws {
        let marker = "synthetic-secret-\(UUID().uuidString)"
        let malformed = "url,username,password\nhttps://example.test,user,\"\(marker)"
        XCTAssertThrowsError(try PasswordCSVImporter.parse(malformed, format: .chrome)) { error in
            XCTAssertFalse(String(describing: error).contains(marker))
            XCTAssertFalse(String(reflecting: error).contains(marker))
        }

        let result = try PasswordCSVImporter.parse(
            "url,username,password\nnot-a-url,user,\(marker)\n",
            format: .chrome
        )
        XCTAssertEqual(result.rejectedRows, [2])
        XCTAssertTrue(result.credentials.isEmpty)
        XCTAssertFalse(String(describing: result.rejectedRows).contains(marker))
    }
}
