import XCTest
@testable import ClipVault

final class SensitivityAndLifecycleTests: XCTestCase {
    func testClassification() {
        let classifier = SensitivityClassifier()
        XCTAssertEqual(classifier.classify(Data("password=hunter2".utf8)), .password)
        XCTAssertEqual(classifier.classify(Data("api_key=sk_live_1234567890".utf8)), .apiKey)
        XCTAssertEqual(classifier.classify(Data("Bearer abcdefghijklmnopqrstuvwxyz".utf8)), .token)
        XCTAssertEqual(classifier.classify(Data("4111 1111 1111 1111".utf8)), .paymentCard)
        XCTAssertEqual(classifier.classify(Data("4111-1111-1111-1111".utf8)), .paymentCard)
        XCTAssertEqual(classifier.classify(Data("4111 abc 1111 xyz 1111 def 1111".utf8)), .publicData)
        XCTAssertEqual(classifier.classify(Data("ordinary note".utf8)), .publicData)
        XCTAssertTrue(SensitivityLabel.paymentCard.requiresVault)
        XCTAssertFalse(SensitivityLabel.publicData.requiresVault)
    }

    func testExpiry() {
        let now = Date(timeIntervalSince1970: 100)
        XCTAssertFalse(VaultExpiry.isExpired(expiresAt: nil, now: now))
        XCTAssertTrue(VaultExpiry.isExpired(expiresAt: now, now: now))
        XCTAssertEqual(VaultExpiry.expiry(from: now, ttl: 10), now.addingTimeInterval(10))
        XCTAssertEqual(VaultExpiry.expiry(from: now, ttl: -1), now)
        XCTAssertNil(VaultExpiry.expiry(from: now, ttl: nil))
    }

    func testAuditHasNoPayloadFields() throws {
        let record = VaultAuditRecord(reference: "clip://00000000-0000-0000-0000-000000000001",
                                      action: "resolve", outcome: "success",
                                      timestamp: Date(timeIntervalSince1970: 42))
        let sink = InMemoryVaultAuditSink()
        sink.record(record)
        XCTAssertEqual(sink.snapshot(), [record])
        let encoded = try String(decoding: JSONEncoder().encode(record), as: UTF8.self)
        XCTAssertFalse(encoded.contains("payload"))
        XCTAssertFalse(encoded.contains("secret"))
    }
}
