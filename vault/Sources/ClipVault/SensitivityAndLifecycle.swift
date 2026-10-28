import Foundation

/// Classification labels are metadata only; callers must never store the inspected value here.
public enum SensitivityLabel: String, Codable, CaseIterable {
    case publicData, password, apiKey, token, paymentCard
    public var requiresVault: Bool { self != .publicData }
}

public struct SensitivityClassifier {
    public init() {}
    public func classify(_ content: Data, declaredType: String? = nil) -> SensitivityLabel {
        let text = String(decoding: content, as: UTF8.self)
        let lower = text.lowercased()
        if Self.cardNumber(in: text) { return .paymentCard }
        if Self.contains(Self.passwordAssignment, in: lower) { return .password }
        if Self.contains(Self.apiKeyAssignment, in: lower) { return .apiKey }
        if Self.contains(Self.tokenAssignment, in: lower) || Self.contains(Self.jwt, in: text) { return .token }
        let type = (declaredType ?? "").lowercased()
        if type.contains("password") { return .password }
        if type.contains("token") { return .token }
        if type.contains("api-key") || type.contains("api_key") { return .apiKey }
        return .publicData
    }
    private static func regex(_ pattern: String) -> NSRegularExpression {
        try! NSRegularExpression(pattern: pattern, options: [.caseInsensitive])
    }
    private static func contains(_ regex: NSRegularExpression, in text: String) -> Bool {
        regex.firstMatch(in: text, range: NSRange(text.startIndex..., in: text)) != nil
    }
    private static let passwordAssignment = regex(#"(?:password|passwd|pwd)\s*[:=]\s*[^\s,;]{4,}"#)
    private static let apiKeyAssignment = regex(#"(?:api[_-]?key|secret[_-]?key)\s*[:=]\s*[a-z0-9_\-]{12,}"#)
    private static let tokenAssignment = regex(#"(?:access[_-]?token|refresh[_-]?token|bearer)\s*[:= ]\s*[a-z0-9._~+/-]{12,}"#)
    private static let jwt = regex(#"\beyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\b"#)
    private static let cardCandidate = regex(#"(?<![A-Za-z0-9])(?:[0-9][ -]?){12,18}[0-9](?![A-Za-z0-9])"#)
    private static func cardNumber(in text: String) -> Bool {
        let range = NSRange(text.startIndex..., in: text)
        return cardCandidate.matches(in: text, range: range).contains { match in
            guard let swiftRange = Range(match.range, in: text) else { return false }
            let digits = text[swiftRange].filter(\.isNumber)
            guard (13...19).contains(digits.count) else { return false }
            var sum = 0
            for (index, character) in digits.reversed().enumerated() {
                guard let digit = character.wholeNumberValue else { return false }
                var value = digit
                if index % 2 == 1 { value *= 2; if value > 9 { value -= 9 } }
                sum += value
            }
            return sum % 10 == 0
        }
    }
}

public enum VaultExpiry {
    public static func isExpired(expiresAt: Date?, now: Date = Date()) -> Bool {
        guard let expiresAt else { return false }
        return expiresAt <= now
    }
    public static func expiry(from now: Date = Date(), ttl: TimeInterval?) -> Date? {
        guard let ttl else { return nil }
        guard ttl.isFinite, ttl >= 0 else { return now }
        return now.addingTimeInterval(ttl)
    }
}

