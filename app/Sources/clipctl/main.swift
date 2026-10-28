import Foundation
import Darwin

struct Metadata: Codable {
    let reference: String
    let type: String
    let size: Int
    let sourceApp: String?
    let timestamp: String
    let sensitivityLabel: String
    let providerTag: String
}

struct Response: Decodable {
    let ok: Bool
    let error: String?
    let items: [Metadata]?
}

struct Request: Encodable {
    let command: String
    let reference: String?
}

func fail(_ message: String, code: Int32 = 1) -> Never {
    FileHandle.standardError.write(Data(("clipctl: \(message)\n").utf8))
    exit(code)
}

func socketPath() -> String {
    ProcessInfo.processInfo.environment["CLIPVAULT_SOCKET"] ??
        (NSHomeDirectory() + "/Library/Application Support/ClipVault/clipvault.sock")
}

func request(_ command: String, reference: String? = nil) throws -> Response {
    let path = socketPath()
    guard path.utf8.count < 104 else { throw NSError(domain: "clipctl", code: 1, userInfo: [NSLocalizedDescriptionKey: "socket path too long"]) }
    let fd = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
    guard fd >= 0 else { throw POSIXError(.init(rawValue: errno) ?? .EIO) }
    defer { _ = Darwin.close(fd) }

    var address = sockaddr_un()
    address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
    address.sun_family = sa_family_t(AF_UNIX)
    withUnsafeMutableBytes(of: &address.sun_path) { buffer in
        buffer.initializeMemory(as: UInt8.self, repeating: 0)
        buffer.copyBytes(from: Array(path.utf8))
    }
    let connected = withUnsafePointer(to: &address) { pointer in
        pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
        }
    }
    guard connected == 0 else { throw POSIXError(.init(rawValue: errno) ?? .ECONNREFUSED) }

    var body = try JSONEncoder().encode(Request(command: command, reference: reference))
    body.append(0x0a)
    let written = body.withUnsafeBytes { Darwin.write(fd, $0.baseAddress, $0.count) }
    guard written == body.count else { throw POSIXError(.init(rawValue: errno) ?? .EIO) }

    var response = Data()
    var byte: UInt8 = 0
    while response.count < 1_048_576 {
        let count = Darwin.read(fd, &byte, 1)
        if count <= 0 || byte == 0x0a { break }
        response.append(byte)
    }
    guard !response.isEmpty else { throw NSError(domain: "clipctl", code: 2, userInfo: [NSLocalizedDescriptionKey: "empty socket response"]) }
    return try JSONDecoder().decode(Response.self, from: response)
}

func validReference(_ value: String) -> Bool {
    guard value.hasPrefix("clip://") else { return false }
    let id = String(value.dropFirst(7))
    return UUID(uuidString: id) != nil
}

let args = Array(CommandLine.arguments.dropFirst())
guard let command = args.first else { fail("usage: clipctl list | copy clip://<UUID> | paste clip://<UUID>", code: 64) }
guard ["list", "copy", "paste"].contains(command) else { fail("unknown command", code: 64) }
let reference: String?
if command == "list" {
    guard args.count == 1 else { fail("usage: clipctl list", code: 64) }
    reference = nil
} else {
    guard args.count == 2, validReference(args[1]) else { fail("usage: clipctl \(command) clip://<UUID>", code: 64) }
    reference = args[1]
}

do {
    let result = try request(command, reference: reference)
    guard result.ok else { fail(result.error ?? "request failed") }
    if command == "list" {
        let items = result.items ?? []
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        if let data = try? encoder.encode(items), let text = String(data: data, encoding: .utf8) { print(text) }
    }
} catch { fail("\(error.localizedDescription). Is the ClipVault app running?") }
