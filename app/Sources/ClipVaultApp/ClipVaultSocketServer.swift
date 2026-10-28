import AppKit
import ClipVault
import CoreGraphics
import Darwin
import Foundation

private struct SocketRequest: Decodable {
    let command: String
    let reference: String?
}

private struct SocketMetadata: Encodable {
    let reference: String
    let type: String
    let size: Int
    let sourceApp: String?
    let timestamp: String
    let sensitivityLabel: String
    let providerTag: String

    init(_ value: VaultMetadata) {
        reference = value.reference
        type = value.type
        size = value.size
        sourceApp = value.sourceApp
        timestamp = ISO8601DateFormatter().string(from: value.timestamp)
        sensitivityLabel = value.sensitivityLabel
        providerTag = value.providerTag
    }
}

private struct SocketResponse: Encodable {
    let ok: Bool
    var error: String? = nil
    var items: [SocketMetadata]? = nil
}

/// Local, metadata-only command surface. Item payloads remain inside VaultStore and
/// are written only to NSPasteboard during resolve.
final class ClipVaultSocketServer {
    private let store: VaultStore
    private let path: String
    private let queue = DispatchQueue(label: "com.clipvault.socket", qos: .userInitiated)
    private var listener: Int32 = -1
    private var running = false

    init(store: VaultStore, path: String? = nil) {
        self.store = store
        self.path = path ?? ProcessInfo.processInfo.environment["CLIPVAULT_SOCKET"] ??
            (NSHomeDirectory() + "/Library/Application Support/ClipVault/clipvault.sock")
    }

    func start() throws {
        guard !running else { return }
        guard path.utf8.count < MemoryLayout.size(ofValue: sockaddr_un().sun_path) else {
            throw POSIXError(.ENAMETOOLONG)
        }
        let directory = URL(fileURLWithPath: path).deletingLastPathComponent()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        _ = unlink(path)
        let fd = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw POSIXError(.init(rawValue: errno) ?? .EIO) }
        var address = sockaddr_un()
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        address.sun_family = sa_family_t(AF_UNIX)
        withUnsafeMutableBytes(of: &address.sun_path) { buffer in
            buffer.initializeMemory(as: UInt8.self, repeating: 0)
            buffer.copyBytes(from: Array(path.utf8))
        }
        let bound = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard bound == 0 else {
            let code = errno
            _ = Darwin.close(fd)
            throw POSIXError(.init(rawValue: code) ?? .EIO)
        }
        guard chmod(path, S_IRUSR | S_IWUSR) == 0 else {
            let code = errno
            _ = Darwin.close(fd); _ = unlink(path)
            throw POSIXError(.init(rawValue: code) ?? .EIO)
        }
        guard Darwin.listen(fd, 8) == 0 else {
            let code = errno
            _ = Darwin.close(fd); _ = unlink(path)
            throw POSIXError(.init(rawValue: code) ?? .EIO)
        }
        listener = fd
        running = true
        queue.async { [weak self] in self?.acceptClients() }
    }

    deinit {
        if listener >= 0 { _ = Darwin.close(listener) }
        _ = unlink(path)
    }

    private func acceptClients() {
        while running {
            let client = Darwin.accept(listener, nil, nil)
            guard client >= 0 else { continue }
            handle(client)
            _ = Darwin.close(client)
        }
    }

    private func handle(_ fd: Int32) {
        var input = Data()
        var byte: UInt8 = 0
        while input.count < 16_384 {
            let count = Darwin.read(fd, &byte, 1)
            if count <= 0 || byte == 0x0a { break }
            input.append(byte)
        }
        let response: SocketResponse
        do {
            let request = try JSONDecoder().decode(SocketRequest.self, from: input)
            switch request.command {
            case "list":
                guard request.reference == nil else { throw SocketFailure.invalidRequest }
                response = SocketResponse(ok: true, items: try store.listMetadata().map(SocketMetadata.init))
            case "copy", "paste":
                guard let text = request.reference, let ref = Self.parseReference(text) else { throw SocketFailure.invalidRequest }
                try store.resolveToPasteboard(ref)
                if request.command == "paste" { synthesizePaste() }
                response = SocketResponse(ok: true)
            default: throw SocketFailure.invalidRequest
            }
        } catch {
            // Do not forward provider errors or untrusted request data over the API.
            response = SocketResponse(ok: false, error: "request failed")
        }
        guard var data = try? JSONEncoder().encode(response) else { return }
        data.append(0x0a)
        data.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else { return }
            var offset = 0
            while offset < raw.count {
                let count = Darwin.write(fd, base.advanced(by: offset), raw.count - offset)
                if count <= 0 { break }
                offset += count
            }
        }
    }

    private static func parseReference(_ text: String) -> URL? {
        guard text.hasPrefix("clip://"), UUID(uuidString: String(text.dropFirst(7))) != nil else { return nil }
        return URL(string: text)
    }

    private func synthesizePaste() {
        guard let down = CGEvent(keyboardEventSource: nil, virtualKey: 9, keyDown: true),
              let up = CGEvent(keyboardEventSource: nil, virtualKey: 9, keyDown: false) else { return }
        down.flags = .maskCommand
        up.flags = .maskCommand
        down.post(tap: .cghidEventTap)
        up.post(tap: .cghidEventTap)
    }
}

private enum SocketFailure: Error { case invalidRequest }
