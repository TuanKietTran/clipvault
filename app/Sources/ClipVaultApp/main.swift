import AppKit
import Darwin
import ClipVault
import SwiftUI
import UniformTypeIdentifiers

@main
struct ClipVaultMenuApp: App {
    @StateObject private var model: ClipboardModel
    private let serviceModel: ClipboardModel

    init() {
        let serveMode = CommandLine.arguments.contains("--serve")
        if serveMode { NSApplication.shared.setActivationPolicy(.prohibited) }
        let serviceModel = ClipboardModel()
        self.serviceModel = serviceModel
        _model = StateObject(wrappedValue: serviceModel)
        guard serveMode else { return }
        do {
            try serviceModel.startServer()
            guard let store = serviceModel.store else { throw VaultError.storageFailure }
            print("CLIPVAULT_SOCKET_READY")
            fflush(stdout)
            if CommandLine.arguments.contains("--seed-smoke-item") {
                let reference = try store.put(content: Data("CLIPVAULT-SYNTHETIC-SMOKE".utf8),
                                              type: "public.utf8-plain-text", sourceApp: "clipvault-smoke",
                                              sensitivityLabel: "test", ttl: 300, providerTag: "local-encrypted")
                print(reference.absoluteString)
                fflush(stdout)
            }
            while true { _ = RunLoop.main.run(mode: .default, before: .distantFuture) }
        } catch {
            FileHandle.standardError.write(Data("ClipVault headless server failed: \(error.localizedDescription)\\n".utf8))
            exit(1)
        }
    }

    var body: some Scene {
        MenuBarExtra("ClipVault", systemImage: "clipboard") {
            ClipboardMenu(model: model)
        }
        .menuBarExtraStyle(.window)
        Settings {
            PreferencesView(model: model)
        }
    }
}

@MainActor
final class ClipboardModel: ObservableObject {
    @Published var search = ""
    @Published var items: [VaultMetadata] = []
    @Published var pinned = Set<String>()
    @Published var ignoredApps = Set<String>()
    @Published var selectedProvider = "local-encrypted"
    @Published var importPresented = false
    @Published var errorMessage: String?
    @Published var pendingImport: PendingImport?
    @Published var showImportPreview = false
    @Published var importFormat = PasswordCSVFormat.chrome

    var store: VaultStore?
    private var socketServer: ClipVaultSocketServer?
    private var clipboardTimer: Timer?
    private var lastPasteboardChangeCount = NSPasteboard.general.changeCount
    private let testMode = ProcessInfo.processInfo.environment["CLIPVAULT_TEST_MODE"] == "1"
    private var testProvider: InMemoryTestVaultProvider?

    init() {
        do {
            let vaultStore: VaultStoreService
            if testMode {
                let provider = InMemoryTestVaultProvider()
                testProvider = provider
                vaultStore = try VaultStoreService(providers: [provider])
            } else {
                let support = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
                    .appendingPathComponent("ClipVault", isDirectory: true)
                let local = try LocalEncryptedProvider(directory: support.appendingPathComponent("Vault", isDirectory: true))
                vaultStore = try VaultStoreService(providers: [local, AppleKeychainProvider()])
            }
            store = vaultStore
            if !CommandLine.arguments.contains("--serve") { try startServer() }
            refresh()
            startClipboardMonitoring()
        } catch {
            errorMessage = "Vault could not be initialized."
        }
    }

    deinit {
        clipboardTimer?.invalidate()
        testProvider?.removeAll()
    }

    func startServer() throws {
        guard socketServer == nil else { return }
        guard let store else { throw VaultError.storageFailure }
        let server = ClipVaultSocketServer(store: store)
        try server.start()
        socketServer = server
    }

    func startClipboardMonitoring() {
        guard clipboardTimer == nil else { return }
        let pasteboard = NSPasteboard.general
        lastPasteboardChangeCount = testMode ? Int.min : pasteboard.changeCount
        // Test mode may start after pbcopy races app launch; inspect the current item once,
        // but captureClipboardIfChanged still accepts only the synthetic test marker there.
        if testMode { captureClipboardIfChanged() }
        clipboardTimer = Timer.scheduledTimer(withTimeInterval: 0.65, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.captureClipboardIfChanged() }
        }
    }

    func stopClipboardMonitoring() {
        clipboardTimer?.invalidate()
        clipboardTimer = nil
    }

    private func captureClipboardIfChanged() {
        let pasteboard = NSPasteboard.general
        guard pasteboard.changeCount != lastPasteboardChangeCount else { return }
        lastPasteboardChangeCount = pasteboard.changeCount

        let frontmost = NSWorkspace.shared.frontmostApplication
        let sourceApp = frontmost?.bundleIdentifier ?? frontmost?.localizedName

        let payload: Data
        let type: String
        if let urls = pasteboard.readObjects(forClasses: [NSURL.self], options: nil) as? [URL], !urls.isEmpty {
            guard let encoded = try? JSONEncoder().encode(urls.map(\.absoluteString)) else { return }
            payload = encoded
            type = "com.clipvault.file-list+json"
        } else if let png = pasteboard.data(forType: .png), !png.isEmpty {
            payload = png
            type = NSPasteboard.PasteboardType.png.rawValue
        } else if let tiff = pasteboard.data(forType: .tiff), !tiff.isEmpty {
            payload = tiff
            type = NSPasteboard.PasteboardType.tiff.rawValue
        } else if let text = pasteboard.string(forType: .string), !text.isEmpty {
            payload = Data(text.utf8)
            type = NSPasteboard.PasteboardType.string.rawValue
        } else {
            return
        }
        if testMode {
            guard type == NSPasteboard.PasteboardType.string.rawValue,
                  let text = String(data: payload, encoding: .utf8),
                  text.hasPrefix("clipvault-smoke-") || text == "CLIPVAULT-SYNTHETIC-SMOKE" else { return }
        } else {
            if let bundleID = frontmost?.bundleIdentifier, ignoredApps.contains(bundleID) { return }
            if let appName = frontmost?.localizedName, ignoredApps.contains(appName) { return }
            if sourceApp == Bundle.main.bundleIdentifier || frontmost?.localizedName == "ClipVault" { return }
        }
        guard let store else { return }
        let sensitivity = SensitivityClassifier().classify(payload, declaredType: type)
        let provider = sensitivity.requiresVault ? "local-encrypted" : selectedProvider
        do {
            let reference = try store.put(content: payload, type: type, sourceApp: sourceApp,
                                          sensitivityLabel: sensitivity.rawValue, ttl: nil, providerTag: provider)
            if testMode, let referencePath = ProcessInfo.processInfo.environment["CLIPVAULT_TEST_REFERENCE_FILE"] {
                try? Data(reference.absoluteString.utf8).write(to: URL(fileURLWithPath: referencePath), options: .atomic)
            }
            refresh()
        } catch {
            errorMessage = "Unable to save clipboard item to the vault."
        }
    }

    var filteredItems: [VaultMetadata] {
        let query = search.trimmingCharacters(in: .whitespacesAndNewlines)
        return items.filter { item in
            guard item.sourceApp.map({ !ignoredApps.contains($0) }) ?? true else { return false }
            guard !query.isEmpty else { return true }
            return [item.type, item.sourceApp ?? "", item.sensitivityLabel, item.providerTag]
                .contains { $0.localizedCaseInsensitiveContains(query) }
        }.sorted {
            let left = pinned.contains($0.reference), right = pinned.contains($1.reference)
            return left == right ? $0.timestamp > $1.timestamp : left
        }
    }

    func refresh() {
        do { items = try store?.listMetadata() ?? [] }
        catch { errorMessage = "Unable to load clipboard metadata." }
    }

    func resolve(_ item: VaultMetadata) {
        do {
            guard let url = URL(string: item.reference) else { throw VaultError.invalidReference }
            try store?.resolveToPasteboard(url)
            lastPasteboardChangeCount = NSPasteboard.general.changeCount
        } catch { errorMessage = "Unable to copy this item to the pasteboard." }
    }

    func delete(_ item: VaultMetadata) {
        do {
            guard let url = URL(string: item.reference) else { throw VaultError.invalidReference }
            try store?.delete(url)
            refresh()
        } catch { errorMessage = "Unable to delete this item." }
    }

    func parseSelectedFile(_ url: URL) {
        do {
            let access = url.startAccessingSecurityScopedResource()
            defer { if access { url.stopAccessingSecurityScopedResource() } }
            let data = try Data(contentsOf: url, options: .mappedIfSafe)
            guard data.count <= 25 * 1024 * 1024, let csv = String(data: data, encoding: .utf8) else {
                throw ImportFailure.invalidFile
            }
            pendingImport = PendingImport(sourceURL: url, csv: csv, credentials: try PasswordCSVImporter.parse(csv, format: importFormat).credentials)
            showImportPreview = true
        } catch { errorMessage = "Could not read a supported UTF-8 password CSV." }
    }

    func commitImport(deleteSource: Bool) {
        guard let pendingImport, let store else { errorMessage = "Vault is unavailable."; return }
        do {
            for credential in pendingImport.credentials {
                // Credential material goes directly to VaultStore; it is never submitted to history.
                let encoded = try JSONEncoder().encode(CredentialPayload(url: credential.url, username: credential.username, password: credential.password, title: credential.title))
                _ = try store.put(content: encoded, type: "credential", sourceApp: nil,
                                  sensitivityLabel: "credential", ttl: nil, providerTag: selectedProvider)
            }
            if deleteSource { bestEffortSecureDelete(pendingImport.sourceURL) }
            self.pendingImport = nil
            showImportPreview = false
            refresh()
        } catch { errorMessage = "Import failed; the selected CSV was not deleted." }
    }

    private func bestEffortSecureDelete(_ url: URL) {
        // Best effort only: APFS snapshots, backups, replicas and SSD wear-leveling prevent guaranteed erasure.
        do {
            let access = url.startAccessingSecurityScopedResource()
            defer { if access { url.stopAccessingSecurityScopedResource() } }
            try FileManager.default.removeItem(at: url)
        } catch { errorMessage = "Imported, but the CSV could not be removed." }
    }
}

private struct CredentialPayload: Codable {
    let url: String
    let username: String
    let password: String
    let title: String?
}

struct PendingImport {
    let sourceURL: URL
    let csv: String
    let credentials: [ImportedCredential]
}

private enum ImportFailure: Error { case invalidFile }

struct ClipboardMenu: View {
    @ObservedObject var model: ClipboardModel

    var body: some View {
        VStack(spacing: 10) {
            HStack {
                Image(systemName: "magnifyingglass")
                TextField("Search metadata", text: $model.search).textFieldStyle(.plain)
                Button(action: model.refresh) { Image(systemName: "arrow.clockwise") }.help("Refresh")
            }.padding(.horizontal)
            if model.filteredItems.isEmpty {
                VStack(spacing: 8) {
                    Image(systemName: "clipboard").font(.largeTitle).foregroundStyle(.secondary)
                    Text("No clipboard items").font(.headline)
                    Text("Items are listed using metadata only.").font(.caption).foregroundStyle(.secondary)
                }.frame(maxWidth: .infinity, minHeight: 150)
            } else {
                List(model.filteredItems, id: \.reference) { item in
                    HistoryRow(item: item, isPinned: model.pinned.contains(item.reference),
                               copy: { model.resolve(item) },
                               togglePin: { togglePin(item, model: model) },
                               delete: { model.delete(item) })
                }.listStyle(.plain).frame(minHeight: 180, maxHeight: 360)
            }
            Divider()
            HStack {
                Button("Import Passwords…") { model.importPresented = true }
                Spacer()
                Button { NSApp.sendAction(Selector(("showPreferencesWindow:")), to: nil, from: nil) } label: { Image(systemName: "gearshape") }
                Button("Quit") { NSApplication.shared.terminate(nil) }
            }.padding(.horizontal)
        }
        .padding(.vertical, 10).frame(width: 390)
        .fileImporter(isPresented: $model.importPresented, allowedContentTypes: [.commaSeparatedText, .plainText], allowsMultipleSelection: false) { result in
            if case let .success(urls) = result, let url = urls.first { model.parseSelectedFile(url) }
            if case .failure = result { model.errorMessage = "File selection was cancelled or unavailable." }
        }
        .sheet(isPresented: $model.showImportPreview) {
            ImportPreview(model: model).frame(minWidth: 560, minHeight: 380)
        }
        .alert("ClipVault", isPresented: Binding(get: { model.errorMessage != nil }, set: { if !$0 { model.errorMessage = nil } })) {
            Button("OK") { model.errorMessage = nil }
        } message: { Text(model.errorMessage ?? "") }
        .onAppear { model.refresh() }
    }
}

private struct HistoryRow: View {
    let item: VaultMetadata
    let isPinned: Bool
    let copy: () -> Void
    let togglePin: () -> Void
    let delete: () -> Void

    var body: some View {
        HStack(spacing: 9) {
            Image(systemName: icon).frame(width: 22)
            VStack(alignment: .leading, spacing: 3) {
                Text(item.type.capitalized).font(.headline)
                Text([item.sourceApp, item.sensitivityLabel, item.providerTag].compactMap { $0 }.joined(separator: " · "))
                    .font(.caption).foregroundStyle(.secondary).lineLimit(1)
                Text("\(ByteCountFormatter.string(fromByteCount: Int64(item.size), countStyle: .file)) · \(item.timestamp.formatted(date: .abbreviated, time: .shortened))")
                    .font(.caption2).foregroundStyle(.tertiary)
            }
            Spacer(minLength: 2)
            Button(action: copy) { Image(systemName: "doc.on.clipboard") }.help("Write item to pasteboard")
            Button(action: togglePin) { Image(systemName: isPinned ? "pin.fill" : "pin") }.help(isPinned ? "Unpin" : "Pin")
            Button(role: .destructive, action: delete) { Image(systemName: "trash") }.help("Delete")
        }.padding(.vertical, 5)
    }

    private var icon: String {
        switch item.type.lowercased() {
        case "image": return "photo"
        case "file": return "doc"
        case "credential": return "key.fill"
        default: return "text.alignleft"
        }
    }
}

@MainActor
private func togglePin(_ item: VaultMetadata, model: ClipboardModel) {
    if model.pinned.contains(item.reference) { model.pinned.remove(item.reference) }
    else { model.pinned.insert(item.reference) }
}

private struct ImportPreview: View {
    @ObservedObject var model: ClipboardModel
    @State private var removeCSV = false

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Review password import").font(.title2.bold())
            Text("\(model.pendingImport?.credentials.count ?? 0) credentials will be written directly to the selected vault provider, not clipboard history.")
            HStack {
                Text("CSV export")
                Picker("CSV export", selection: $model.importFormat) {
                    Text("Chrome").tag(PasswordCSVFormat.chrome)
                    Text("Edge").tag(PasswordCSVFormat.edge)
                    Text("Brave").tag(PasswordCSVFormat.brave)
                    Text("Firefox").tag(PasswordCSVFormat.firefox)
                    Text("Safari").tag(PasswordCSVFormat.safari)
                    Text("Apple Passwords").tag(PasswordCSVFormat.applePasswords)
                }.labelsHidden().onChange(of: model.importFormat) { format in
                    guard let pending = model.pendingImport else { return }
                    do { model.pendingImport = PendingImport(sourceURL: pending.sourceURL, csv: pending.csv, credentials: try PasswordCSVImporter.parse(pending.csv, format: format).credentials) }
                    catch { model.errorMessage = "CSV does not match the selected official export format." }
                }
            }
            HStack {
                Text("Vault provider")
                Picker("Vault provider", selection: $model.selectedProvider) {
                    Text("Local encrypted").tag("local-encrypted")
                    Text("Apple Keychain (iCloud sync)").tag("apple-keychain")
                }.labelsHidden()
            }
            List(model.pendingImport?.credentials ?? [], id: \.url) { credential in
                VStack(alignment: .leading, spacing: 4) {
                    Text(credential.title ?? credential.url).font(.headline)
                    Text(credential.url).font(.caption)
                    Text("Username: \(credential.username) · Password: \(String(repeating: "•", count: min(credential.password.count, 16)))")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            Toggle("Remove selected CSV after successful import (best effort)", isOn: $removeCSV)
            Text("Secure deletion cannot be guaranteed for APFS snapshots, backups, synced copies, or SSD storage.")
                .font(.caption).foregroundStyle(.secondary)
            HStack {
                Spacer()
                Button("Cancel") { model.showImportPreview = false; model.pendingImport = nil }
                Button("Import") { model.commitImport(deleteSource: removeCSV) }.keyboardShortcut(.defaultAction)
                    .disabled(model.pendingImport?.credentials.isEmpty != false)
            }
        }.padding()
    }
}

private struct PreferencesView: View {
    @ObservedObject var model: ClipboardModel
    @State private var ignoredAppInput = ""
    @State private var hotkey = "⌃⌥V"

    var body: some View {
        Form {
            Section("Ignored apps") {
                HStack {
                    TextField("Bundle identifier or app name", text: $ignoredAppInput)
                    Button("Add") {
                        let value = ignoredAppInput.trimmingCharacters(in: .whitespacesAndNewlines)
                        if !value.isEmpty { model.ignoredApps.insert(value); ignoredAppInput = "" }
                    }
                }
                ForEach(model.ignoredApps.sorted(), id: \.self) { app in
                    HStack { Text(app); Spacer(); Button("Remove") { model.ignoredApps.remove(app) } }
                }
            }
            Section("Popup hotkey") {
                TextField("Shortcut", text: $hotkey)
                Text("Global shortcut registration is provided by the host app integration.").font(.caption).foregroundStyle(.secondary)
            }
            Section("Privacy") {
                Text("Agent-facing history displays metadata and opaque references only. Copy writes content to the system pasteboard.")
            }
        }.padding(20).frame(width: 430, height: 400)
    }
}
