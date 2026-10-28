// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "ClipVaultApp",
    platforms: [.macOS(.v13)],
    dependencies: [.package(path: "../vault")],
    targets: [
        .executableTarget(name: "ClipVaultApp", dependencies: [.product(name: "ClipVault", package: "vault")], path: "Sources/ClipVaultApp"),
        .executableTarget(name: "clipctl", path: "Sources/clipctl")
    ]
)
