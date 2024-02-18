// swift-tools-version:5.8
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "KeychainMacOS",
    platforms: [
        .macOS(.v13),
        .iOS(.v16)
    ],
    products: [
        // Products define the executables and libraries a package produces, and make them visible to other packages.
        .library(
            name: "KeychainMacOS",
            targets: ["KeychainMacOS"]),
    ],
    dependencies: [
        // Dependencies declare other packages that this package depends on.
        .package(url: "https://github.com/apple/swift-crypto", from: "3.2.0"),
        .package(url: "https://github.com/OperatorFoundation/KeychainTypes", from: "1.0.0"),
    ],
    targets: [
        .target(
            name: "KeychainMacOS",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
                "KeychainTypes",
            ]),
        .testTarget(
            name: "KeychainMacOSTests",
            dependencies:[
                "KeychainMacOS",
                "KeychainTypes",
            ]),
    ],
    swiftLanguageVersions: [.v5]
)
