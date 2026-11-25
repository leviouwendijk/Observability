// swift-tools-version: 6.3
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "Observability",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .library(
            name: "Observability",
            targets: [
                "Observability"
            ]
        )
    ],
    dependencies: [
        .package(
            url: "https://github.com/swift-webc/HTTP.git",
            branch: "master"
        ),
        .package(
            url: "https://github.com/swift-lco/Cryptography.git",
            branch: "master"
        )
    ],
    targets: [
        .target(
            name: "Observability",
            dependencies: [
                .product(
                    name: "HTTP",
                    package: "HTTP"
                ),
                .product(
                    name: "Cryptography",
                    package: "Cryptography"
                )
            ]
        )
    ],
    swiftLanguageModes: [.v6]
)
