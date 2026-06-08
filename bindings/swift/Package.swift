// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "EasyDogeKM",
    platforms: [
        .iOS(.v16),
        .macOS(.v13)
    ],
    products: [
        .library(name: "EasyDogeKM", targets: ["EasyDogeKM"])
    ],
    targets: [
        .target(
            name: "EasyDogeKM",
            dependencies: ["easydoge_km_ffi"]
        ),
        .target(
            name: "easydoge_km_ffi",
            dependencies: ["easydoge_km_ffiFFI"],
            linkerSettings: [
                .unsafeFlags(["-L../../target/debug"]),
                .linkedLibrary("easydoge_km_ffi")
            ]
        ),
        .systemLibrary(
            name: "easydoge_km_ffiFFI",
            path: "Sources/easydoge_km_ffiFFI"
        ),
        .testTarget(
            name: "EasyDogeKMTests",
            dependencies: ["EasyDogeKM"]
        )
    ]
)
