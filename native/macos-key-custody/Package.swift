// swift-tools-version: 6.1
import PackageDescription

let package = Package(
  name: "EchoVeilKeyCustody",
  platforms: [.macOS(.v13)],
  products: [
    .executable(
      name: "echo-veil-key-custody",
      targets: ["EchoVeilKeyCustody"]
    )
  ],
  targets: [
    .executableTarget(
      name: "EchoVeilKeyCustody",
      linkerSettings: [
        .linkedFramework("CryptoKit"),
        .linkedFramework("LocalAuthentication"),
        .linkedFramework("Security"),
      ]
    )
  ]
)
