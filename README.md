# p2premote-wg-ffi

Thin Go C ABI for the desktop client's userspace WireGuard data plane. It
contains WireGuard-go, gVisor, Wintun and the Windows subnet-router backend;
it deliberately contains no STUN, MQTT signaling, NAT traversal or Punch
transport code. Those responsibilities live in the Rust \`p2premote-punch-rs-gonc\`
crate and are linked directly into the client.

## Windows build

Build with the Go 1.20.14 compatibility baseline:

\`\`\`bash
GOTOOLCHAIN=go1.20.14 go build -tags wgonly -buildmode=c-shared \
  -ldflags "-s -w" -o p2premote-wg.dll ./punchffi
\`\`\`

The client requires ABI version \`2\`, reported by \`GetWgCapabilities\`.
The exported JSON-in/JSON-out functions are:

- \`GetWgCapabilities\`, \`GenerateWgKeypair\`
- \`Start/Stop/Get/SetUserspaceWgPeer\`
- \`StopUserspaceWgEngine\`, \`CleanupUserspaceWgPlatform\`
- \`Start/Stop/GetSubnetRouter\`
- \`FreeCString\`

Every returned string must be released by this module's \`FreeCString\`.

## Platform scope

The standalone ABI is currently complete for Windows. Linux uses the
client's kernel WireGuard / \`wireguard-go\` fallback, while macOS remains on
the legacy combined dynamic library until its WG backend is extracted and
build-tested here.
