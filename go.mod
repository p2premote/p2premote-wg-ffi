// Candidate dependency baseline for the standalone Windows WG data-plane
// module. This file is intentionally separate from go.mod: the current
// punchffi package still contains gonc/Punch code and must not be downgraded
// as a whole.
module github.com/p2premote/p2premote-wg-ffi

go 1.20

require (
	github.com/tailscale/wireguard-go v0.0.0-20230410165232-af172621b4dd
	golang.org/x/crypto v0.13.0
	golang.org/x/sys v0.13.0
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2
	golang.zx2c4.com/wireguard/windows v0.5.3
	gvisor.dev/gvisor v0.0.0-20230927004350-cbd86285d259
)

require (
	github.com/google/btree v1.1.2 // indirect
	golang.org/x/net v0.15.0 // indirect
	golang.org/x/time v0.3.0 // indirect
)
