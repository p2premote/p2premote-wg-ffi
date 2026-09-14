module github.com/p2premote/p2premote-wg-ffi/mobile/libwgmobile

// 独立于仓库根 go.mod：根模块为 Windows WG 数据面锁定 Go 1.20 /
// wireguard-go 2023 版基线，本模块服务 Android gomobile 绑定，
// 依赖版本对齐 p2premote-punch 仓库（libwgmobile 的原始来源）。

go 1.26.0

require (
	github.com/tailscale/wireguard-go v0.0.0-20260622165914-65d8d42c9a5a
	golang.org/x/crypto v0.57.0
)

require (
	golang.org/x/mobile v0.0.0-20260908204917-8b95e45f8d3e // indirect
	golang.org/x/mod v0.41.0 // indirect
	golang.org/x/net v0.59.0 // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/tools v0.50.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
)

tool golang.org/x/mobile/cmd/gobind
