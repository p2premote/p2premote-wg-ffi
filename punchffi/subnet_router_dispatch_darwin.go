//go:build darwin

package main

func startPlatformSubnetRouter(startSubnetRouterInput) *subnetRouterResult {
	return &subnetRouterResult{
		OK:    false,
		Error: "macOS LAN access is managed by the userspace WireGuard peer API",
	}
}
