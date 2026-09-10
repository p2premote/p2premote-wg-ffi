//go:build windows

// p2premote extension: this entire file dispatches the WGVPN subnet router on Windows.
package main

func startPlatformSubnetRouter(req startSubnetRouterInput) *subnetRouterResult {
	return startWindowsSubnetRouter(req)
}
