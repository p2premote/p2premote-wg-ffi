//go:build darwin && wgonly

// p2premote extension: dispatches the WGVPN subnet router on macOS to the
// shared userspace engine.
package main

func startPlatformSubnetRouter(req startSubnetRouterInput) *subnetRouterResult {
	return startWindowsSubnetRouter(req)
}
