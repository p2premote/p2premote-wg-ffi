//go:build !windows && !darwin

// p2premote extension: this entire file dispatches the WGVPN subnet router on non-Windows platforms.
package main

import (
	"fmt"
	"runtime"
)

func startPlatformSubnetRouter(req startSubnetRouterInput) *subnetRouterResult {
	switch runtime.GOOS {
	case "linux":
		return startLinuxSubnetRouter(req)
	default:
		return &subnetRouterResult{
			OK:    false,
			Error: fmt.Sprintf("subnet router backend is not implemented on %s", runtime.GOOS),
		}
	}
}
