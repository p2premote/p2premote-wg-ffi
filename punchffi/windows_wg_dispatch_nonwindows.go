//go:build !windows && !darwin

// p2premote extension: this entire file provides the non-Windows stub for Windows WGVPN dispatch.
package main

import "runtime"

func platformWgCapabilities() *wgCapabilitiesResult {
	return &wgCapabilitiesResult{OK: true, ABIVersion: 2, Platform: runtime.GOOS}
}

func unsupportedUserspaceWG() *windowsWgPeerResult {
	return &windowsWgPeerResult{OK: false, Error: "Windows userspace WireGuard is not supported on " + runtime.GOOS}
}

func startWindowsWgPeer(startWindowsWgPeerInput) *windowsWgPeerResult {
	return unsupportedUserspaceWG()
}
func stopWindowsWgPeer(string) *windowsWgPeerResult             { return unsupportedUserspaceWG() }
func setWindowsWgPeerAllowed(string, bool) *windowsWgPeerResult { return unsupportedUserspaceWG() }
func getWindowsWgPeerStatus(string) *windowsWgPeerResult        { return unsupportedUserspaceWG() }
func stopWindowsWgEngine() *windowsWgPeerResult                 { return unsupportedUserspaceWG() }
func cleanupWindowsWgPlatform() *windowsWgPeerResult            { return unsupportedUserspaceWG() }
func generateWindowsWgKeypair() *wgKeypairResult {
	return &wgKeypairResult{OK: false, Error: "Windows userspace WireGuard is not supported on " + runtime.GOOS}
}
