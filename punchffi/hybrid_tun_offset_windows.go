//go:build windows

package main

// Wintun packets do not use the Darwin utun address-family header.
const hybridNativePacketOffset = 0
