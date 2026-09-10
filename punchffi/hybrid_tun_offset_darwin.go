//go:build darwin

package main

// Darwin utun prepends a four-byte address-family header. wireguard-go's
// NativeTun expects callers to reserve this headroom for both Read and Write.
const hybridNativePacketOffset = 4
