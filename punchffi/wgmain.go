//go:build wgonly

// Standalone userspace WireGuard C ABI entry point. The wgonly tag selects
// this c-shared build; the package carries no Punch/gonc transport code.
package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"encoding/json"
	"unsafe"
)

func encodeJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return `{"ok":false,"error":"failed to encode result"}`
	}
	return string(b)
}
func wgInput(p *C.char) (string, bool) {
	if p == nil {
		return `{"ok":false,"error":"input is null"}`, false
	}
	return C.GoString(p), true
}

func handleStartSubnetRouterJSON(s string) string {
	var r startSubnetRouterInput
	if err := json.Unmarshal([]byte(s), &r); err != nil {
		return encodeJSON(&subnetRouterResult{Error: "invalid input json: " + err.Error()})
	}
	return encodeJSON(startSubnetRouter(r))
}
func handleStopSubnetRouterJSON(s string) string {
	var r stopSubnetRouterInput
	if err := json.Unmarshal([]byte(s), &r); err != nil {
		return encodeJSON(&subnetRouterResult{Error: "invalid input json: " + err.Error()})
	}
	return encodeJSON(stopSubnetRouter(r.HandleID))
}
func handleGetSubnetRouterStatusJSON(s string) string {
	var r getSubnetRouterStatusInput
	if err := json.Unmarshal([]byte(s), &r); err != nil {
		return encodeJSON(&subnetRouterResult{Error: "invalid input json: " + err.Error()})
	}
	return encodeJSON(getSubnetRouterStatus(r.HandleID))
}
func handleStartWindowsWgPeerJSON(s string) string {
	var r startWindowsWgPeerInput
	if err := json.Unmarshal([]byte(s), &r); err != nil {
		return encodeJSON(&windowsWgPeerResult{Error: "invalid input json: " + err.Error()})
	}
	return encodeJSON(startWindowsWgPeer(r))
}
func handleWgPeerJSON(s string, f func(string) *windowsWgPeerResult) string {
	var r windowsWgPeerHandleInput
	if err := json.Unmarshal([]byte(s), &r); err != nil {
		return encodeJSON(&windowsWgPeerResult{Error: "invalid input json: " + err.Error()})
	}
	return encodeJSON(f(r.HandleID))
}
func handleWgAllowedJSON(s string) string {
	var r windowsWgPeerAllowedInput
	if err := json.Unmarshal([]byte(s), &r); err != nil {
		return encodeJSON(&windowsWgPeerResult{Error: "invalid input json: " + err.Error()})
	}
	return encodeJSON(setWindowsWgPeerAllowed(r.HandleID, r.Allowed))
}

//export StartSubnetRouter
func StartSubnetRouter(p *C.char) *C.char {
	s, ok := wgInput(p)
	if !ok {
		return C.CString(s)
	}
	return C.CString(handleStartSubnetRouterJSON(s))
}

//export StopSubnetRouter
func StopSubnetRouter(p *C.char) *C.char {
	s, ok := wgInput(p)
	if !ok {
		return C.CString(s)
	}
	return C.CString(handleStopSubnetRouterJSON(s))
}

//export GetSubnetRouterStatus
func GetSubnetRouterStatus(p *C.char) *C.char {
	s, ok := wgInput(p)
	if !ok {
		return C.CString(s)
	}
	return C.CString(handleGetSubnetRouterStatusJSON(s))
}

//export GetWgCapabilities
func GetWgCapabilities(p *C.char) *C.char {
	_ = p
	return C.CString(encodeJSON(platformWgCapabilities()))
}

//export GenerateWgKeypair
func GenerateWgKeypair(p *C.char) *C.char {
	_ = p
	return C.CString(encodeJSON(generateWindowsWgKeypair()))
}

//export StartWindowsWgPeer
func StartWindowsWgPeer(p *C.char) *C.char {
	s, ok := wgInput(p)
	if !ok {
		return C.CString(s)
	}
	return C.CString(handleStartWindowsWgPeerJSON(s))
}

//export StopWindowsWgPeer
func StopWindowsWgPeer(p *C.char) *C.char {
	s, ok := wgInput(p)
	if !ok {
		return C.CString(s)
	}
	return C.CString(handleWgPeerJSON(s, stopWindowsWgPeer))
}

//export GetWindowsWgPeerStatus
func GetWindowsWgPeerStatus(p *C.char) *C.char {
	s, ok := wgInput(p)
	if !ok {
		return C.CString(s)
	}
	return C.CString(handleWgPeerJSON(s, getWindowsWgPeerStatus))
}

//export SetWindowsWgPeerAllowed
func SetWindowsWgPeerAllowed(p *C.char) *C.char {
	s, ok := wgInput(p)
	if !ok {
		return C.CString(s)
	}
	return C.CString(handleWgAllowedJSON(s))
}

//export StopWindowsWgEngine
func StopWindowsWgEngine(p *C.char) *C.char {
	_ = p
	return C.CString(encodeJSON(stopWindowsWgEngine()))
}

//export CleanupWindowsWgPlatform
func CleanupWindowsWgPlatform(p *C.char) *C.char {
	_ = p
	return C.CString(encodeJSON(cleanupWindowsWgPlatform()))
}

//export StartUserspaceWgPeer
func StartUserspaceWgPeer(p *C.char) *C.char { return StartWindowsWgPeer(p) }

//export StopUserspaceWgPeer
func StopUserspaceWgPeer(p *C.char) *C.char { return StopWindowsWgPeer(p) }

//export GetUserspaceWgPeerStatus
func GetUserspaceWgPeerStatus(p *C.char) *C.char { return GetWindowsWgPeerStatus(p) }

//export SetUserspaceWgPeerAllowed
func SetUserspaceWgPeerAllowed(p *C.char) *C.char { return SetWindowsWgPeerAllowed(p) }

//export StopUserspaceWgEngine
func StopUserspaceWgEngine(p *C.char) *C.char { return StopWindowsWgEngine(p) }

//export CleanupUserspaceWgPlatform
func CleanupUserspaceWgPlatform(p *C.char) *C.char { return CleanupWindowsWgPlatform(p) }

//export FreeCString
func FreeCString(p *C.char) {
	if p != nil {
		C.free(unsafe.Pointer(p))
	}
}

func main() {}
