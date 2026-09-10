//go:build wgonly

// Standalone Windows WireGuard C ABI entry point. Punch/STUN/MQTT handlers in
// main.go are excluded by the wgonly build tag.
package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"encoding/json"
	"unsafe"
)

type startSubnetRouterInput struct {
	SessionID       int64    `json:"session_id"`
	PeerDeviceID    int64    `json:"peer_device_id"`
	WgPrivateKey    string   `json:"wg_private_key"`
	PeerPublicKey   string   `json:"peer_public_key"`
	TailIP          string   `json:"tail_ip"`
	PeerTailIP      string   `json:"peer_tail_ip"`
	PeerEndpoint    string   `json:"peer_endpoint"`
	ListenIP        string   `json:"listen_ip"`
	ListenPort      int      `json:"listen_port"`
	ExposedLANCIDRs []string `json:"exposed_lan_cidrs"`
	SNAT            bool     `json:"snat"`
	AllowTCP        bool     `json:"allow_tcp"`
	AllowUDP        bool     `json:"allow_udp"`
	AllowICMPEcho   bool     `json:"allow_icmp_echo"`
}
type stopSubnetRouterInput struct {
	HandleID string `json:"handle_id"`
}
type getSubnetRouterStatusInput struct {
	HandleID string `json:"handle_id"`
}
type startWindowsWgPeerInput struct {
	SessionID     int64    `json:"session_id"`
	PeerDeviceID  int64    `json:"peer_device_id"`
	Role          string   `json:"role"`
	WgPrivateKey  string   `json:"wg_private_key"`
	PeerPublicKey string   `json:"peer_public_key"`
	LocalTailIP   string   `json:"local_tail_ip"`
	PeerTailIP    string   `json:"peer_tail_ip"`
	PeerEndpoint  string   `json:"peer_endpoint"`
	ListenIP      string   `json:"listen_ip"`
	ListenPort    int      `json:"listen_port"`
	Routes        []string `json:"routes"`
}
type windowsWgPeerHandleInput struct {
	HandleID string `json:"handle_id"`
}
type windowsWgPeerAllowedInput struct {
	HandleID string `json:"handle_id"`
	Allowed  bool   `json:"allowed"`
}
type windowsWgPeerResult struct {
	OK              bool   `json:"ok"`
	HandleID        string `json:"handle_id,omitempty"`
	Started         bool   `json:"started"`
	Role            string `json:"role,omitempty"`
	LocalTailIP     string `json:"local_tail_ip,omitempty"`
	PeerTailIP      string `json:"peer_tail_ip,omitempty"`
	LastHandshakeAt int64  `json:"last_handshake_at"`
	RxBytes         int64  `json:"rx_bytes"`
	TxBytes         int64  `json:"tx_bytes"`
	RxPackets       int64  `json:"rx_packets"`
	TxPackets       int64  `json:"tx_packets"`
	RxBatches       int64  `json:"rx_batches"`
	TxBatches       int64  `json:"tx_batches"`
	TCPSessions     int    `json:"tcp_sessions"`
	UDPSessions     int    `json:"udp_sessions"`
	ICMPSuccess     int64  `json:"icmp_success"`
	ICMPFailed      int64  `json:"icmp_failed"`
	RejectedFlows   int64  `json:"rejected_flows"`
	LastError       string `json:"last_error,omitempty"`
	Error           string `json:"error,omitempty"`
}
type wgCapabilitiesResult struct {
	OK            bool   `json:"ok"`
	ABIVersion    int    `json:"abi_version"`
	Platform      string `json:"platform"`
	UserspaceWG   bool   `json:"userspace_wg"`
	HybridTun     bool   `json:"hybrid_tun"`
	Wintun        bool   `json:"wintun"`
	NativeTun     bool   `json:"native_tun"`
	NetstackProxy bool   `json:"netstack_proxy"`
	Error         string `json:"error,omitempty"`
}
type wgKeypairResult struct {
	OK         bool   `json:"ok"`
	PrivateKey string `json:"private_key,omitempty"`
	PublicKey  string `json:"public_key,omitempty"`
	Error      string `json:"error,omitempty"`
}
type subnetRouterResult struct {
	OK               bool     `json:"ok"`
	HandleID         string   `json:"handle_id,omitempty"`
	LanMode          string   `json:"lan_mode,omitempty"`
	ListenIP         string   `json:"listen_ip,omitempty"`
	ListenPort       int      `json:"listen_port,omitempty"`
	Started          bool     `json:"started"`
	TCPSessions      int      `json:"tcp_sessions"`
	UDPSessions      int      `json:"udp_sessions"`
	WGRxPackets      int64    `json:"wg_rx_packets"`
	WGTxPackets      int64    `json:"wg_tx_packets"`
	ICMPSuccess      int64    `json:"icmp_success"`
	ICMPFailed       int64    `json:"icmp_failed"`
	RejectedFlows    int64    `json:"rejected_flows"`
	LastError        string   `json:"last_error,omitempty"`
	AdvertisedRoutes []string `json:"advertised_routes,omitempty"`
	Error            string   `json:"error,omitempty"`
}

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
