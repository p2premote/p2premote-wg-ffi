//go:build !wgonly

// p2premote extension: this entire file is the desktop C ABI for invoking gonc and WGVPN services.
package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"
	"unsafe"

	"github.com/p2premote/p2premote-punch/easyp2p"
)

type udpTunnelInput struct {
	Token            string `json:"token"`
	RoleHint         string `json:"role_hint"`
	TraversalMode    string `json:"traversal_mode"`
	Network          string `json:"network"`
	TimeoutSecs      int    `json:"timeout_secs"`
	BindIP           string `json:"bind_ip"`
	LocalListenIP    string `json:"local_listen_ip"`
	LocalListenPort  int    `json:"local_listen_port"`
	RemoteTargetIP   string `json:"remote_target_ip"`
	RemoteTargetPort int    `json:"remote_target_port"`
	AllowRelay       bool   `json:"allow_relay"`
}

type stopTunnelInput struct {
	HandleID string `json:"handle_id"`
}

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

type stopTunnelResult struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

var (
	tunnelsMu sync.Mutex
	tunnels   = map[string]*easyp2p.UDPTunnel{}
)

func handleStartUdpTunnelJSON(input string) string {
	var req udpTunnelInput
	if err := json.Unmarshal([]byte(input), &req); err != nil {
		return encodeTunnelResult(&easyp2p.UDPTunnelResult{OK: false, Error: "invalid input json: " + err.Error()})
	}
	timeout := time.Duration(req.TimeoutSecs) * time.Second
	if timeout <= 0 {
		timeout = 45 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout+10*time.Second)
	defer cancel()

	var logs bytes.Buffer
	tunnel, err := easyp2p.StartUDPTunnel(ctx, easyp2p.UDPTunnelRequest{
		Token:            req.Token,
		RoleHint:         req.RoleHint,
		TraversalMode:    req.TraversalMode,
		Network:          req.Network,
		TimeoutSecs:      req.TimeoutSecs,
		BindIP:           req.BindIP,
		LocalListenIP:    req.LocalListenIP,
		LocalListenPort:  req.LocalListenPort,
		RemoteTargetIP:   req.RemoteTargetIP,
		RemoteTargetPort: req.RemoteTargetPort,
		AllowRelay:       req.AllowRelay,
	}, &logs)
	if err != nil {
		if result, ok := easyp2p.UDPTunnelResultFromError(err); ok {
			return encodeTunnelResult(&result)
		}
		return encodeTunnelResult(&easyp2p.UDPTunnelResult{OK: false, Error: err.Error()})
	}
	result := tunnel.Result()
	result.HandleID = fmt.Sprintf("udp-%d", time.Now().UnixNano())
	tunnelsMu.Lock()
	tunnels[result.HandleID] = tunnel
	tunnelsMu.Unlock()
	return encodeTunnelResult(&result)
}

func handleStopUdpTunnelJSON(input string) string {
	var req stopTunnelInput
	if err := json.Unmarshal([]byte(input), &req); err != nil {
		return encodeStopTunnelResult(&stopTunnelResult{OK: false, Error: "invalid input json: " + err.Error()})
	}
	if req.HandleID == "" {
		return encodeStopTunnelResult(&stopTunnelResult{OK: false, Error: "handle_id is required"})
	}
	tunnelsMu.Lock()
	tunnel := tunnels[req.HandleID]
	delete(tunnels, req.HandleID)
	tunnelsMu.Unlock()
	if tunnel == nil {
		return encodeStopTunnelResult(&stopTunnelResult{OK: true})
	}
	tunnel.Stop()
	return encodeStopTunnelResult(&stopTunnelResult{OK: true})
}

func handleStartSubnetRouterJSON(input string) string {
	var req startSubnetRouterInput
	if err := json.Unmarshal([]byte(input), &req); err != nil {
		return encodeSubnetRouterResult(&subnetRouterResult{OK: false, Error: "invalid input json: " + err.Error()})
	}
	if req.SessionID <= 0 {
		return encodeSubnetRouterResult(&subnetRouterResult{OK: false, Error: "session_id must be positive"})
	}
	if req.PeerDeviceID <= 0 {
		return encodeSubnetRouterResult(&subnetRouterResult{OK: false, Error: "peer_device_id must be positive"})
	}
	if len(req.ExposedLANCIDRs) == 0 {
		return encodeSubnetRouterResult(&subnetRouterResult{OK: false, Error: "exposed_lan_cidrs is required"})
	}
	if req.ListenPort <= 0 || req.ListenPort > 65535 {
		return encodeSubnetRouterResult(&subnetRouterResult{OK: false, Error: "listen_port must be 1..65535"})
	}
	if !req.SNAT {
		return encodeSubnetRouterResult(&subnetRouterResult{OK: false, Error: "snat=false is not supported"})
	}
	if req.ListenIP != "127.0.0.1" {
		return encodeSubnetRouterResult(&subnetRouterResult{OK: false, Error: "listen_ip must be 127.0.0.1"})
	}
	if !req.AllowTCP || !req.AllowUDP || !req.AllowICMPEcho {
		return encodeSubnetRouterResult(&subnetRouterResult{OK: false, Error: "TCP, UDP, and ICMP echo must all be enabled"})
	}
	return encodeSubnetRouterResult(startSubnetRouter(req))
}

func handleStopSubnetRouterJSON(input string) string {
	var req stopSubnetRouterInput
	if err := json.Unmarshal([]byte(input), &req); err != nil {
		return encodeSubnetRouterResult(&subnetRouterResult{OK: false, Error: "invalid input json: " + err.Error()})
	}
	if req.HandleID == "" {
		return encodeSubnetRouterResult(&subnetRouterResult{OK: false, Error: "handle_id is required"})
	}
	return encodeSubnetRouterResult(stopSubnetRouter(req.HandleID))
}

func handleGetSubnetRouterStatusJSON(input string) string {
	var req getSubnetRouterStatusInput
	if err := json.Unmarshal([]byte(input), &req); err != nil {
		return encodeSubnetRouterResult(&subnetRouterResult{OK: false, Error: "invalid input json: " + err.Error()})
	}
	if req.HandleID == "" {
		return encodeSubnetRouterResult(&subnetRouterResult{OK: false, Error: "handle_id is required"})
	}
	return encodeSubnetRouterResult(getSubnetRouterStatus(req.HandleID))
}

func encodeTunnelResult(result *easyp2p.UDPTunnelResult) string {
	data, err := json.Marshal(result)
	if err != nil {
		return `{"ok":false,"error":"failed to encode tunnel result"}`
	}
	return string(data)
}

func encodeStopTunnelResult(result *stopTunnelResult) string {
	data, err := json.Marshal(result)
	if err != nil {
		return `{"ok":false,"error":"failed to encode stop tunnel result"}`
	}
	return string(data)
}

func encodeSubnetRouterResult(result *subnetRouterResult) string {
	data, err := json.Marshal(result)
	if err != nil {
		return `{"ok":false,"error":"failed to encode subnet router result"}`
	}
	return string(data)
}

func encodeJSON(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		return `{"ok":false,"error":"failed to encode result"}`
	}
	return string(data)
}

func handleStartWindowsWgPeerJSON(input string) string {
	var req startWindowsWgPeerInput
	if err := json.Unmarshal([]byte(input), &req); err != nil {
		return encodeJSON(&windowsWgPeerResult{OK: false, Error: "invalid input json: " + err.Error()})
	}
	if req.SessionID <= 0 || req.PeerDeviceID <= 0 {
		return encodeJSON(&windowsWgPeerResult{OK: false, Error: "session_id and peer_device_id must be positive"})
	}
	return encodeJSON(startWindowsWgPeer(req))
}

func handleWindowsWgPeerJSON(input string, action func(string) *windowsWgPeerResult) string {
	var req windowsWgPeerHandleInput
	if err := json.Unmarshal([]byte(input), &req); err != nil {
		return encodeJSON(&windowsWgPeerResult{OK: false, Error: "invalid input json: " + err.Error()})
	}
	if req.HandleID == "" {
		return encodeJSON(&windowsWgPeerResult{OK: false, Error: "handle_id is required"})
	}
	return encodeJSON(action(req.HandleID))
}

func handleWindowsWgPeerAllowedJSON(input string) string {
	var req windowsWgPeerAllowedInput
	if err := json.Unmarshal([]byte(input), &req); err != nil {
		return encodeJSON(&windowsWgPeerResult{OK: false, Error: "invalid input json: " + err.Error()})
	}
	if req.HandleID == "" {
		return encodeJSON(&windowsWgPeerResult{OK: false, Error: "handle_id is required"})
	}
	return encodeJSON(setWindowsWgPeerAllowed(req.HandleID, req.Allowed))
}

//export StartUdpTunnel
func StartUdpTunnel(input *C.char) *C.char {
	if input == nil {
		return C.CString(`{"ok":false,"error":"input is null"}`)
	}
	return C.CString(handleStartUdpTunnelJSON(C.GoString(input)))
}

//export StopUdpTunnel
func StopUdpTunnel(input *C.char) *C.char {
	if input == nil {
		return C.CString(`{"ok":false,"error":"input is null"}`)
	}
	return C.CString(handleStopUdpTunnelJSON(C.GoString(input)))
}

//export StartSubnetRouter
func StartSubnetRouter(input *C.char) *C.char {
	if input == nil {
		return C.CString(`{"ok":false,"error":"input is null"}`)
	}
	return C.CString(handleStartSubnetRouterJSON(C.GoString(input)))
}

//export StopSubnetRouter
func StopSubnetRouter(input *C.char) *C.char {
	if input == nil {
		return C.CString(`{"ok":false,"error":"input is null"}`)
	}
	return C.CString(handleStopSubnetRouterJSON(C.GoString(input)))
}

//export GetSubnetRouterStatus
func GetSubnetRouterStatus(input *C.char) *C.char {
	if input == nil {
		return C.CString(`{"ok":false,"error":"input is null"}`)
	}
	return C.CString(handleGetSubnetRouterStatusJSON(C.GoString(input)))
}

//export GetWgCapabilities
func GetWgCapabilities(input *C.char) *C.char {
	_ = input
	return C.CString(encodeJSON(platformWgCapabilities()))
}

//export GenerateWgKeypair
func GenerateWgKeypair(input *C.char) *C.char {
	_ = input
	return C.CString(encodeJSON(generateWindowsWgKeypair()))
}

//export StartWindowsWgPeer
func StartWindowsWgPeer(input *C.char) *C.char {
	if input == nil {
		return C.CString(`{"ok":false,"error":"input is null"}`)
	}
	return C.CString(handleStartWindowsWgPeerJSON(C.GoString(input)))
}

//export StopWindowsWgPeer
func StopWindowsWgPeer(input *C.char) *C.char {
	if input == nil {
		return C.CString(`{"ok":false,"error":"input is null"}`)
	}
	return C.CString(handleWindowsWgPeerJSON(C.GoString(input), stopWindowsWgPeer))
}

//export GetWindowsWgPeerStatus
func GetWindowsWgPeerStatus(input *C.char) *C.char {
	if input == nil {
		return C.CString(`{"ok":false,"error":"input is null"}`)
	}
	return C.CString(handleWindowsWgPeerJSON(C.GoString(input), getWindowsWgPeerStatus))
}

//export SetWindowsWgPeerAllowed
func SetWindowsWgPeerAllowed(input *C.char) *C.char {
	if input == nil {
		return C.CString(`{"ok":false,"error":"input is null"}`)
	}
	return C.CString(handleWindowsWgPeerAllowedJSON(C.GoString(input)))
}

//export StopWindowsWgEngine
func StopWindowsWgEngine(input *C.char) *C.char {
	_ = input
	return C.CString(encodeJSON(stopWindowsWgEngine()))
}

//export CleanupWindowsWgPlatform
func CleanupWindowsWgPlatform(input *C.char) *C.char {
	_ = input
	return C.CString(encodeJSON(cleanupWindowsWgPlatform()))
}

// Generic userspace-WG ABI v2. The Windows-named exports above remain as
// compatibility aliases for one release cycle.

//export StartUserspaceWgPeer
func StartUserspaceWgPeer(input *C.char) *C.char { return StartWindowsWgPeer(input) }

//export StopUserspaceWgPeer
func StopUserspaceWgPeer(input *C.char) *C.char { return StopWindowsWgPeer(input) }

//export GetUserspaceWgPeerStatus
func GetUserspaceWgPeerStatus(input *C.char) *C.char { return GetWindowsWgPeerStatus(input) }

//export SetUserspaceWgPeerAllowed
func SetUserspaceWgPeerAllowed(input *C.char) *C.char { return SetWindowsWgPeerAllowed(input) }

//export StopUserspaceWgEngine
func StopUserspaceWgEngine(input *C.char) *C.char { return StopWindowsWgEngine(input) }

//export CleanupUserspaceWgPlatform
func CleanupUserspaceWgPlatform(input *C.char) *C.char { return CleanupWindowsWgPlatform(input) }

//export FreeCString
func FreeCString(ptr *C.char) {
	if ptr != nil {
		C.free(unsafe.Pointer(ptr))
	}
}

// ============ wgvpn 公钥/IP 交换 FFI ============
//
// 通过 gonc 的 MQTT 加密通道交换任意字符串载荷（双方互传 JSON）。
// 替代旧版 spawn p2plink.exe -send 的子进程方案，实现 gonc 彻底库化。
//
// exmode（对齐 easyp2p 的 EXMODE_*）：
//   0 = mutual   主动端：广播 sendData + 接收对端（一次调用完成双向交换）
//   1 = waitOnly 被动端第一步：只接收对端，不广播
//   2 = reply    被动端第二步：广播 sendData + 接收对端确认
//
// topicSalt 使用 "wgvpn-kx/" 前缀，与 UDP 数据面的地址交换 topic 隔离，
// 避免公钥交换数据与打洞地址交换数据串扰。

const wgvpnExchangeTopicSalt = "wgvpn-kx/"

type exchangeInput struct {
	Token       string `json:"token"`
	Exmode      int    `json:"exmode"`
	SendData    string `json:"send_data"`
	RoleHint    string `json:"role_hint"`
	TimeoutSecs int    `json:"timeout_secs"`
}

type exchangeResult struct {
	OK       bool   `json:"ok"`
	RecvData string `json:"recv_data"`
	Error    string `json:"error"`
}

func handleExchangeJSON(input string) string {
	var req exchangeInput
	if err := json.Unmarshal([]byte(input), &req); err != nil {
		return encodeExchangeResult(&exchangeResult{OK: false, Error: "invalid input json: " + err.Error()})
	}
	if req.Token == "" {
		return encodeExchangeResult(&exchangeResult{OK: false, Error: "token is required"})
	}
	if req.RoleHint != "" && req.RoleHint != "active" && req.RoleHint != "passive" {
		return encodeExchangeResult(&exchangeResult{OK: false, Error: fmt.Sprintf("unsupported role_hint: %s", req.RoleHint)})
	}
	timeout := time.Duration(req.TimeoutSecs) * time.Second
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout+10*time.Second)
	defer cancel()

	// 调用确定性高层封装：双方相同 token → 相同 topic → 成功交换
	recvData, err := easyp2p.MQTT_ExchangePayload(
		ctx, req.Exmode, req.SendData, req.Token, wgvpnExchangeTopicSalt, "", timeout,
	)
	if err != nil {
		return encodeExchangeResult(&exchangeResult{OK: false, Error: err.Error()})
	}
	return encodeExchangeResult(&exchangeResult{OK: true, RecvData: recvData})
}

func encodeExchangeResult(result *exchangeResult) string {
	data, err := json.Marshal(result)
	if err != nil {
		return `{"ok":false,"error":"failed to encode exchange result"}`
	}
	return string(data)
}

//export Exchange
func Exchange(input *C.char) *C.char {
	if input == nil {
		return C.CString(`{"ok":false,"error":"input is null"}`)
	}
	return C.CString(handleExchangeJSON(C.GoString(input)))
}

func main() {}
