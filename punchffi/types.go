package main

// Shared JSON ABI types for the wgonly C-ABI entry points (wgmain.go) and the
// WGVPN engine files. The Rust FFI consumers declare field-compatible mirrors
// of these structs; changing a json tag changes the DLL wire format.
//
// startSubnetRouterInput is no longer an ABI input: the SubnetRouter C-ABI
// entry points were removed 2026-09-30 (audit B-1) because no platform calls
// them (Windows/macOS carry LAN routes in the userspace WG peer request,
// Linux uses the in-process Rust backend). It survives as the internal
// engine-construction/config type shared by the userspace peer path.

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
	OK          bool   `json:"ok"`
	ABIVersion  int    `json:"abi_version"`
	Platform    string `json:"platform"`
	UserspaceWG bool   `json:"userspace_wg"`
	HybridTun   bool   `json:"hybrid_tun"`
	Wintun      bool   `json:"wintun"`
	NativeTun   bool   `json:"native_tun"`
	Error       string `json:"error,omitempty"`
}

type wgKeypairResult struct {
	OK         bool   `json:"ok"`
	PrivateKey string `json:"private_key,omitempty"`
	PublicKey  string `json:"public_key,omitempty"`
	Error      string `json:"error,omitempty"`
}
