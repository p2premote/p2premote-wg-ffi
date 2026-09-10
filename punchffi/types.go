//go:build !cgo

package main

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
