//go:build wgonly

// p2premote extension: the userspace WireGuard engine shared by the Windows
// DLL and the macOS dylib. Platform-specific native-TUN plumbing (Wintun on
// Windows, utun on macOS) lives in subnet_platform_windows.go /
// subnet_platform_darwin.go behind the hooks below.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	wgdevice "github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun"
	"golang.org/x/crypto/curve25519"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	gtcp "gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	gudp "gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	windowsMaxTCPSessions  = 1024
	windowsMaxUDPSessions  = 4096
	windowsMaxICMPSessions = 20
	windowsUDPIdleTimeout  = 2 * time.Minute
	windowsNativeTunMTU    = 1280
	windowsPeerStopTimeout = 5 * time.Second
)

type windowsSubnetPeer struct {
	handleID    string
	role        string
	publicKey   string
	endpoint    string
	localTailIP netip.Addr
	peerTailIP  netip.Addr
	routes      []netip.Prefix
	advertised  []string
	ctx         context.Context
	cancel      context.CancelFunc
	tcpActive   atomic.Int32
	udpActive   atomic.Int32
	icmpOK      atomic.Int64
	icmpFailed  atomic.Int64
	rejected    atomic.Int64
	lastError   atomic.Value
	// wg 跟踪所有由 handleTCP/handleUDP/handleICMPEcho 启动的转发 goroutine。
	// stopWindowsSubnetPeer 在 cancel() 后 Wait()，确保所有 goroutine 退出再清理资源，
	// 避免 close engine 后 goroutine 仍访问 e.tun/e.registered 造成 use-after-close。
	wg sync.WaitGroup
}

func waitWindowsSubnetPeer(peer *windowsSubnetPeer, timeout time.Duration) bool {
	done := make(chan struct{})
	go func() {
		peer.wg.Wait()
		close(done)
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
		return true
	case <-timer.C:
		return false
	}
}

type windowsSubnetEngine struct {
	privateKey string
	listenIP   string
	listenPort int
	tun        *hybridTun
	wg         *wgdevice.Device
	net        *subnetNet
	bind       *loopbackBind
	peers      map[string]*windowsSubnetPeer
	registered map[netip.Addr]windowsRegisteredAddress
	tcpSem     chan struct{}
	udpSem     chan struct{}
	icmpSem    chan struct{}
	// configMu serializes control-plane changes.  It must never be taken by
	// packet forwarding: configuring Windows networking can synchronously start
	// netsh/PowerShell and take seconds on some hosts.
	configMu     sync.Mutex
	registeredMu sync.Mutex
	// These sets contain only routes/rules installed by this engine after the
	// process-start stale-state cleanup.  They let live reconciliation remove
	// only this engine's obsolete entries, rather than flushing the interface.
	nativeRoutes        map[string]map[netip.Prefix]struct{}
	nativeFirewallPeers map[string]map[netip.Addr]struct{}
	closeOnce           sync.Once
}

type windowsRegisteredAddress struct {
	refs int
}

var windowsSubnetManager struct {
	sync.Mutex
	engine *windowsSubnetEngine
}

func newWindowsSubnetEngine(req startSubnetRouterInput) (*windowsSubnetEngine, error) {
	privateKey, err := wgKeyBase64ToHex(req.WgPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("invalid wg_private_key: %w", err)
	}
	tunDev, netstackDev, err := createSubnetNetTUN(nil, 1280)
	if err != nil {
		return nil, fmt.Errorf("create userspace netstack failed: %w", err)
	}
	concreteTun := tunDev.(*subnetNetTun)
	hybrid := newHybridTun(concreteTun)
	engine := &windowsSubnetEngine{
		privateKey: privateKey, listenIP: req.ListenIP, listenPort: req.ListenPort,
		tun: hybrid, net: netstackDev, bind: newLoopbackBind(), peers: map[string]*windowsSubnetPeer{}, registered: map[netip.Addr]windowsRegisteredAddress{},
		nativeRoutes: map[string]map[netip.Prefix]struct{}{}, nativeFirewallPeers: map[string]map[netip.Addr]struct{}{},
		tcpSem: make(chan struct{}, windowsMaxTCPSessions), udpSem: make(chan struct{}, windowsMaxUDPSessions), icmpSem: make(chan struct{}, windowsMaxICMPSessions),
	}
	engine.wg = wgdevice.NewDevice(hybrid, engine.bind, &wgdevice.Logger{Verbosef: func(string, ...any) {}, Errorf: func(string, ...any) {}})
	if err := engine.wg.IpcSet("private_key=" + privateKey + "\nlisten_port=" + strconv.Itoa(req.ListenPort) + "\n"); err != nil {
		engine.close()
		return nil, fmt.Errorf("configure embedded wireguard failed: %w", err)
	}
	engine.installForwarders()
	engine.tun.packetHandler = engine.handleInboundPacket
	if err := engine.wg.Up(); err != nil {
		engine.close()
		return nil, fmt.Errorf("bring up embedded wireguard failed: %w", err)
	}
	return engine, nil
}

func (e *windowsSubnetEngine) compatible(req startSubnetRouterInput) error {
	privateKey, err := wgKeyBase64ToHex(req.WgPrivateKey)
	if err != nil {
		return fmt.Errorf("invalid wg_private_key: %w", err)
	}
	if privateKey != e.privateKey || req.ListenPort != e.listenPort || req.ListenIP != e.listenIP {
		return fmt.Errorf("subnet router engine parameters conflict with an active session")
	}
	return nil
}

func (e *windowsSubnetEngine) checkPeerConflicts(role, key string, tail netip.Addr, routes []netip.Prefix) error {
	for _, peer := range e.peers {
		if peer.publicKey == key {
			return fmt.Errorf("peer public key already active")
		}
		if peer.peerTailIP == tail {
			return fmt.Errorf("peer tail ip already active: %s", tail)
		}
		if prefixContains(peer.routes, tail) {
			return fmt.Errorf("peer tail ip %s overlaps active route", tail)
		}
		for _, route := range routes {
			if route.Contains(peer.peerTailIP) {
				return fmt.Errorf("route %s overlaps active peer tail ip %s", route, peer.peerTailIP)
			}
		}
		// Multiple active clients connected to the same passive gateway may
		// advertise the same local LAN. Their peerTailIP values disambiguate
		// inbound flows, so passive/passive overlap is valid. Overlapping remote
		// routes on an active side remain ambiguous and must still be rejected.
		if role != "passive" || peer.role != "passive" {
			for _, a := range peer.routes {
				for _, b := range routes {
					if a.Overlaps(b) {
						return fmt.Errorf("LAN route %s overlaps active route %s", b, a)
					}
				}
			}
		}
	}
	return nil
}

func (e *windowsSubnetEngine) removePeerConfig(peer *windowsSubnetPeer) {
	if e.wg != nil && peer != nil {
		_ = e.wg.IpcSet("public_key=" + peer.publicKey + "\nremove=true\n")
	}
}

func (e *windowsSubnetEngine) addPeer(req startSubnetRouterInput, peer *windowsSubnetPeer) error {
	var conf strings.Builder
	conf.WriteString("public_key=" + peer.publicKey + "\nprotocol_version=1\n")
	if endpoint := strings.TrimSpace(req.PeerEndpoint); endpoint != "" {
		conf.WriteString("endpoint=" + endpoint + "\n")
	}
	conf.WriteString("replace_allowed_ips=true\nallowed_ip=" + peer.peerTailIP.String() + "/32\n")
	if peer.role == "active" {
		for _, route := range peer.routes {
			conf.WriteString("allowed_ip=" + route.String() + "\n")
		}
	}
	conf.WriteString("persistent_keepalive_interval=25\n")
	if err := e.wg.IpcSet(conf.String()); err != nil {
		return fmt.Errorf("add embedded wireguard peer failed: %w", err)
	}
	return nil
}

func startWindowsWgPeer(req startWindowsWgPeerInput) *windowsWgPeerResult {
	if req.Role != "active" && req.Role != "passive" {
		return &windowsWgPeerResult{OK: false, Error: "role must be active or passive"}
	}
	localTailIP, err := netip.ParseAddr(req.LocalTailIP)
	if err != nil || !localTailIP.Is4() {
		return &windowsWgPeerResult{OK: false, Error: "invalid local_tail_ip"}
	}
	peerTailIP, err := netip.ParseAddr(req.PeerTailIP)
	if err != nil || !peerTailIP.Is4() {
		return &windowsWgPeerResult{OK: false, Error: "invalid peer_tail_ip"}
	}
	routes := make([]netip.Prefix, 0, len(req.Routes))
	for _, value := range req.Routes {
		prefix, parseErr := netip.ParsePrefix(value)
		if parseErr != nil || !prefix.Addr().Is4() {
			return &windowsWgPeerResult{OK: false, Error: "invalid IPv4 route: " + value}
		}
		routes = append(routes, prefix.Masked())
	}
	peerKey, err := wgKeyBase64ToHex(req.PeerPublicKey)
	if err != nil {
		return &windowsWgPeerResult{OK: false, Error: "invalid peer_public_key: " + err.Error()}
	}
	listenIP := strings.TrimSpace(req.ListenIP)
	if listenIP == "" {
		listenIP = "127.0.0.1"
	}
	listenPort := req.ListenPort
	if listenPort == 0 {
		listenPort = 51820
	}
	compatReq := startSubnetRouterInput{
		SessionID: req.SessionID, PeerDeviceID: req.PeerDeviceID,
		WgPrivateKey: req.WgPrivateKey, PeerPublicKey: req.PeerPublicKey,
		TailIP: localTailIP.String(), PeerTailIP: peerTailIP.String(),
		PeerEndpoint: req.PeerEndpoint, ListenIP: listenIP, ListenPort: listenPort,
		ExposedLANCIDRs: req.Routes,
	}

	windowsSubnetManager.Lock()
	engine := windowsSubnetManager.engine
	if engine == nil {
		engine, err = newWindowsSubnetEngine(compatReq)
		if err != nil {
			windowsSubnetManager.Unlock()
			return &windowsWgPeerResult{OK: false, Error: err.Error()}
		}
		windowsSubnetManager.engine = engine
	}
	windowsSubnetManager.Unlock()

	// Do not hold windowsSubnetManager while mutating Windows networking. The
	// packet path takes that mutex for every packet; holding it across a firewall
	// command made an existing RDP session freeze when a second peer joined.
	engine.configMu.Lock()
	defer engine.configMu.Unlock()

	windowsSubnetManager.Lock()
	if windowsSubnetManager.engine != engine {
		windowsSubnetManager.Unlock()
		return &windowsWgPeerResult{OK: false, Error: "userspace WireGuard engine stopped while starting peer"}
	}
	if err := engine.compatible(compatReq); err != nil {
		windowsSubnetManager.Unlock()
		return &windowsWgPeerResult{OK: false, Error: err.Error()}
	}
	if err := engine.checkPeerConflicts(req.Role, peerKey, peerTailIP.Unmap(), routes); err != nil {
		windowsSubnetManager.Unlock()
		return &windowsWgPeerResult{OK: false, Error: err.Error()}
	}
	windowsSubnetManager.Unlock()
	handleID := fmt.Sprintf("wgpeer-%d", time.Now().UnixNano())
	ctx, cancel := context.WithCancel(context.Background())
	peer := &windowsSubnetPeer{
		handleID: handleID, role: req.Role, publicKey: peerKey,
		endpoint: strings.TrimSpace(req.PeerEndpoint), localTailIP: localTailIP.Unmap(),
		peerTailIP: peerTailIP.Unmap(), routes: routes, advertised: append([]string(nil), req.Routes...),
		ctx: ctx, cancel: cancel,
	}
	if err := engine.addPeer(compatReq, peer); err != nil {
		cancel()
		windowsSubnetManager.Lock()
		if len(engine.peers) == 0 {
			engine.close()
			windowsSubnetManager.engine = nil
		}
		windowsSubnetManager.Unlock()
		return &windowsWgPeerResult{OK: false, Error: err.Error()}
	}
	windowsSubnetManager.Lock()
	engine.peers[handleID] = peer
	windowsSubnetManager.Unlock()
	if err := engine.refreshPlatformState(); err != nil {
		windowsSubnetManager.Lock()
		delete(engine.peers, handleID)
		engine.removePeerConfig(peer)
		cancel()
		if len(engine.peers) == 0 {
			engine.close()
			windowsSubnetManager.engine = nil
		}
		stillCurrent := windowsSubnetManager.engine == engine
		windowsSubnetManager.Unlock()
		// Reconcile the prior desired state without the failed peer. This is
		// safe because reconciliation is additive/differential, never a flush.
		if stillCurrent {
			_ = engine.refreshPlatformState()
		}
		return &windowsWgPeerResult{OK: false, Error: err.Error()}
	}
	engine.startHandshakeProbe(peer)
	return engine.peerResult(peer)
}

func stopWindowsWgPeer(handleID string) *windowsWgPeerResult {
	windowsSubnetManager.Lock()
	engine := windowsSubnetManager.engine
	if engine == nil {
		windowsSubnetManager.Unlock()
		return &windowsWgPeerResult{OK: true}
	}
	windowsSubnetManager.Unlock()
	engine.configMu.Lock()
	defer engine.configMu.Unlock()

	windowsSubnetManager.Lock()
	if windowsSubnetManager.engine != engine {
		windowsSubnetManager.Unlock()
		return &windowsWgPeerResult{OK: true}
	}
	peer := engine.peers[handleID]
	if peer == nil {
		windowsSubnetManager.Unlock()
		return &windowsWgPeerResult{OK: true}
	}
	delete(engine.peers, handleID)
	peer.cancel()
	windowsSubnetManager.Unlock()

	if !waitWindowsSubnetPeer(peer, windowsPeerStopTimeout) {
		return &windowsWgPeerResult{
			OK:    false,
			Error: fmt.Sprintf("timed out after %s waiting for peer forwarding goroutines to stop: %s", windowsPeerStopTimeout, handleID),
		}
	}

	windowsSubnetManager.Lock()
	if windowsSubnetManager.engine != engine {
		windowsSubnetManager.Unlock()
		return &windowsWgPeerResult{OK: true}
	}
	engine.removePeerConfig(peer)
	engine.removeRegisteredAddresses()
	if len(engine.peers) == 0 {
		engine.close()
		windowsSubnetManager.engine = nil
		windowsSubnetManager.Unlock()
		return &windowsWgPeerResult{OK: true}
	}
	windowsSubnetManager.Unlock()
	if err := engine.refreshPlatformState(); err != nil {
		return &windowsWgPeerResult{OK: false, Error: err.Error()}
	}
	return &windowsWgPeerResult{OK: true}
}

// setWindowsWgPeerAllowed toggles only the peer's AllowedIPs through the
// embedded WireGuard UAPI. The peer, endpoint, keys and keepalive remain alive,
// so approval never rebuilds the userspace engine or enters the packet path.
func setWindowsWgPeerAllowed(handleID string, allowed bool) *windowsWgPeerResult {
	windowsSubnetManager.Lock()
	engine := windowsSubnetManager.engine
	if engine == nil {
		windowsSubnetManager.Unlock()
		return &windowsWgPeerResult{OK: false, Error: "userspace WireGuard engine not running"}
	}
	peer := engine.peers[handleID]
	windowsSubnetManager.Unlock()
	if peer == nil {
		return &windowsWgPeerResult{OK: false, Error: "userspace WireGuard peer not found"}
	}
	if peer.role != "passive" {
		return &windowsWgPeerResult{OK: false, Error: "AllowedIPs approval gate is only valid for passive peers"}
	}

	engine.configMu.Lock()
	defer engine.configMu.Unlock()
	conf := "public_key=" + peer.publicKey + "\nreplace_allowed_ips=true\n"
	if allowed {
		conf += "allowed_ip=" + peer.peerTailIP.String() + "/32\n"
		for _, route := range peer.routes {
			conf += "allowed_ip=" + route.String() + "\n"
		}
	}
	if err := engine.wg.IpcSet(conf); err != nil {
		return &windowsWgPeerResult{OK: false, Error: "update embedded WireGuard AllowedIPs failed: " + err.Error()}
	}
	return engine.peerResult(peer)
}

func getWindowsWgPeerStatus(handleID string) *windowsWgPeerResult {
	windowsSubnetManager.Lock()
	defer windowsSubnetManager.Unlock()
	engine := windowsSubnetManager.engine
	if engine == nil || engine.peers[handleID] == nil {
		return &windowsWgPeerResult{OK: false, Error: "userspace WireGuard peer not found"}
	}
	return engine.peerResult(engine.peers[handleID])
}

func stopWindowsWgEngine() *windowsWgPeerResult {
	windowsSubnetManager.Lock()
	engine := windowsSubnetManager.engine
	windowsSubnetManager.Unlock()
	if engine == nil {
		return &windowsWgPeerResult{OK: true}
	}
	engine.configMu.Lock()
	defer engine.configMu.Unlock()
	windowsSubnetManager.Lock()
	if windowsSubnetManager.engine != engine {
		windowsSubnetManager.Unlock()
		return &windowsWgPeerResult{OK: true}
	}
	peers := make([]*windowsSubnetPeer, 0, len(engine.peers))
	for _, peer := range engine.peers {
		peers = append(peers, peer)
	}
	windowsSubnetManager.Unlock()
	for _, peer := range peers {
		peer.cancel()
	}
	for _, peer := range peers {
		if !waitWindowsSubnetPeer(peer, windowsPeerStopTimeout) {
			windowsSubnetManager.Lock()
			stillCurrent := windowsSubnetManager.engine == engine
			windowsSubnetManager.Unlock()
			if stillCurrent {
				return &windowsWgPeerResult{
					OK:    false,
					Error: fmt.Sprintf("timed out after %s waiting for peer forwarding goroutines to stop: %s", windowsPeerStopTimeout, peer.handleID),
				}
			}
			return &windowsWgPeerResult{OK: true}
		}
	}
	windowsSubnetManager.Lock()
	if windowsSubnetManager.engine != engine {
		windowsSubnetManager.Unlock()
		return &windowsWgPeerResult{OK: true}
	}
	windowsSubnetManager.engine = nil
	windowsSubnetManager.Unlock()
	engine.close()
	return &windowsWgPeerResult{OK: true}
}

func cleanupWindowsWgPlatform() *windowsWgPeerResult {
	if err := cleanupNativePlatform(); err != nil {
		return &windowsWgPeerResult{OK: false, Error: err.Error()}
	}
	return &windowsWgPeerResult{OK: true}
}

func generateWindowsWgKeypair() *wgKeypairResult {
	var private [32]byte
	if _, err := rand.Read(private[:]); err != nil {
		return &wgKeypairResult{OK: false, Error: err.Error()}
	}
	private[0] &= 248
	private[31] = (private[31] & 127) | 64
	var public [32]byte
	curve25519.ScalarBaseMult(&public, &private)
	return &wgKeypairResult{
		OK:         true,
		PrivateKey: base64.StdEncoding.EncodeToString(private[:]),
		PublicKey:  base64.StdEncoding.EncodeToString(public[:]),
	}
}

func (e *windowsSubnetEngine) peerResult(peer *windowsSubnetPeer) *windowsWgPeerResult {
	result := &windowsWgPeerResult{
		OK: true, HandleID: peer.handleID, Started: true, Role: peer.role,
		LocalTailIP: peer.localTailIP.String(), PeerTailIP: peer.peerTailIP.String(),
		TCPSessions: int(peer.tcpActive.Load()), UDPSessions: int(peer.udpActive.Load()),
		ICMPSuccess: peer.icmpOK.Load(), ICMPFailed: peer.icmpFailed.Load(), RejectedFlows: peer.rejected.Load(),
	}
	if value := peer.lastError.Load(); value != nil {
		result.LastError, _ = value.(string)
	}
	result.RxPackets, result.TxPackets = e.bind.endpointPackets(peer.endpoint)
	result.TxBatches = e.bind.txBatchStats()
	if e.wg != nil {
		if state, err := e.wg.IpcGet(); err == nil {
			result.LastHandshakeAt, result.RxBytes, result.TxBytes = parseWgPeerState(state, peer.publicKey)
		}
	}
	return result
}

func parseWgPeerState(state, publicKey string) (int64, int64, int64) {
	current := false
	var handshake, rx, tx int64
	for _, line := range strings.Split(state, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if key == "public_key" {
			current = strings.EqualFold(value, publicKey)
			continue
		}
		if !current {
			continue
		}
		parsed, _ := strconv.ParseInt(value, 10, 64)
		switch key {
		case "last_handshake_time_sec":
			handshake = parsed
		case "rx_bytes":
			rx = parsed
		case "tx_bytes":
			tx = parsed
		}
	}
	return handshake, rx, tx
}

func (e *windowsSubnetEngine) startHandshakeProbe(peer *windowsSubnetPeer) {
	peer.wg.Add(1)
	go func() {
		defer peer.wg.Done()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		deadline := time.NewTimer(35 * time.Second)
		defer deadline.Stop()
		for {
			if state, err := e.wg.IpcGet(); err == nil {
				handshake, _, _ := parseWgPeerState(state, peer.publicKey)
				if handshake > 0 {
					return
				}
			}
			packet := makeICMPEchoRequest(peer.localTailIP, peer.peerTailIP)
			if packet != nil {
				_ = e.tun.netstack.injectToWireGuard(packet)
			}
			select {
			case <-peer.ctx.Done():
				return
			case <-deadline.C:
				return
			case <-ticker.C:
			}
		}
	}()
}

func makeICMPEchoRequest(src, dst netip.Addr) []byte {
	if !src.Is4() || !dst.Is4() {
		return nil
	}
	packet := make([]byte, 28)
	packet[0] = 0x45
	packet[8] = 64
	packet[9] = 1
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	copy(packet[12:16], src.AsSlice())
	copy(packet[16:20], dst.AsSlice())
	packet[20] = 8
	binary.BigEndian.PutUint16(packet[24:26], uint16(time.Now().UnixNano()))
	binary.BigEndian.PutUint16(packet[22:24], internetChecksum(packet[20:]))
	binary.BigEndian.PutUint16(packet[10:12], internetChecksum(packet[:20]))
	return packet
}

// refreshPlatformState is the shared reconciliation skeleton: it groups peers
// by local tail IP, creates/destroys native TUN adapters through the platform
// hooks and delegates address/route/firewall work to configureNativeTun /
// clearNativeTun.
func (e *windowsSubnetEngine) refreshPlatformState() error {
	nativeByLocalIP := make(map[string][]*windowsSubnetPeer)
	// The caller serializes control-plane updates with configMu. Take the
	// manager lock only long enough to snapshot peers; forwarding is then free
	// to resolve packets while the OS applies the small delta below.
	windowsSubnetManager.Lock()
	for _, peer := range e.peers {
		key := peer.localTailIP.String()
		nativeByLocalIP[key] = append(nativeByLocalIP[key], peer)
	}
	windowsSubnetManager.Unlock()
	for key, peers := range nativeByLocalIP {
		if e.tun.nativeDevice(key) == nil {
			device, err := createNativeTun(peers[0].localTailIP, windowsNativeTunMTU)
			if err != nil {
				return fmt.Errorf("create native TUN for %s: %w", key, err)
			}
			if err := e.tun.attachNative(key, device); err != nil {
				return err
			}
		}
		if err := e.configureNativeTun(key, e.tun.nativeDevice(key), peers[0].localTailIP, peers); err != nil {
			return err
		}
	}
	for _, key := range e.tun.nativeKeys() {
		if _, ok := nativeByLocalIP[key]; ok {
			continue
		}
		if err := e.clearNativeTun(key, e.tun.nativeDevice(key)); err != nil {
			return err
		}
		if err := e.tun.detachNative(key); err != nil {
			return err
		}
	}
	return nil
}

// nativeRoutePrefixes lists the destinations the native TUN interface must
// route into WireGuard: every peer tail IP plus the remote LAN prefixes of
// active-side peers. Passive-side advertised routes describe the local LAN and
// must stay on the physical interface; installing them here would loop the
// gateway back through the tunnel.
func nativeRoutePrefixes(peers []*windowsSubnetPeer) []netip.Prefix {
	routes := make([]netip.Prefix, 0)
	seenRoute := map[netip.Prefix]bool{}
	for _, peer := range peers {
		peerRoute := netip.PrefixFrom(peer.peerTailIP, 32)
		if !seenRoute[peerRoute] {
			seenRoute[peerRoute] = true
			routes = append(routes, peerRoute)
		}
		if peer.role != "active" {
			continue
		}
		for _, route := range peer.routes {
			if !seenRoute[route] {
				seenRoute[route] = true
				routes = append(routes, route)
			}
		}
	}
	return routes
}

// reconcileNativeRoutes differentially applies `routes` through the
// platform-provided ensure/remove helpers, mirroring the OS route table without
// flushing entries this engine does not own.
func (e *windowsSubnetEngine) reconcileNativeRoutes(key string, routes []netip.Prefix, ensure func(netip.Prefix) error, remove func(netip.Prefix) error) error {
	want := make(map[netip.Prefix]struct{}, len(routes))
	for _, route := range routes {
		want[route] = struct{}{}
	}
	if e.nativeRoutes[key] == nil {
		e.nativeRoutes[key] = map[netip.Prefix]struct{}{}
	}
	current := e.nativeRoutes[key]
	for route := range want {
		// Re-apply on every reconcile. current tracks only ownership for stale
		// deletion and must not mask external drift.
		if err := ensure(route); err != nil {
			return fmt.Errorf("configure native route %s: %w", route, err)
		}
		current[route] = struct{}{}
	}
	for route := range current {
		if _, wanted := want[route]; wanted {
			continue
		}
		if err := remove(route); err != nil {
			return fmt.Errorf("remove stale native route %s: %w", route, err)
		}
		delete(current, route)
	}
	if len(current) == 0 {
		delete(e.nativeRoutes, key)
	}
	return nil
}

func (e *windowsSubnetEngine) removeRegisteredAddresses() {
	e.registeredMu.Lock()
	defer e.registeredMu.Unlock()
	for ip, registration := range e.registered {
		if registration.refs > 0 {
			continue
		}
		_ = e.net.stack.RemoveAddress(subnetNetstackNICID, tcpip.AddrFromSlice(ip.AsSlice()))
		delete(e.registered, ip)
	}
}

func (e *windowsSubnetEngine) resolvePeer(src, dst netip.Addr) *windowsSubnetPeer {
	windowsSubnetManager.Lock()
	defer windowsSubnetManager.Unlock()
	for _, peer := range e.peers {
		localTailIP := e.peerLocalTailIP(peer)
		if peer.role == "active" {
			if dst != localTailIP {
				continue
			}
			if src == peer.peerTailIP || prefixContains(peer.routes, src) {
				return peer
			}
			continue
		}
		if src == peer.peerTailIP && (dst == localTailIP || prefixContains(peer.routes, dst)) {
			return peer
		}
	}
	return nil
}

func (e *windowsSubnetEngine) peerLocalTailIP(peer *windowsSubnetPeer) netip.Addr {
	return peer.localTailIP
}

func prefixContains(prefixes []netip.Prefix, address netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func (e *windowsSubnetEngine) ensureAddress(peer *windowsSubnetPeer, ip netip.Addr) error {
	e.registeredMu.Lock()
	defer e.registeredMu.Unlock()
	if _, ok := e.registered[ip]; ok {
		return nil
	}
	if err := addNetstackAddress(e.net.stack, ip); err != nil {
		return err
	}
	e.registered[ip] = windowsRegisteredAddress{}
	return nil
}

func (e *windowsSubnetEngine) retainAddress(ip netip.Addr) bool {
	e.registeredMu.Lock()
	defer e.registeredMu.Unlock()
	registration, ok := e.registered[ip]
	if !ok {
		return false
	}
	registration.refs++
	e.registered[ip] = registration
	return true
}

func (e *windowsSubnetEngine) releaseAddress(ip netip.Addr) {
	e.registeredMu.Lock()
	defer e.registeredMu.Unlock()
	registration, ok := e.registered[ip]
	if !ok {
		return
	}
	registration.refs--
	if registration.refs <= 0 {
		_ = e.net.stack.RemoveAddress(subnetNetstackNICID, tcpip.AddrFromSlice(ip.AsSlice()))
		delete(e.registered, ip)
		return
	}
	e.registered[ip] = registration
}

func (e *windowsSubnetEngine) handleInboundPacket(raw []byte, offset int) hybridPacketDisposition {
	packet := raw[offset:]
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return hybridPacketConsumed
	}
	hlen := int(packet[0]&0x0f) * 4
	if hlen < 20 || len(packet) < hlen {
		return hybridPacketConsumed
	}
	src := netip.AddrFrom4([4]byte{packet[12], packet[13], packet[14], packet[15]})
	dst := netip.AddrFrom4([4]byte{packet[16], packet[17], packet[18], packet[19]})
	peer := e.resolvePeer(src, dst)
	if peer == nil {
		return hybridPacketConsumed
	}
	if e.usesNativeDestination(peer, dst) {
		if err := e.tun.writeNative(peer.localTailIP.String(), raw, offset); err != nil {
			peer.lastError.Store(err.Error())
			peer.rejected.Add(1)
		}
		return hybridPacketConsumed
	}
	if packet[9] == 1 && len(packet) >= hlen+8 && packet[hlen] == 8 {
		e.handleICMPEcho(peer, dst, append([]byte(nil), packet...))
		return hybridPacketConsumed
	}
	if packet[9] != 6 && packet[9] != 17 {
		peer.rejected.Add(1)
		return hybridPacketConsumed
	}
	if err := e.ensureAddress(peer, dst); err != nil {
		peer.lastError.Store(err.Error())
		peer.rejected.Add(1)
		return hybridPacketConsumed
	}
	return hybridPacketNetstack
}

func (e *windowsSubnetEngine) usesNativeDestination(peer *windowsSubnetPeer, dst netip.Addr) bool {
	return peer != nil && dst == e.peerLocalTailIP(peer)
}

func (e *windowsSubnetEngine) installForwarders() {
	tcpFwd := gtcp.NewForwarder(e.net.stack, 0, windowsMaxTCPSessions, e.handleTCP)
	udpFwd := gudp.NewForwarder(e.net.stack, e.handleUDP)
	e.net.stack.SetTransportProtocolHandler(gtcp.ProtocolNumber, tcpFwd.HandlePacket)
	e.net.stack.SetTransportProtocolHandler(gudp.ProtocolNumber, udpFwd.HandlePacket)
}

func (e *windowsSubnetEngine) handleTCP(req *gtcp.ForwarderRequest) {
	id := req.ID()
	dst, ok1 := netip.AddrFromSlice(id.LocalAddress.AsSlice())
	src, ok2 := netip.AddrFromSlice(id.RemoteAddress.AsSlice())
	if !ok1 || !ok2 {
		req.Complete(true)
		return
	}
	peer := e.resolvePeer(src.Unmap(), dst.Unmap())
	if peer == nil {
		req.Complete(true)
		return
	}
	if !e.retainAddress(dst.Unmap()) {
		peer.rejected.Add(1)
		req.Complete(true)
		return
	}
	select {
	case e.tcpSem <- struct{}{}:
	default:
		e.releaseAddress(dst.Unmap())
		peer.rejected.Add(1)
		req.Complete(true)
		return
	}
	dialHost := dst.Unmap().String()
	if dst.Unmap() == e.peerLocalTailIP(peer) {
		dialHost = "127.0.0.1"
	}
	ctx, cancel := context.WithTimeout(peer.ctx, 10*time.Second)
	backend, err := (&net.Dialer{}).DialContext(ctx, "tcp4", net.JoinHostPort(dialHost, strconv.Itoa(int(id.LocalPort))))
	cancel()
	if err != nil {
		<-e.tcpSem
		e.releaseAddress(dst.Unmap())
		peer.lastError.Store(err.Error())
		req.Complete(true)
		return
	}
	var wq waiter.Queue
	ep, terr := req.CreateEndpoint(&wq)
	if terr != nil {
		<-e.tcpSem
		e.releaseAddress(dst.Unmap())
		backend.Close()
		req.Complete(true)
		return
	}
	req.Complete(false)
	client := gonet.NewTCPConn(&wq, ep)
	peer.tcpActive.Add(1)
	peer.wg.Add(1)
	go func() {
		defer func() {
			<-e.tcpSem
			e.releaseAddress(dst.Unmap())
			peer.tcpActive.Add(-1)
			peer.wg.Done()
			backend.Close()
			client.Close()
		}()
		done := make(chan struct{}, 2)
		go func() { _, _ = io.Copy(backend, client); done <- struct{}{} }()
		go func() { _, _ = io.Copy(client, backend); done <- struct{}{} }()
		select {
		case <-done:
		case <-peer.ctx.Done():
		}
		backend.Close()
		client.Close()
	}()
}

func (e *windowsSubnetEngine) handleUDP(req *gudp.ForwarderRequest) {
	id := req.ID()
	dst, ok1 := netip.AddrFromSlice(id.LocalAddress.AsSlice())
	src, ok2 := netip.AddrFromSlice(id.RemoteAddress.AsSlice())
	if !ok1 || !ok2 {
		return
	}
	peer := e.resolvePeer(src.Unmap(), dst.Unmap())
	if peer == nil {
		return
	}
	if !e.retainAddress(dst.Unmap()) {
		peer.rejected.Add(1)
		return
	}
	select {
	case e.udpSem <- struct{}{}:
	default:
		e.releaseAddress(dst.Unmap())
		peer.rejected.Add(1)
		return
	}
	var wq waiter.Queue
	ep, terr := req.CreateEndpoint(&wq)
	if terr != nil {
		<-e.udpSem
		e.releaseAddress(dst.Unmap())
		return
	}
	client := gonet.NewUDPConn(e.net.stack, &wq, ep)
	dstAddr, bindIP := dst.Unmap().String(), net.IPv4zero
	if dst.Unmap() == e.peerLocalTailIP(peer) {
		dstAddr, bindIP = "127.0.0.1", net.IPv4(127, 0, 0, 1)
	}
	backend, err := net.ListenUDP("udp4", &net.UDPAddr{IP: bindIP})
	if err != nil {
		<-e.udpSem
		e.releaseAddress(dst.Unmap())
		client.Close()
		return
	}
	remote := &net.UDPAddr{IP: net.ParseIP(dstAddr), Port: int(id.LocalPort)}
	clientRemote := net.UDPAddrFromAddrPort(netip.AddrPortFrom(src.Unmap(), id.RemotePort))
	ctx, cancel := context.WithCancel(peer.ctx)
	timer := time.AfterFunc(windowsUDPIdleTimeout, cancel)
	peer.udpActive.Add(1)
	peer.wg.Add(1)
	go func() {
		defer func() {
			<-e.udpSem
			e.releaseAddress(dst.Unmap())
			peer.udpActive.Add(-1)
			peer.wg.Done()
			timer.Stop()
			cancel()
			client.Close()
			backend.Close()
		}()
		go udpCopyLoop(ctx, cancel, backend, remote, client, func() { timer.Reset(windowsUDPIdleTimeout) })
		udpCopyLoop(ctx, cancel, client, clientRemote, backend, func() { timer.Reset(windowsUDPIdleTimeout) })
	}()
}

func (e *windowsSubnetEngine) handleICMPEcho(peer *windowsSubnetPeer, dst netip.Addr, request []byte) {
	select {
	case e.icmpSem <- struct{}{}:
	default:
		peer.rejected.Add(1)
		return
	}
	peer.wg.Add(1)
	go func() {
		defer func() {
			<-e.icmpSem
			peer.wg.Done()
		}()
		ctx, cancel := context.WithTimeout(peer.ctx, 4*time.Second)
		defer cancel()
		if err := exec.CommandContext(ctx, "ping", pingArgs(dst.String())...).Run(); err != nil {
			peer.icmpFailed.Add(1)
			peer.lastError.Store(err.Error())
			return
		}
		reply := makeICMPEchoReply(request)
		if reply == nil {
			peer.icmpFailed.Add(1)
			return
		}
		if err := e.tun.netstack.injectToWireGuard(reply); err != nil {
			peer.icmpFailed.Add(1)
			peer.lastError.Store(err.Error())
			return
		}
		peer.icmpOK.Add(1)
	}()
}

func makeICMPEchoReply(packet []byte) []byte {
	if len(packet) < 28 || packet[0]>>4 != 4 {
		return nil
	}
	hlen := int(packet[0]&0x0f) * 4
	if hlen < 20 || len(packet) < hlen+8 {
		return nil
	}
	out := append([]byte(nil), packet...)
	copy(out[12:16], packet[16:20])
	copy(out[16:20], packet[12:16])
	out[hlen], out[hlen+1], out[hlen+2], out[hlen+3] = 0, 0, 0, 0
	binary.BigEndian.PutUint16(out[hlen+2:], internetChecksum(out[hlen:]))
	out[10], out[11] = 0, 0
	binary.BigEndian.PutUint16(out[10:], internetChecksum(out[:hlen]))
	return out
}

func internetChecksum(data []byte) uint16 {
	var sum uint32
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data))
		data = data[2:]
	}
	if len(data) == 1 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func addNetstackAddress(ipstack *stack.Stack, ip netip.Addr) error {
	if terr := ipstack.AddProtocolAddress(subnetNetstackNICID, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddrFromSlice(ip.AsSlice()).WithPrefix()}, stack.AddressProperties{}); terr != nil {
		return fmt.Errorf("%v", terr)
	}
	return nil
}

func wgKeyBase64ToHex(v string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(v))
	if err != nil {
		return "", err
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("expected 32 bytes, got %d", len(raw))
	}
	return hex.EncodeToString(raw), nil
}

func udpCopyLoop(ctx context.Context, cancel context.CancelFunc, dst net.PacketConn, fixedDst net.Addr, src net.PacketConn, onPacket func()) {
	buf := make([]byte, 64*1024)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		_ = src.SetReadDeadline(time.Now().Add(time.Second))
		n, addr, err := src.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			cancel()
			return
		}
		target := fixedDst
		if target == nil {
			target = addr
		}
		if _, err := dst.WriteTo(buf[:n], target); err != nil {
			cancel()
			return
		}
		onPacket()
	}
}

func (e *windowsSubnetEngine) close() {
	e.closeOnce.Do(func() {
		if e.tun != nil {
			for _, key := range e.tun.nativeKeys() {
				_ = e.clearNativeTun(key, e.tun.nativeDevice(key))
			}
		}
		if e.wg != nil {
			e.wg.Close()
		}
		if e.tun != nil {
			_ = e.tun.Close()
		}
	})
}

var _ tun.Device = (*subnetNetTun)(nil)
