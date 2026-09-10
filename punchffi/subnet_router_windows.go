//go:build windows

// p2premote extension: this entire file implements p2premote's Windows WGVPN subnet router.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
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

	"github.com/tailscale/wireguard-go/conn"
	wgdevice "github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
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
	windowsWintunMTU       = 1280
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
	// tailIP is retained for compatibility with focused netstack tests. Runtime
	// routing uses each peer's localTailIP so active and passive roles can share
	// one engine.
	tailIP     netip.Addr
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
	refs       int
	persistent bool
}

var windowsSubnetManager struct {
	sync.Mutex
	engine *windowsSubnetEngine
}

func platformWgCapabilities() *wgCapabilitiesResult {
	return &wgCapabilitiesResult{
		OK: true, ABIVersion: 2, Platform: "windows", UserspaceWG: true, HybridTun: true, Wintun: true, NativeTun: true, NetstackProxy: true,
	}
}

func startWindowsSubnetRouter(req startSubnetRouterInput) *subnetRouterResult {
	tailIP, peerTailIP, routes, err := validateWindowsSubnetRequest(req)
	if err != nil {
		return &subnetRouterResult{OK: false, Error: err.Error()}
	}
	peerKey, err := wgKeyBase64ToHex(req.PeerPublicKey)
	if err != nil {
		return &subnetRouterResult{OK: false, Error: fmt.Sprintf("invalid peer_public_key: %v", err)}
	}

	windowsSubnetManager.Lock()
	defer windowsSubnetManager.Unlock()
	engine := windowsSubnetManager.engine
	if engine == nil {
		engine, err = newWindowsSubnetEngine(req, tailIP)
		if err != nil {
			return &subnetRouterResult{OK: false, Error: err.Error()}
		}
		windowsSubnetManager.engine = engine
	} else if err := engine.compatible(req, tailIP); err != nil {
		return &subnetRouterResult{OK: false, Error: err.Error()}
	}
	if err := engine.checkPeerConflicts("passive", peerKey, peerTailIP, routes); err != nil {
		return &subnetRouterResult{OK: false, Error: err.Error()}
	}

	handleID := fmt.Sprintf("subnet-%d", time.Now().UnixNano())
	ctx, cancel := context.WithCancel(context.Background())
	peer := &windowsSubnetPeer{
		handleID: handleID, role: "passive", publicKey: peerKey, endpoint: strings.TrimSpace(req.PeerEndpoint), localTailIP: tailIP, peerTailIP: peerTailIP,
		routes: routes, advertised: append([]string(nil), req.ExposedLANCIDRs...),
		ctx: ctx, cancel: cancel,
	}
	if err := engine.addPeer(req, peer); err != nil {
		cancel()
		if len(engine.peers) == 0 {
			engine.close()
			windowsSubnetManager.engine = nil
		}
		return &subnetRouterResult{OK: false, Error: err.Error()}
	}
	engine.peers[handleID] = peer
	if err := engine.refreshNetstackAddresses(); err != nil {
		delete(engine.peers, handleID)
		engine.removePeerConfig(peer)
		cancel()
		if len(engine.peers) == 0 {
			engine.close()
			windowsSubnetManager.engine = nil
		}
		return &subnetRouterResult{OK: false, Error: err.Error()}
	}

	result := subnetRouterResult{OK: true, HandleID: handleID, LanMode: "userspace_snat", ListenIP: req.ListenIP, ListenPort: req.ListenPort, Started: true, AdvertisedRoutes: peer.advertised}
	subnetRoutersMu.Lock()
	subnetRouters[handleID] = &subnetRouterHandle{
		result:   result,
		stopFn:   func() { stopWindowsSubnetPeer(handleID) },
		statusFn: func(out *subnetRouterResult) { updateWindowsSubnetStatus(handleID, out) },
	}
	subnetRoutersMu.Unlock()
	return &result
}

func validateWindowsSubnetRequest(req startSubnetRouterInput) (netip.Addr, netip.Addr, []netip.Prefix, error) {
	tailIP, err := netip.ParseAddr(req.TailIP)
	if err != nil || !tailIP.Is4() {
		return netip.Addr{}, netip.Addr{}, nil, fmt.Errorf("invalid tail_ip: %s", req.TailIP)
	}
	peerTailIP, err := netip.ParseAddr(req.PeerTailIP)
	if err != nil || !peerTailIP.Is4() {
		return netip.Addr{}, netip.Addr{}, nil, fmt.Errorf("invalid peer_tail_ip: %s", req.PeerTailIP)
	}
	routes := make([]netip.Prefix, 0, len(req.ExposedLANCIDRs))
	for _, text := range req.ExposedLANCIDRs {
		prefix, err := netip.ParsePrefix(text)
		if err != nil || !prefix.Addr().Is4() {
			return netip.Addr{}, netip.Addr{}, nil, fmt.Errorf("invalid ipv4 exposed_lan_cidr: %s", text)
		}
		routes = append(routes, prefix.Masked())
	}
	return tailIP.Unmap(), peerTailIP.Unmap(), routes, nil
}

func newWindowsSubnetEngine(req startSubnetRouterInput, tailIP netip.Addr) (*windowsSubnetEngine, error) {
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
		privateKey: privateKey, tailIP: tailIP, listenIP: req.ListenIP, listenPort: req.ListenPort,
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

func (e *windowsSubnetEngine) compatible(req startSubnetRouterInput, tailIP netip.Addr) error {
	privateKey, err := wgKeyBase64ToHex(req.WgPrivateKey)
	if err != nil {
		return fmt.Errorf("invalid wg_private_key: %w", err)
	}
	if privateKey != e.privateKey || req.ListenPort != e.listenPort || req.ListenIP != e.listenIP {
		return fmt.Errorf("subnet router engine parameters conflict with an active session")
	}
	_ = tailIP
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
		ExposedLANCIDRs: req.Routes, SNAT: true, AllowTCP: true, AllowUDP: true, AllowICMPEcho: true,
	}

	windowsSubnetManager.Lock()
	engine := windowsSubnetManager.engine
	if engine == nil {
		engine, err = newWindowsSubnetEngine(compatReq, localTailIP.Unmap())
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
	if err := engine.compatible(compatReq, localTailIP.Unmap()); err != nil {
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
	engine.removeRegisteredAddresses(handleID)
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
	clearAllWintunFirewallRules()
	interfaces, err := net.Interfaces()
	if err != nil {
		return &windowsWgPeerResult{OK: false, Error: "enumerate network adapters: " + err.Error()}
	}
	for _, iface := range interfaces {
		if iface.Name != "p2pRemote" && !strings.HasPrefix(iface.Name, "p2pRemote-") {
			continue
		}
		if err := clearExistingWintunAdapter(iface.Name); err != nil {
			return &windowsWgPeerResult{OK: false, Error: err.Error()}
		}
	}
	return &windowsWgPeerResult{OK: true}
}

func clearExistingWintunAdapter(name string) error {
	adapter, err := wintun.OpenAdapter(name)
	if err != nil {
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			return nil
		}
		return fmt.Errorf("open existing Wintun adapter %q: %w", name, err)
	}
	defer adapter.Close()
	luid := winipcfg.LUID(adapter.LUID())
	if err := clearWintunIPv4Routes(luid); err != nil {
		return fmt.Errorf("clear stale Wintun routes on %q: %w", name, err)
	}
	if err := luid.SetIPAddressesForFamily(windows.AF_INET, nil); err != nil {
		return fmt.Errorf("clear stale Wintun addresses on %q: %w", name, err)
	}
	return nil
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
	result.RxBatches, result.TxBatches = e.bind.batchStats()
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

func (e *windowsSubnetEngine) refreshPlatformState() error {
	if err := e.refreshNetstackAddresses(); err != nil {
		return err
	}
	nativeByLocalIP := make(map[string][]*windowsSubnetPeer)
	// The caller serializes control-plane updates with configMu. Take the
	// manager lock only long enough to snapshot peers; forwarding is then free
	// to resolve packets while Windows applies the small delta below.
	windowsSubnetManager.Lock()
	for _, peer := range e.peers {
		key := peer.localTailIP.String()
		nativeByLocalIP[key] = append(nativeByLocalIP[key], peer)
	}
	windowsSubnetManager.Unlock()
	for key, peers := range nativeByLocalIP {
		if e.tun.nativeDevice(key) == nil {
			tun.WintunTunnelType = "p2pRemote"
			device, err := tun.CreateTUN(wintunAdapterName(peers[0].localTailIP), 1280)
			if err != nil {
				return fmt.Errorf("create Wintun adapter for %s: %w", key, err)
			}
			if err := e.tun.attachNative(key, device); err != nil {
				return err
			}
		}
		if err := e.configureWintun(key, peers); err != nil {
			return err
		}
	}
	for _, key := range e.tun.nativeKeys() {
		if _, ok := nativeByLocalIP[key]; ok {
			continue
		}
		if err := e.clearWintunConfig(key); err != nil {
			return err
		}
		if err := e.tun.detachNative(key); err != nil {
			return err
		}
	}
	return nil
}

func wintunAdapterName(ip netip.Addr) string {
	return "p2pRemote-" + strings.ReplaceAll(ip.String(), ".", "-")
}

func (e *windowsSubnetEngine) clearWintunConfig(key string) error {
	if err := e.reconcileWintunFirewall(key, netip.Addr{}, nil); err != nil {
		return err
	}
	clearLegacyWintunFirewallRule(key)
	if e.tun == nil {
		return nil
	}
	device := e.tun.nativeDevice(key)
	if device == nil {
		return nil
	}
	native, ok := device.(interface{ LUID() uint64 })
	if !ok {
		return fmt.Errorf("Wintun device does not expose LUID")
	}
	luid := winipcfg.LUID(native.LUID())
	if err := clearWintunIPv4Routes(luid); err != nil {
		return fmt.Errorf("clear Wintun routes: %w", err)
	}
	delete(e.nativeRoutes, key)
	if err := luid.SetIPAddressesForFamily(windows.AF_INET, nil); err != nil {
		return fmt.Errorf("clear Wintun addresses: %w", err)
	}
	return nil
}

func (e *windowsSubnetEngine) configureWintun(key string, peers []*windowsSubnetPeer) error {
	device := e.tun.nativeDevice(key)
	native, ok := device.(interface{ LUID() uint64 })
	if !ok {
		return fmt.Errorf("Wintun device does not expose LUID")
	}
	luid := winipcfg.LUID(native.LUID())
	localIP := peers[0].localTailIP
	address := netip.PrefixFrom(localIP, 32)
	if err := ensureWintunIPv4Address(luid, address); err != nil {
		return fmt.Errorf("configure Wintun address: %w", err)
	}
	routePrefixes := wintunRoutePrefixes(peers)
	ipInterface, err := luid.IPInterface(windows.AF_INET)
	if err != nil {
		return fmt.Errorf("query Wintun IPv4 interface: %w", err)
	}
	if ipInterface.NLMTU != windowsWintunMTU {
		ipInterface.NLMTU = windowsWintunMTU
		if err := ipInterface.Set(); err != nil {
			return fmt.Errorf("configure Wintun IPv4 MTU: %w", err)
		}
	}
	if err := e.reconcileWintunRoutes(key, luid, routePrefixes); err != nil {
		return err
	}
	if err := e.reconcileWintunFirewall(key, localIP, peers); err != nil {
		return err
	}
	primeWintunRoutes(localIP, peers)
	return nil
}

func primeWintunRoutes(localIP netip.Addr, peers []*windowsSubnetPeer) {
	local := &net.UDPAddr{IP: net.IP(localIP.AsSlice())}
	for _, peer := range peers {
		if !peer.peerTailIP.IsValid() {
			continue
		}
		remote := &net.UDPAddr{IP: net.IP(peer.peerTailIP.AsSlice()), Port: 9}
		conn, err := net.DialUDP("udp4", local, remote)
		if err != nil {
			continue
		}
		_, _ = conn.Write([]byte{0})
		_ = conn.Close()
	}
}

func wintunFirewallRuleName(localIP string, peerIP netip.Addr) string {
	return "p2pRemote WGVPN Wintun " + localIP + " peer " + peerIP.String()
}

// clearLegacyWintunFirewallRule removes the pre-differential aggregate rule.
// It is only used when an adapter has no remaining peers (or during startup
// cleanup), never while an existing connection is using that adapter.
func clearLegacyWintunFirewallRule(localIP string) {
	if localIP == "" {
		return
	}
	_ = exec.Command(
		"netsh", "advfirewall", "firewall", "delete", "rule",
		"name="+"p2pRemote WGVPN Wintun "+localIP,
	).Run()
}

func clearWintunFirewallRule(localIP string, peerIP netip.Addr) error {
	if localIP == "" || !peerIP.IsValid() {
		return nil
	}
	output, err := exec.Command(
		"netsh", "advfirewall", "firewall", "delete", "rule",
		"name="+wintunFirewallRuleName(localIP, peerIP),
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("clear Wintun firewall rule: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func clearAllWintunFirewallRules() {
	_ = exec.Command(
		"powershell", "-NoProfile", "-NonInteractive", "-Command",
		"Get-NetFirewallRule -DisplayName 'p2pRemote WGVPN Wintun *' -ErrorAction SilentlyContinue | Remove-NetFirewallRule",
	).Run()
}

func (e *windowsSubnetEngine) reconcileWintunFirewall(key string, localIP netip.Addr, peers []*windowsSubnetPeer) error {
	want := make(map[netip.Addr]struct{}, len(peers))
	for _, peer := range peers {
		if peer.peerTailIP.IsValid() {
			want[peer.peerTailIP] = struct{}{}
		}
	}
	if e.nativeFirewallPeers[key] == nil {
		e.nativeFirewallPeers[key] = map[netip.Addr]struct{}{}
	}
	current := e.nativeFirewallPeers[key]
	for peerIP := range want {
		// Always verify Windows state. current is only our ownership ledger for
		// stale-rule removal; it is not evidence that the rule still exists or
		// still has the expected filter.
		if err := ensureWintunFirewallRule(localIP, peerIP); err != nil {
			return err
		}
		current[peerIP] = struct{}{}
	}
	for peerIP := range current {
		if _, wanted := want[peerIP]; wanted {
			continue
		}
		if err := clearWintunFirewallRule(key, peerIP); err != nil {
			return err
		}
		delete(current, peerIP)
	}
	if len(current) == 0 {
		delete(e.nativeFirewallPeers, key)
	}
	return nil
}

func ensureWintunFirewallRule(localIP, peerIP netip.Addr) error {
	if !localIP.IsValid() || !peerIP.IsValid() {
		return fmt.Errorf("configure Wintun firewall: invalid peer virtual IP")
	}
	localText, peerText := localIP.String(), peerIP.String()
	name := wintunFirewallRuleName(localText, peerIP)
	// A rule is scoped to one peer. Treat the Windows firewall as the source of
	// truth rather than trusting our in-process cache: a same-named rule can be
	// stale, externally edited, or have survived a partial prior operation.
	// If no valid rule exists, install the replacement before deleting invalid
	// ones so an established session never sees an allow-rule gap.
	script := fmt.Sprintf(
		"$ErrorActionPreference = 'Stop'; $rules = @(Get-NetFirewallRule -DisplayName '%s' -ErrorAction SilentlyContinue); $valid = @(); $invalid = @(); foreach ($rule in $rules) { $address = @($rule | Get-NetFirewallAddressFilter); $interface = @($rule | Get-NetFirewallInterfaceFilter); $matches = $rule.Direction.ToString() -eq 'Inbound' -and $rule.Action.ToString() -eq 'Allow' -and $address.Count -eq 1 -and $interface.Count -eq 1 -and @($address[0].LocalAddress) -contains '%s' -and @($address[0].RemoteAddress) -contains '%s' -and @($interface[0].InterfaceAlias) -contains '%s'; if ($matches) { $valid += $rule } else { $invalid += $rule } }; if ($valid.Count -eq 0) { $ruleName = 'p2premote-wgvpn-' + [guid]::NewGuid().ToString('N'); New-NetFirewallRule -Name $ruleName -DisplayName '%s' -Direction Inbound -Action Allow -Profile Any -InterfaceAlias '%s' -Protocol Any -LocalAddress '%s' -RemoteAddress '%s' | Out-Null }; if ($invalid.Count -gt 0) { $invalid | Remove-NetFirewallRule }",
		name, localText, peerText, wintunAdapterName(localIP), name, wintunAdapterName(localIP), localText, peerText,
	)
	output, err := exec.Command(
		"powershell", "-NoProfile", "-NonInteractive", "-Command", script,
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("configure Wintun firewall: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func wintunRoutePrefixes(peers []*windowsSubnetPeer) []netip.Prefix {
	routes := make([]netip.Prefix, 0)
	seenRoute := map[netip.Prefix]bool{}
	for _, peer := range peers {
		peerRoute := netip.PrefixFrom(peer.peerTailIP, 32)
		if !seenRoute[peerRoute] {
			seenRoute[peerRoute] = true
			routes = append(routes, peerRoute)
		}
		// Active peers need routes to the remote LAN so packets enter WireGuard
		// and are proxied by the passive peer's gVisor stack. A passive peer's
		// advertised routes describe its own LAN and must remain on the physical
		// interface; adding them to Wintun would route the gateway back into the
		// tunnel and create a loop.
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

func ensureWintunIPv4Address(luid winipcfg.LUID, address netip.Prefix) error {
	_, err := luid.IPAddress(address.Addr())
	if err == nil {
		return nil
	}
	if !errors.Is(err, windows.ERROR_NOT_FOUND) {
		return err
	}
	return luid.AddIPAddress(address)
}

// Full route cleanup is only used after the last peer on an adapter is gone,
// or during process-start stale-state cleanup. It is intentionally not part of
// live multi-peer reconciliation.
func clearWintunIPv4Routes(luid winipcfg.LUID) error {
	return luid.SetRoutesForFamily(windows.AF_INET, nil)
}

func ensureWintunIPv4Route(luid winipcfg.LUID, route netip.Prefix) error {
	const metric = 0
	nextHop := netip.IPv4Unspecified()
	existing, err := luid.Route(route, nextHop)
	if err == nil {
		if existing.Metric == metric {
			return nil
		}
		existing.Metric = metric
		return existing.Set()
	}
	if !errors.Is(err, windows.ERROR_NOT_FOUND) {
		return err
	}
	return luid.AddRoute(route, nextHop, metric)
}

func (e *windowsSubnetEngine) reconcileWintunRoutes(key string, luid winipcfg.LUID, routes []netip.Prefix) error {
	want := make(map[netip.Prefix]struct{}, len(routes))
	for _, route := range routes {
		want[route] = struct{}{}
	}
	if e.nativeRoutes[key] == nil {
		e.nativeRoutes[key] = map[netip.Prefix]struct{}{}
	}
	current := e.nativeRoutes[key]
	for route := range want {
		// Re-read the real route table on every reconcile. current tracks only
		// ownership for stale deletion and must not mask external drift.
		if err := ensureWintunIPv4Route(luid, route); err != nil {
			return fmt.Errorf("configure Wintun route %s: %w", route, err)
		}
		current[route] = struct{}{}
	}
	for route := range current {
		if _, wanted := want[route]; wanted {
			continue
		}
		if err := luid.DeleteRoute(route, netip.IPv4Unspecified()); err != nil && !errors.Is(err, windows.ERROR_NOT_FOUND) {
			return fmt.Errorf("remove stale Wintun route %s: %w", route, err)
		}
		delete(current, route)
	}
	if len(current) == 0 {
		delete(e.nativeRoutes, key)
	}
	return nil
}

func (e *windowsSubnetEngine) removeRegisteredAddresses(_ string) {
	e.registeredMu.Lock()
	defer e.registeredMu.Unlock()
	for ip, registration := range e.registered {
		if registration.persistent || registration.refs > 0 {
			continue
		}
		_ = e.net.stack.RemoveAddress(subnetNetstackNICID, tcpip.AddrFromSlice(ip.AsSlice()))
		delete(e.registered, ip)
	}
}

func stopWindowsSubnetPeer(handleID string) {
	windowsSubnetManager.Lock()
	e := windowsSubnetManager.engine
	if e == nil {
		windowsSubnetManager.Unlock()
		return
	}
	peer := e.peers[handleID]
	if peer == nil {
		windowsSubnetManager.Unlock()
		return
	}
	delete(e.peers, handleID)
	peer.cancel()
	windowsSubnetManager.Unlock()

	// Wait outside windowsSubnetManager: forwarding goroutines release dynamic
	// addresses during defer and must finish before their peer is removed.
	if !waitWindowsSubnetPeer(peer, windowsPeerStopTimeout) {
		return
	}

	windowsSubnetManager.Lock()
	defer windowsSubnetManager.Unlock()
	if windowsSubnetManager.engine != e {
		return
	}
	if e.wg != nil {
		_ = e.wg.IpcSet("public_key=" + peer.publicKey + "\nremove=true\n")
	}
	e.removeRegisteredAddresses(handleID)
	if len(e.peers) == 0 {
		e.close()
		windowsSubnetManager.engine = nil
	} else {
		_ = e.refreshNetstackAddresses()
	}
}

func updateWindowsSubnetStatus(handleID string, out *subnetRouterResult) {
	windowsSubnetManager.Lock()
	defer windowsSubnetManager.Unlock()
	e := windowsSubnetManager.engine
	if e == nil || e.peers[handleID] == nil {
		out.Started = false
		return
	}
	p := e.peers[handleID]
	out.LanMode, out.Started = "userspace_snat", true
	out.TCPSessions, out.UDPSessions = int(p.tcpActive.Load()), int(p.udpActive.Load())
	out.ICMPSuccess, out.ICMPFailed, out.RejectedFlows = p.icmpOK.Load(), p.icmpFailed.Load(), p.rejected.Load()
	if v := p.lastError.Load(); v != nil {
		out.LastError, _ = v.(string)
	}
	out.WGRxPackets, out.WGTxPackets = e.bind.endpointPackets(p.endpoint)
	out.AdvertisedRoutes = append([]string(nil), p.advertised...)
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
	if peer.localTailIP.IsValid() {
		return peer.localTailIP
	}
	return e.tailIP
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

func (e *windowsSubnetEngine) refreshNetstackAddresses() error {
	e.registeredMu.Lock()
	defer e.registeredMu.Unlock()
	// Local virtual IPs are owned by Wintun for both roles. gVisor only keeps
	// dynamically retained LAN destination addresses used by its TCP/UDP/ICMP
	// proxy, so remove any persistent addresses left by the old passive path.
	for ip, registration := range e.registered {
		if !registration.persistent {
			continue
		}
		if err := e.net.stack.RemoveAddress(subnetNetstackNICID, tcpip.AddrFromSlice(ip.AsSlice())); err != nil {
			return fmt.Errorf("remove stale passive local IP %s: %v", ip, err)
		}
		delete(e.registered, ip)
	}
	return nil
}

func (e *windowsSubnetEngine) retainAddress(peer *windowsSubnetPeer, ip netip.Addr) bool {
	_ = peer
	e.registeredMu.Lock()
	defer e.registeredMu.Unlock()
	registration, ok := e.registered[ip]
	if !ok {
		return false
	}
	if registration.persistent {
		return true
	}
	registration.refs++
	e.registered[ip] = registration
	return true
}

func (e *windowsSubnetEngine) releaseAddress(peer *windowsSubnetPeer, ip netip.Addr) {
	_ = peer
	e.registeredMu.Lock()
	defer e.registeredMu.Unlock()
	registration, ok := e.registered[ip]
	if !ok || registration.persistent {
		return
	}
	registration.refs--
	if registration.refs <= 0 && !registration.persistent {
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
	if !e.retainAddress(peer, dst.Unmap()) {
		peer.rejected.Add(1)
		req.Complete(true)
		return
	}
	select {
	case e.tcpSem <- struct{}{}:
	default:
		e.releaseAddress(peer, dst.Unmap())
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
		e.releaseAddress(peer, dst.Unmap())
		peer.lastError.Store(err.Error())
		req.Complete(true)
		return
	}
	var wq waiter.Queue
	ep, terr := req.CreateEndpoint(&wq)
	if terr != nil {
		<-e.tcpSem
		e.releaseAddress(peer, dst.Unmap())
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
			e.releaseAddress(peer, dst.Unmap())
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
	if !e.retainAddress(peer, dst.Unmap()) {
		peer.rejected.Add(1)
		return
	}
	select {
	case e.udpSem <- struct{}{}:
	default:
		e.releaseAddress(peer, dst.Unmap())
		peer.rejected.Add(1)
		return
	}
	var wq waiter.Queue
	ep, terr := req.CreateEndpoint(&wq)
	if terr != nil {
		<-e.udpSem
		e.releaseAddress(peer, dst.Unmap())
		return
	}
	client := newGonetUDPConn(e.net.stack, &wq, ep)
	dstAddr, bindIP := dst.Unmap().String(), net.IPv4zero
	if dst.Unmap() == e.peerLocalTailIP(peer) {
		dstAddr, bindIP = "127.0.0.1", net.IPv4(127, 0, 0, 1)
	}
	backend, err := net.ListenUDP("udp4", &net.UDPAddr{IP: bindIP})
	if err != nil {
		<-e.udpSem
		e.releaseAddress(peer, dst.Unmap())
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
			e.releaseAddress(peer, dst.Unmap())
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
		if err := exec.CommandContext(ctx, "ping", "-n", "1", "-w", "3000", dst.String()).Run(); err != nil {
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
				_ = e.clearWintunConfig(key)
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

var _ conn.Bind = (*loopbackBind)(nil)
var _ tun.Device = (*subnetNetTun)(nil)
