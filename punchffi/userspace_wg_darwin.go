//go:build darwin

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
	darwinWgMTU           = 1280
	darwinMaxTCPSessions  = 1024
	darwinMaxUDPSessions  = 4096
	darwinMaxICMPSessions = 20
	darwinUDPIdleTimeout  = 2 * time.Minute
	darwinNativeTunKey    = "utun"
)

type darwinWgPeer struct {
	handleID    string
	role        string
	publicKey   string
	endpoint    string
	localTailIP netip.Addr
	peerTailIP  netip.Addr
	routes      []netip.Prefix
	allowed     bool
	ctx         context.Context
	cancel      context.CancelFunc
	tcpActive   atomic.Int32
	udpActive   atomic.Int32
	rejected    atomic.Int64
	icmpOK      atomic.Int64
	icmpFailed  atomic.Int64
	lastError   atomic.Value
	wg          sync.WaitGroup
}

type darwinRegisteredAddress struct {
	refs int
}

type darwinWgEngine struct {
	privateKey    string
	listenPort    int
	interfaceName string
	tun           *hybridTun
	wg            *wgdevice.Device
	bind          *loopbackBind
	net           *subnetNet
	peers         map[string]*darwinWgPeer
	registered    map[netip.Addr]darwinRegisteredAddress
	registeredMu  sync.Mutex
	tcpSem        chan struct{}
	udpSem        chan struct{}
	icmpSem       chan struct{}
}

var darwinWgManager struct {
	sync.Mutex
	engine *darwinWgEngine
}

func platformWgCapabilities() *wgCapabilitiesResult {
	return &wgCapabilitiesResult{
		OK: true, ABIVersion: 2, Platform: "macos", UserspaceWG: true,
		HybridTun: true, NativeTun: true, NetstackProxy: true,
	}
}

func darwinKeyBase64ToHex(value string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil || len(raw) != 32 {
		return "", fmt.Errorf("WireGuard key must be 32-byte base64")
	}
	return hex.EncodeToString(raw), nil
}

func newDarwinWgEngine(req startWindowsWgPeerInput) (*darwinWgEngine, error) {
	privateKey, err := darwinKeyBase64ToHex(req.WgPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("invalid wg_private_key: %w", err)
	}
	tunDev, err := tun.CreateTUN("utun", darwinWgMTU)
	if err != nil {
		return nil, fmt.Errorf("create macOS utun failed: %w", err)
	}
	name, err := tunDev.Name()
	if err != nil {
		_ = tunDev.Close()
		return nil, fmt.Errorf("resolve macOS utun name: %w", err)
	}
	netTun, netstackDev, err := createSubnetNetTUN(nil, darwinWgMTU)
	if err != nil {
		_ = tunDev.Close()
		return nil, fmt.Errorf("create macOS userspace LAN proxy: %w", err)
	}
	hybrid := newHybridTun(netTun.(*subnetNetTun))
	if err := hybrid.attachNative(darwinNativeTunKey, tunDev); err != nil {
		_ = hybrid.Close()
		return nil, fmt.Errorf("attach macOS utun: %w", err)
	}
	bind := newLoopbackBind()
	device := wgdevice.NewDevice(hybrid, bind, &wgdevice.Logger{
		Verbosef: func(string, ...any) {},
		Errorf:   func(string, ...any) {},
	})
	listenPort := req.ListenPort
	if listenPort == 0 {
		listenPort = 51820
	}
	if err := device.IpcSet("private_key=" + privateKey + "\nlisten_port=" + strconv.Itoa(listenPort) + "\n"); err != nil {
		device.Close()
		return nil, fmt.Errorf("configure embedded WireGuard: %w", err)
	}
	if err := device.Up(); err != nil {
		device.Close()
		return nil, fmt.Errorf("bring up embedded WireGuard: %w", err)
	}
	engine := &darwinWgEngine{
		privateKey: privateKey, listenPort: listenPort, interfaceName: name,
		tun: hybrid, wg: device, bind: bind, net: netstackDev,
		peers: map[string]*darwinWgPeer{}, registered: map[netip.Addr]darwinRegisteredAddress{},
		tcpSem: make(chan struct{}, darwinMaxTCPSessions), udpSem: make(chan struct{}, darwinMaxUDPSessions),
		icmpSem: make(chan struct{}, darwinMaxICMPSessions),
	}
	engine.installForwarders()
	engine.tun.packetHandler = engine.handleInboundPacket
	return engine, nil
}

func runDarwinNetworkCommand(name string, args ...string) error {
	output, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s failed: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return nil
}

func (e *darwinWgEngine) configurePeerNetwork(peer *darwinWgPeer, add bool) error {
	if add {
		if err := runDarwinNetworkCommand("/sbin/ifconfig", e.interfaceName, "inet", peer.localTailIP.String(), peer.peerTailIP.String(), "netmask", "255.255.255.255", "alias"); err != nil {
			return err
		}
		prefixes := []netip.Prefix{netip.PrefixFrom(peer.peerTailIP, 32)}
		if peer.role == "active" {
			prefixes = append(prefixes, peer.routes...)
		}
		for _, prefix := range prefixes {
			if err := runDarwinNetworkCommand("/sbin/route", "-n", "add", "-net", prefix.String(), "-interface", e.interfaceName); err != nil && !strings.Contains(err.Error(), "File exists") {
				return err
			}
		}
		return runDarwinNetworkCommand("/sbin/ifconfig", e.interfaceName, "mtu", strconv.Itoa(darwinWgMTU), "up")
	}
	prefixes := []netip.Prefix{netip.PrefixFrom(peer.peerTailIP, 32)}
	if peer.role == "active" {
		prefixes = append(prefixes, peer.routes...)
	}
	for _, prefix := range prefixes {
		_ = runDarwinNetworkCommand("/sbin/route", "-n", "delete", "-net", prefix.String(), "-interface", e.interfaceName)
	}
	_ = runDarwinNetworkCommand("/sbin/ifconfig", e.interfaceName, "inet", peer.localTailIP.String(), "-alias")
	return nil
}

func (e *darwinWgEngine) setPeerAllowed(peer *darwinWgPeer, allowed bool) error {
	var config strings.Builder
	config.WriteString("public_key=" + peer.publicKey + "\nreplace_allowed_ips=true\n")
	if allowed {
		config.WriteString("allowed_ip=" + peer.peerTailIP.String() + "/32\n")
		if peer.role == "active" {
			for _, route := range peer.routes {
				config.WriteString("allowed_ip=" + route.String() + "\n")
			}
		}
	}
	if err := e.wg.IpcSet(config.String()); err != nil {
		return err
	}
	peer.allowed = allowed
	return nil
}

func startWindowsWgPeer(req startWindowsWgPeerInput) *windowsWgPeerResult {
	if req.Role != "active" && req.Role != "passive" {
		return &windowsWgPeerResult{OK: false, Error: "role must be active or passive"}
	}
	localIP, err := netip.ParseAddr(req.LocalTailIP)
	if err != nil || !localIP.Is4() {
		return &windowsWgPeerResult{OK: false, Error: "invalid local_tail_ip"}
	}
	peerIP, err := netip.ParseAddr(req.PeerTailIP)
	if err != nil || !peerIP.Is4() {
		return &windowsWgPeerResult{OK: false, Error: "invalid peer_tail_ip"}
	}
	peerKey, err := darwinKeyBase64ToHex(req.PeerPublicKey)
	if err != nil {
		return &windowsWgPeerResult{OK: false, Error: "invalid peer_public_key: " + err.Error()}
	}
	routes := make([]netip.Prefix, 0, len(req.Routes))
	for _, value := range req.Routes {
		prefix, parseErr := netip.ParsePrefix(value)
		if parseErr != nil || !prefix.Addr().Is4() {
			return &windowsWgPeerResult{OK: false, Error: "invalid IPv4 route: " + value}
		}
		routes = append(routes, prefix.Masked())
	}

	darwinWgManager.Lock()
	defer darwinWgManager.Unlock()
	engine := darwinWgManager.engine
	if engine == nil {
		engine, err = newDarwinWgEngine(req)
		if err != nil {
			return &windowsWgPeerResult{OK: false, Error: err.Error()}
		}
		darwinWgManager.engine = engine
	} else {
		privateKey, keyErr := darwinKeyBase64ToHex(req.WgPrivateKey)
		if keyErr != nil || privateKey != engine.privateKey || (req.ListenPort != 0 && req.ListenPort != engine.listenPort) {
			return &windowsWgPeerResult{OK: false, Error: "userspace WireGuard engine parameters conflict with an active session"}
		}
	}
	for _, existing := range engine.peers {
		if existing.publicKey == peerKey || existing.peerTailIP == peerIP.Unmap() {
			return &windowsWgPeerResult{OK: false, Error: "WireGuard peer conflicts with an active session"}
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	peer := &darwinWgPeer{
		handleID: fmt.Sprintf("wgpeer-%d", time.Now().UnixNano()), role: req.Role,
		publicKey: peerKey, endpoint: strings.TrimSpace(req.PeerEndpoint),
		localTailIP: localIP.Unmap(), peerTailIP: peerIP.Unmap(), routes: routes,
		ctx: ctx, cancel: cancel,
	}
	config := "public_key=" + peer.publicKey + "\nprotocol_version=1\n"
	if peer.endpoint != "" {
		config += "endpoint=" + peer.endpoint + "\n"
	}
	config += "persistent_keepalive_interval=25\n"
	if err := engine.wg.IpcSet(config); err != nil {
		cancel()
		return &windowsWgPeerResult{OK: false, Error: "add embedded WireGuard peer: " + err.Error()}
	}
	if err := engine.setPeerAllowed(peer, true); err != nil {
		cancel()
		_ = engine.wg.IpcSet("public_key=" + peer.publicKey + "\nremove=true\n")
		return &windowsWgPeerResult{OK: false, Error: "configure AllowedIPs: " + err.Error()}
	}
	if err := engine.configurePeerNetwork(peer, true); err != nil {
		cancel()
		_ = engine.wg.IpcSet("public_key=" + peer.publicKey + "\nremove=true\n")
		return &windowsWgPeerResult{OK: false, Error: err.Error()}
	}
	engine.peers[peer.handleID] = peer
	return engine.peerResult(peer)
}

func stopWindowsWgPeer(handleID string) *windowsWgPeerResult {
	darwinWgManager.Lock()
	defer darwinWgManager.Unlock()
	engine := darwinWgManager.engine
	if engine == nil {
		return &windowsWgPeerResult{OK: true}
	}
	peer := engine.peers[handleID]
	if peer == nil {
		return &windowsWgPeerResult{OK: true}
	}
	peer.cancel()
	peer.wg.Wait()
	_ = engine.configurePeerNetwork(peer, false)
	_ = engine.wg.IpcSet("public_key=" + peer.publicKey + "\nremove=true\n")
	delete(engine.peers, handleID)
	if len(engine.peers) == 0 {
		engine.wg.Close()
		darwinWgManager.engine = nil
	}
	return &windowsWgPeerResult{OK: true}
}

func setWindowsWgPeerAllowed(handleID string, allowed bool) *windowsWgPeerResult {
	darwinWgManager.Lock()
	defer darwinWgManager.Unlock()
	engine := darwinWgManager.engine
	if engine == nil || engine.peers[handleID] == nil {
		return &windowsWgPeerResult{OK: false, Error: "userspace WireGuard peer not found"}
	}
	peer := engine.peers[handleID]
	if err := engine.setPeerAllowed(peer, allowed); err != nil {
		return &windowsWgPeerResult{OK: false, Error: err.Error()}
	}
	return engine.peerResult(peer)
}

func getWindowsWgPeerStatus(handleID string) *windowsWgPeerResult {
	darwinWgManager.Lock()
	defer darwinWgManager.Unlock()
	if darwinWgManager.engine == nil || darwinWgManager.engine.peers[handleID] == nil {
		return &windowsWgPeerResult{OK: false, Error: "userspace WireGuard peer not found"}
	}
	return darwinWgManager.engine.peerResult(darwinWgManager.engine.peers[handleID])
}

func stopWindowsWgEngine() *windowsWgPeerResult {
	darwinWgManager.Lock()
	defer darwinWgManager.Unlock()
	engine := darwinWgManager.engine
	if engine == nil {
		return &windowsWgPeerResult{OK: true}
	}
	for _, peer := range engine.peers {
		peer.cancel()
		peer.wg.Wait()
		_ = engine.configurePeerNetwork(peer, false)
	}
	engine.wg.Close()
	darwinWgManager.engine = nil
	return &windowsWgPeerResult{OK: true}
}

func cleanupWindowsWgPlatform() *windowsWgPeerResult { return stopWindowsWgEngine() }

func generateWindowsWgKeypair() *wgKeypairResult {
	var private [32]byte
	if _, err := rand.Read(private[:]); err != nil {
		return &wgKeypairResult{OK: false, Error: err.Error()}
	}
	private[0] &= 248
	private[31] = (private[31] & 127) | 64
	var public [32]byte
	curve25519.ScalarBaseMult(&public, &private)
	return &wgKeypairResult{OK: true, PrivateKey: base64.StdEncoding.EncodeToString(private[:]), PublicKey: base64.StdEncoding.EncodeToString(public[:])}
}

func (e *darwinWgEngine) resolvePeer(src, dst netip.Addr) *darwinWgPeer {
	darwinWgManager.Lock()
	defer darwinWgManager.Unlock()
	for _, peer := range e.peers {
		if !peer.allowed {
			continue
		}
		if peer.role == "active" {
			if dst == peer.localTailIP && (src == peer.peerTailIP || darwinPrefixContains(peer.routes, src)) {
				return peer
			}
			continue
		}
		if src == peer.peerTailIP && (dst == peer.localTailIP || darwinPrefixContains(peer.routes, dst)) {
			return peer
		}
	}
	return nil
}

func darwinPrefixContains(prefixes []netip.Prefix, address netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func (e *darwinWgEngine) ensureAddress(ip netip.Addr) error {
	e.registeredMu.Lock()
	defer e.registeredMu.Unlock()
	if _, ok := e.registered[ip]; ok {
		return nil
	}
	if terr := e.net.stack.AddProtocolAddress(subnetNetstackNICID, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFromSlice(ip.AsSlice()).WithPrefix(),
	}, stack.AddressProperties{}); terr != nil {
		return fmt.Errorf("add macOS LAN proxy address %s: %v", ip, terr)
	}
	e.registered[ip] = darwinRegisteredAddress{}
	return nil
}

func (e *darwinWgEngine) retainAddress(ip netip.Addr) bool {
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

func (e *darwinWgEngine) releaseAddress(ip netip.Addr) {
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

func (e *darwinWgEngine) handleInboundPacket(raw []byte, offset int) hybridPacketDisposition {
	packet := raw[offset:]
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return hybridPacketConsumed
	}
	headerLength := int(packet[0]&0x0f) * 4
	if headerLength < 20 || len(packet) < headerLength {
		return hybridPacketConsumed
	}
	src := netip.AddrFrom4([4]byte{packet[12], packet[13], packet[14], packet[15]})
	dst := netip.AddrFrom4([4]byte{packet[16], packet[17], packet[18], packet[19]})
	peer := e.resolvePeer(src, dst)
	if peer == nil {
		return hybridPacketConsumed
	}
	if dst == peer.localTailIP {
		if err := e.tun.writeNative(darwinNativeTunKey, raw, offset); err != nil {
			peer.lastError.Store(err.Error())
			peer.rejected.Add(1)
		}
		return hybridPacketConsumed
	}
	// LAN forwarding is intentionally userspace-only. TCP and UDP are proxied
	// by gVisor, so no global PF rule or IP forwarding setting is touched.
	if packet[9] == 1 && len(packet) >= headerLength+8 && packet[headerLength] == 8 {
		e.handleICMPEcho(peer, dst, append([]byte(nil), packet...))
		return hybridPacketConsumed
	}
	if packet[9] != 6 && packet[9] != 17 {
		peer.rejected.Add(1)
		return hybridPacketConsumed
	}
	if err := e.ensureAddress(dst); err != nil {
		peer.lastError.Store(err.Error())
		peer.rejected.Add(1)
		return hybridPacketConsumed
	}
	return hybridPacketNetstack
}

func (e *darwinWgEngine) handleICMPEcho(peer *darwinWgPeer, dst netip.Addr, request []byte) {
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
		if err := exec.CommandContext(ctx, "/sbin/ping", "-c", "1", "-W", "3000", dst.String()).Run(); err != nil {
			peer.icmpFailed.Add(1)
			peer.lastError.Store(err.Error())
			return
		}
		reply := makeDarwinICMPEchoReply(request)
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

func makeDarwinICMPEchoReply(packet []byte) []byte {
	if len(packet) < 28 || packet[0]>>4 != 4 {
		return nil
	}
	headerLength := int(packet[0]&0x0f) * 4
	if headerLength < 20 || len(packet) < headerLength+8 {
		return nil
	}
	out := append([]byte(nil), packet...)
	copy(out[12:16], packet[16:20])
	copy(out[16:20], packet[12:16])
	out[headerLength], out[headerLength+1], out[headerLength+2], out[headerLength+3] = 0, 0, 0, 0
	binary.BigEndian.PutUint16(out[headerLength+2:], darwinInternetChecksum(out[headerLength:]))
	out[10], out[11] = 0, 0
	binary.BigEndian.PutUint16(out[10:], darwinInternetChecksum(out[:headerLength]))
	return out
}

func darwinInternetChecksum(data []byte) uint16 {
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

func (e *darwinWgEngine) installForwarders() {
	tcpForwarder := gtcp.NewForwarder(e.net.stack, 0, darwinMaxTCPSessions, e.handleTCP)
	udpForwarder := gudp.NewForwarder(e.net.stack, e.handleUDP)
	e.net.stack.SetTransportProtocolHandler(gtcp.ProtocolNumber, tcpForwarder.HandlePacket)
	e.net.stack.SetTransportProtocolHandler(gudp.ProtocolNumber, udpForwarder.HandlePacket)
}

func (e *darwinWgEngine) handleTCP(req *gtcp.ForwarderRequest) {
	id := req.ID()
	dst, ok1 := netip.AddrFromSlice(id.LocalAddress.AsSlice())
	src, ok2 := netip.AddrFromSlice(id.RemoteAddress.AsSlice())
	if !ok1 || !ok2 {
		req.Complete(true)
		return
	}
	peer := e.resolvePeer(src.Unmap(), dst.Unmap())
	if peer == nil || !e.retainAddress(dst.Unmap()) {
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
	ctx, cancel := context.WithTimeout(peer.ctx, 10*time.Second)
	backend, err := (&net.Dialer{}).DialContext(ctx, "tcp4", net.JoinHostPort(dst.Unmap().String(), strconv.Itoa(int(id.LocalPort))))
	cancel()
	if err != nil {
		<-e.tcpSem
		e.releaseAddress(dst.Unmap())
		peer.lastError.Store(err.Error())
		req.Complete(true)
		return
	}
	var queue waiter.Queue
	endpoint, transportError := req.CreateEndpoint(&queue)
	if transportError != nil {
		<-e.tcpSem
		e.releaseAddress(dst.Unmap())
		_ = backend.Close()
		req.Complete(true)
		return
	}
	req.Complete(false)
	client := gonet.NewTCPConn(&queue, endpoint)
	peer.tcpActive.Add(1)
	peer.wg.Add(1)
	go func() {
		defer func() {
			<-e.tcpSem
			e.releaseAddress(dst.Unmap())
			peer.tcpActive.Add(-1)
			peer.wg.Done()
			_ = backend.Close()
			_ = client.Close()
		}()
		done := make(chan struct{}, 2)
		go func() { _, _ = io.Copy(backend, client); done <- struct{}{} }()
		go func() { _, _ = io.Copy(client, backend); done <- struct{}{} }()
		select {
		case <-done:
		case <-peer.ctx.Done():
		}
		_ = backend.Close()
		_ = client.Close()
	}()
}

func (e *darwinWgEngine) handleUDP(req *gudp.ForwarderRequest) {
	id := req.ID()
	dst, ok1 := netip.AddrFromSlice(id.LocalAddress.AsSlice())
	src, ok2 := netip.AddrFromSlice(id.RemoteAddress.AsSlice())
	if !ok1 || !ok2 {
		return
	}
	peer := e.resolvePeer(src.Unmap(), dst.Unmap())
	if peer == nil || !e.retainAddress(dst.Unmap()) {
		return
	}
	select {
	case e.udpSem <- struct{}{}:
	default:
		e.releaseAddress(dst.Unmap())
		peer.rejected.Add(1)
		return
	}
	var queue waiter.Queue
	endpoint, transportError := req.CreateEndpoint(&queue)
	if transportError != nil {
		<-e.udpSem
		e.releaseAddress(dst.Unmap())
		return
	}
	client := gonet.NewUDPConn(&queue, endpoint)
	backend, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		<-e.udpSem
		e.releaseAddress(dst.Unmap())
		_ = client.Close()
		return
	}
	remote := &net.UDPAddr{IP: net.ParseIP(dst.Unmap().String()), Port: int(id.LocalPort)}
	clientRemote := net.UDPAddrFromAddrPort(netip.AddrPortFrom(src.Unmap(), id.RemotePort))
	ctx, cancel := context.WithCancel(peer.ctx)
	timer := time.AfterFunc(darwinUDPIdleTimeout, cancel)
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
			_ = client.Close()
			_ = backend.Close()
		}()
		go darwinUDPCopyLoop(ctx, cancel, backend, remote, client, func() { timer.Reset(darwinUDPIdleTimeout) })
		darwinUDPCopyLoop(ctx, cancel, client, clientRemote, backend, func() { timer.Reset(darwinUDPIdleTimeout) })
	}()
}

func darwinUDPCopyLoop(ctx context.Context, cancel context.CancelFunc, dst net.PacketConn, fixedDst net.Addr, src net.PacketConn, onPacket func()) {
	buffer := make([]byte, 64*1024)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		_ = src.SetReadDeadline(time.Now().Add(time.Second))
		n, address, err := src.ReadFrom(buffer)
		if err != nil {
			if networkError, ok := err.(net.Error); ok && networkError.Timeout() {
				continue
			}
			cancel()
			return
		}
		target := fixedDst
		if target == nil {
			target = address
		}
		if _, err := dst.WriteTo(buffer[:n], target); err != nil {
			cancel()
			return
		}
		onPacket()
	}
}

func (e *darwinWgEngine) peerResult(peer *darwinWgPeer) *windowsWgPeerResult {
	result := &windowsWgPeerResult{
		OK: true, HandleID: peer.handleID, Started: true, Role: peer.role,
		LocalTailIP: peer.localTailIP.String(), PeerTailIP: peer.peerTailIP.String(),
		TCPSessions: int(peer.tcpActive.Load()), UDPSessions: int(peer.udpActive.Load()),
		ICMPSuccess: peer.icmpOK.Load(), ICMPFailed: peer.icmpFailed.Load(),
		RejectedFlows: peer.rejected.Load(),
	}
	if lastError := peer.lastError.Load(); lastError != nil {
		result.LastError, _ = lastError.(string)
	}
	result.RxPackets, result.TxPackets = e.bind.endpointPackets(peer.endpoint)
	result.RxBatches, result.TxBatches = e.bind.batchStats()
	if state, err := e.wg.IpcGet(); err == nil {
		result.LastHandshakeAt, result.RxBytes, result.TxBytes = parseDarwinWgPeerState(state, peer.publicKey)
	}
	return result
}

func parseDarwinWgPeerState(state, publicKey string) (int64, int64, int64) {
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
		switch key {
		case "last_handshake_time_sec":
			handshake, _ = strconv.ParseInt(value, 10, 64)
		case "rx_bytes":
			rx, _ = strconv.ParseInt(value, 10, 64)
		case "tx_bytes":
			tx, _ = strconv.ParseInt(value, 10, 64)
		}
	}
	return handshake, rx, tx
}
