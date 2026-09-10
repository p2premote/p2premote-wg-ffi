//go:build windows && !wgonly

// p2premote extension: this entire file tests p2premote's Windows WGVPN subnet router.
package main

import (
	"context"
	"encoding/base64"
	"net/netip"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func TestWaitWindowsSubnetPeerCompletes(t *testing.T) {
	peer := &windowsSubnetPeer{}
	if !waitWindowsSubnetPeer(peer, time.Second) {
		t.Fatal("empty peer wait group should complete immediately")
	}
}

func TestWaitWindowsSubnetPeerTimesOut(t *testing.T) {
	peer := &windowsSubnetPeer{}
	peer.wg.Add(1)
	defer peer.wg.Done()
	started := time.Now()
	if waitWindowsSubnetPeer(peer, 20*time.Millisecond) {
		t.Fatal("peer wait unexpectedly completed")
	}
	if elapsed := time.Since(started); elapsed < 20*time.Millisecond || elapsed > time.Second {
		t.Fatalf("unexpected timeout duration: %s", elapsed)
	}
}

func TestValidateWindowsSubnetRequestAcceptsLargePrefix(t *testing.T) {
	_, _, routes, err := validateWindowsSubnetRequest(startSubnetRouterInput{
		TailIP: "100.99.71.1", PeerTailIP: "100.99.71.2", ExposedLANCIDRs: []string{"10.0.0.0/8"},
	})
	if err != nil {
		t.Fatalf("validate failed: %v", err)
	}
	if len(routes) != 1 || routes[0] != mustPrefix(t, "10.0.0.0/8") {
		t.Fatalf("unexpected routes: %v", routes)
	}
}

func TestMakeICMPEchoReply(t *testing.T) {
	p := []byte{0x45, 0, 0, 28, 0, 0, 0, 0, 64, 1, 0, 0, 100, 99, 71, 2, 192, 168, 1, 10, 8, 0, 0, 0, 0x12, 0x34, 0, 1}
	p[10], p[11] = byte(internetChecksum(p[:20])>>8), byte(internetChecksum(p[:20]))
	p[22], p[23] = byte(internetChecksum(p[20:])>>8), byte(internetChecksum(p[20:]))
	r := makeICMPEchoReply(p)
	if r == nil || r[20] != 0 {
		t.Fatalf("invalid reply: %v", r)
	}
	if netip.AddrFrom4([4]byte{r[12], r[13], r[14], r[15]}).String() != "192.168.1.10" {
		t.Fatalf("source not swapped")
	}
	if internetChecksum(r[:20]) != 0 || internetChecksum(r[20:]) != 0 {
		t.Fatalf("invalid checksums")
	}
}

func TestWgKeyBase64ToHex(t *testing.T) {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i)
	}
	key := base64.StdEncoding.EncodeToString(raw)
	got, err := wgKeyBase64ToHex(key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 64 {
		t.Fatalf("unexpected hex: %q", got)
	}
}

func TestWindowsEngineRejectsPeerAndRouteConflicts(t *testing.T) {
	e := &windowsSubnetEngine{peers: map[string]*windowsSubnetPeer{
		"one": {role: "active", publicKey: "key-one", peerTailIP: netip.MustParseAddr("100.99.71.2"), routes: []netip.Prefix{mustPrefix(t, "192.168.10.0/24")}},
	}}
	if err := e.checkPeerConflicts("active", "key-one", netip.MustParseAddr("100.99.71.3"), []netip.Prefix{mustPrefix(t, "10.0.0.0/8")}); err == nil {
		t.Fatal("duplicate key accepted")
	}
	if err := e.checkPeerConflicts("active", "key-two", netip.MustParseAddr("100.99.71.2"), []netip.Prefix{mustPrefix(t, "10.0.0.0/8")}); err == nil {
		t.Fatal("duplicate tail ip accepted")
	}
	if err := e.checkPeerConflicts("active", "key-two", netip.MustParseAddr("100.99.71.3"), []netip.Prefix{mustPrefix(t, "192.168.10.128/25")}); err == nil {
		t.Fatal("overlapping route accepted")
	}
	if err := e.checkPeerConflicts("active", "key-two", netip.MustParseAddr("100.99.71.3"), []netip.Prefix{mustPrefix(t, "10.0.0.0/8")}); err != nil {
		t.Fatalf("disjoint peer rejected: %v", err)
	}
}

func TestWindowsEngineAllowsPassivePeersToShareLANRoute(t *testing.T) {
	e := &windowsSubnetEngine{peers: map[string]*windowsSubnetPeer{
		"one": {role: "passive", publicKey: "key-one", peerTailIP: netip.MustParseAddr("100.99.71.2"), routes: []netip.Prefix{mustPrefix(t, "192.168.10.0/24")}},
	}}
	err := e.checkPeerConflicts(
		"passive", "key-two", netip.MustParseAddr("100.99.71.3"),
		[]netip.Prefix{mustPrefix(t, "192.168.10.0/24")},
	)
	if err != nil {
		t.Fatalf("shared passive LAN route rejected: %v", err)
	}
}

func TestWindowsEngineResolvesSharedPassiveLANByPeerTailIP(t *testing.T) {
	route := mustPrefix(t, "192.168.10.0/24")
	one := &windowsSubnetPeer{role: "passive", peerTailIP: netip.MustParseAddr("100.99.71.2"), localTailIP: netip.MustParseAddr("100.99.71.1"), routes: []netip.Prefix{route}}
	two := &windowsSubnetPeer{role: "passive", peerTailIP: netip.MustParseAddr("100.99.71.3"), localTailIP: netip.MustParseAddr("100.99.71.1"), routes: []netip.Prefix{route}}
	e := &windowsSubnetEngine{peers: map[string]*windowsSubnetPeer{"one": one, "two": two}}
	windowsSubnetManager.Lock()
	windowsSubnetManager.engine = e
	windowsSubnetManager.Unlock()
	defer func() {
		windowsSubnetManager.Lock()
		windowsSubnetManager.engine = nil
		windowsSubnetManager.Unlock()
	}()
	destination := netip.MustParseAddr("192.168.10.20")
	if got := e.resolvePeer(one.peerTailIP, destination); got != one {
		t.Fatal("first passive peer was not resolved by its virtual source IP")
	}
	if got := e.resolvePeer(two.peerTailIP, destination); got != two {
		t.Fatal("second passive peer was not resolved by its virtual source IP")
	}
}

func TestWindowsEngineResolvesTailAndLANOwner(t *testing.T) {
	p := &windowsSubnetPeer{peerTailIP: netip.MustParseAddr("100.99.71.2"), routes: []netip.Prefix{mustPrefix(t, "192.168.10.0/24")}}
	e := &windowsSubnetEngine{tailIP: netip.MustParseAddr("100.99.71.1"), peers: map[string]*windowsSubnetPeer{"one": p}}
	windowsSubnetManager.Lock()
	windowsSubnetManager.engine = e
	windowsSubnetManager.Unlock()
	defer func() { windowsSubnetManager.Lock(); windowsSubnetManager.engine = nil; windowsSubnetManager.Unlock() }()
	if got := e.resolvePeer(p.peerTailIP, e.tailIP); got != p {
		t.Fatal("tail flow owner not resolved")
	}
	if got := e.resolvePeer(p.peerTailIP, netip.MustParseAddr("192.168.10.9")); got != p {
		t.Fatal("LAN flow owner not resolved")
	}
	if got := e.resolvePeer(p.peerTailIP, netip.MustParseAddr("192.168.11.9")); got != nil {
		t.Fatal("unadvertised target accepted")
	}
	if got := e.resolvePeer(netip.MustParseAddr("100.99.71.99"), netip.MustParseAddr("192.168.10.9")); got != nil {
		t.Fatal("route accepted for the wrong peer source")
	}
}

func TestWindowsDynamicAddressReferenceLifecycle(t *testing.T) {
	tunDev, netstackDev, err := createSubnetNetTUN([]netip.Addr{netip.MustParseAddr("100.99.71.1")}, 1420)
	if err != nil {
		t.Fatal(err)
	}
	defer tunDev.Close()
	p := &windowsSubnetPeer{handleID: "one"}
	e := &windowsSubnetEngine{tailIP: netip.MustParseAddr("100.99.71.1"), net: netstackDev, registered: map[netip.Addr]windowsRegisteredAddress{}}
	ip := netip.MustParseAddr("10.20.30.40")
	if err := e.ensureAddress(p, ip); err != nil {
		t.Fatal(err)
	}
	if !e.retainAddress(p, ip) || !e.retainAddress(p, ip) {
		t.Fatal("retain failed")
	}
	e.releaseAddress(p, ip)
	if e.registered[ip].refs != 1 {
		t.Fatalf("unexpected refs: %+v", e.registered[ip])
	}
	e.releaseAddress(p, ip)
	if _, ok := e.registered[ip]; ok {
		t.Fatal("address registration leaked")
	}
}

func TestWindowsDynamicAddressCanBeSharedByMultiplePassivePeers(t *testing.T) {
	tunDev, netstackDev, err := createSubnetNetTUN(nil, windowsWintunMTU)
	if err != nil {
		t.Fatal(err)
	}
	defer tunDev.Close()
	one := &windowsSubnetPeer{handleID: "one", role: "passive"}
	two := &windowsSubnetPeer{handleID: "two", role: "passive"}
	e := &windowsSubnetEngine{net: netstackDev, registered: map[netip.Addr]windowsRegisteredAddress{}}
	ip := netip.MustParseAddr("192.168.10.20")
	if err := e.ensureAddress(one, ip); err != nil {
		t.Fatal(err)
	}
	if !e.retainAddress(one, ip) || !e.retainAddress(two, ip) {
		t.Fatal("shared retain failed")
	}
	e.releaseAddress(one, ip)
	if got := e.registered[ip].refs; got != 1 {
		t.Fatalf("address removed while second peer still used it: refs=%d", got)
	}
	e.releaseAddress(two, ip)
	if _, ok := e.registered[ip]; ok {
		t.Fatal("shared address registration leaked")
	}
}

func TestLoopbackBindCountsPacketsByEndpoint(t *testing.T) {
	b := newLoopbackBind()
	one := netip.MustParseAddrPort("127.0.0.1:10001")
	two := netip.MustParseAddrPort("127.0.0.1:10002")
	b.recordRx(one)
	b.recordRx(two)
	b.recordTx(one, 1)
	rx, tx := b.endpointPackets("127.0.0.1:10001")
	if rx != 1 || tx != 1 {
		t.Fatalf("endpoint one counts = %d/%d", rx, tx)
	}
	rx, tx = b.endpointPackets("127.0.0.1:10002")
	if rx != 1 || tx != 0 {
		t.Fatalf("endpoint two counts = %d/%d", rx, tx)
	}
}

func TestSubnetNetTunEnablesGvisorSoftwareGSO(t *testing.T) {
	tunDev, _, err := createSubnetNetTUN(nil, 1280)
	if err != nil {
		t.Fatal(err)
	}
	defer tunDev.Close()
	dev := tunDev.(*subnetNetTun)
	if got := dev.ep.SupportedGSO(); got != stack.GVisorGSOSupported {
		t.Fatalf("SupportedGSO() = %v, want %v", got, stack.GVisorGSOSupported)
	}
}

func TestWintunRoutesKeepPassiveLANOnPhysicalInterface(t *testing.T) {
	active := &windowsSubnetPeer{
		role: "active", peerTailIP: netip.MustParseAddr("100.99.71.31"),
		routes: []netip.Prefix{mustPrefix(t, "192.168.71.0/24")},
	}
	passive := &windowsSubnetPeer{
		role: "passive", peerTailIP: netip.MustParseAddr("100.99.71.2"),
		routes: []netip.Prefix{mustPrefix(t, "192.168.203.0/24")},
	}
	routes := wintunRoutePrefixes([]*windowsSubnetPeer{active, passive})
	want := map[netip.Prefix]bool{
		netip.PrefixFrom(active.peerTailIP, 32):  true,
		netip.PrefixFrom(passive.peerTailIP, 32): true,
		active.routes[0]:                         true,
	}
	for _, route := range routes {
		if !want[route] {
			t.Fatalf("unexpected Wintun route %s", route)
		}
		delete(want, route)
	}
	if len(want) != 0 {
		t.Fatalf("missing Wintun routes: %v", want)
	}
}

func TestPassiveLocalIPUsesNativeButLANUsesNetstack(t *testing.T) {
	peer := &windowsSubnetPeer{
		role: "passive", localTailIP: netip.MustParseAddr("100.99.71.31"),
		peerTailIP: netip.MustParseAddr("100.99.71.2"),
		routes:     []netip.Prefix{mustPrefix(t, "192.168.203.0/24")},
	}
	engine := &windowsSubnetEngine{}
	if !engine.usesNativeDestination(peer, peer.localTailIP) {
		t.Fatal("passive local virtual IP should use Wintun")
	}
	if engine.usesNativeDestination(peer, netip.MustParseAddr("192.168.203.10")) {
		t.Fatal("passive LAN destination should remain on gVisor")
	}
}

func TestWintunFirewallRuleNameIsScopedPerPeer(t *testing.T) {
	if got := wintunFirewallRuleName("100.99.71.31", netip.MustParseAddr("100.99.71.2")); got != "p2pRemote WGVPN Wintun 100.99.71.31 peer 100.99.71.2" {
		t.Fatalf("unexpected firewall rule name %q", got)
	}
}

func TestStopWindowsSubnetPeerDoesNotWaitWithManagerLockHeld(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	p := &windowsSubnetPeer{handleID: "one", publicKey: "key-one", ctx: ctx, cancel: cancel}
	p.wg.Add(1)
	e := &windowsSubnetEngine{peers: map[string]*windowsSubnetPeer{"one": p}, registered: map[netip.Addr]windowsRegisteredAddress{}}
	windowsSubnetManager.Lock()
	windowsSubnetManager.engine = e
	windowsSubnetManager.Unlock()
	defer func() {
		windowsSubnetManager.Lock()
		windowsSubnetManager.engine = nil
		windowsSubnetManager.Unlock()
	}()
	go func() {
		defer p.wg.Done()
		<-ctx.Done()
		windowsSubnetManager.Lock()
		windowsSubnetManager.Unlock()
	}()
	done := make(chan struct{})
	go func() {
		stopWindowsSubnetPeer("one")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("stopWindowsSubnetPeer waited while holding windowsSubnetManager")
	}
}

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("parse prefix failed: %v", err)
	}
	return p
}
