package main

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

func serviceTestPacket(protocol byte, sport, dport uint16, inbound bool) []byte {
	size := 8
	if protocol == 6 {
		size = 20
	}
	p := make([]byte, 20+size)
	p[0], p[9] = 0x45, protocol
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	p[12], p[15], p[16], p[19] = 100, 1, 100, 2
	if !inbound {
		p[15], p[19] = 2, 1
	}
	binary.BigEndian.PutUint16(p[20:22], sport)
	binary.BigEndian.PutUint16(p[22:24], dport)
	if protocol == 6 {
		p[32], p[33] = 0x50, 0x02
	}
	if protocol == 17 {
		binary.BigEndian.PutUint16(p[24:26], 8)
	}
	if protocol == 1 {
		p[20] = 8
		binary.BigEndian.PutUint16(p[24:26], 123)
	}
	return p
}
func newServiceTestFilter(mode string) *serviceFilter {
	return &serviceFilter{policy: serviceAccessPolicy{Mode: mode, TCP: []servicePortRange{{1000, 2000}}, UDP: []servicePortRange{{53, 53}}}, flows: make(map[serviceTuple]serviceFlow)}
}

func TestServiceCapacityStaysBoundedAndExpiredEntriesAreReclaimed(t *testing.T) {
	f := newServiceTestFilter("deny")
	now := time.Now()
	for port := 0; port < 65536; port++ {
		f.flows[serviceTuple{protocol: 17, sport: uint16(port)}] = serviceFlow{outbound: true, expires: now.Add(time.Second)}
	}
	outgoing := serviceTestPacket(17, 50000, 443, false)
	f.observeOutbound(outgoing)
	if len(f.flows) != 65536 {
		t.Fatalf("flow table grew beyond its capacity: %d", len(f.flows))
	}
	if f.allowInbound(serviceTestPacket(17, 443, 50000, true)) {
		t.Fatal("capacity exhaustion granted an untracked reply exemption")
	}
	f.maintain(now.Add(31 * time.Second))
	if len(f.flows) != 0 {
		t.Fatalf("expired entries retained: %d", len(f.flows))
	}
	f.observeOutbound(outgoing)
	if !f.allowInbound(serviceTestPacket(17, 443, 50000, true)) {
		t.Fatal("new outbound flow could not be tracked after reclamation")
	}
}

func TestServicePeerRemovalReleasesOnlyThatPeersFlows(t *testing.T) {
	f := newServiceTestFilter("deny")
	ip := netip.MustParseAddr("100.0.0.1")
	other := netip.MustParseAddr("100.0.0.3")
	now := time.Now()
	f.remember(serviceTuple{src: ip, protocol: 6}, true, now)
	f.remember(serviceTuple{dst: ip, protocol: 17}, false, now)
	survivor := serviceTuple{src: other, protocol: 6}
	f.remember(survivor, true, now)
	f.forgetPeer(ip)
	if len(f.flows) != 1 {
		t.Fatalf("unexpected remaining flow count: %d", len(f.flows))
	}
	if _, ok := f.flows[survivor]; !ok {
		t.Fatal("another peer's flow was removed")
	}
}
func TestServicePortWhitelist(t *testing.T) {
	f := newServiceTestFilter("allowlist")
	for _, test := range []struct {
		proto byte
		port  uint16
		allow bool
	}{
		{6, 999, false}, {6, 1000, true}, {6, 2000, true}, {6, 2001, false},
		{17, 1000, false}, {17, 53, true}, {17, 54, false},
	} {
		if got := f.allowInbound(serviceTestPacket(test.proto, 50000, test.port, true)); got != test.allow {
			t.Fatalf("protocol %d port %d got %v", test.proto, test.port, got)
		}
	}
	f.policy = serviceAccessPolicy{Mode: "allowlist"}
	if f.allowInbound(serviceTestPacket(6, 50000, 1000, true)) {
		t.Fatal("empty whitelist allowed TCP")
	}
	f.policy.Mode = "all"
	if !f.allowInbound(serviceTestPacket(17, 50000, 999, true)) {
		t.Fatal("all mode denied UDP")
	}
}
func TestServiceShrinkDoesNotGrandfatherInbound(t *testing.T) {
	for _, proto := range []byte{6, 17} {
		f := newServiceTestFilter("all")
		request := serviceTestPacket(proto, 50000, 1000, true)
		if !f.allowInbound(request) {
			t.Fatal("initial access denied")
		}
		reply := serviceTestPacket(proto, 1000, 50000, false)
		if proto == 6 {
			reply[33] = 0x12
		}
		f.observeOutbound(reply)
		f.policy.Mode = "deny"
		if f.allowInbound(request) {
			t.Fatalf("old inbound flow bypassed tightened policy (%d)", proto)
		}
	}
}
func TestServiceLocallyInitiatedReplies(t *testing.T) {
	for _, proto := range []byte{6, 17} {
		f := newServiceTestFilter("deny")
		outgoing := serviceTestPacket(proto, 50000, 443, false)
		f.observeOutbound(outgoing)
		reply := serviceTestPacket(proto, 443, 50000, true)
		if proto == 6 {
			reply[33] = 0x12
		}
		if !f.allowInbound(reply) {
			t.Fatalf("local connection reply denied (%d)", proto)
		}
		if f.allowInbound(serviceTestPacket(proto, 444, 50000, true)) {
			t.Fatal("unrelated tuple allowed")
		}
		if proto == 6 {
			reply[33] = 0x02
			if f.allowInbound(reply) {
				t.Fatal("inbound SYN reused outbound tuple")
			}
		}
	}
}
func TestServicePingAndUnsolicitedReplies(t *testing.T) {
	f := newServiceTestFilter("allowlist")
	ping := serviceTestPacket(1, 0, 0, true)
	if f.allowInbound(ping) {
		t.Fatal("Ping ignored switch")
	}
	f.policy.AllowPing = true
	if !f.allowInbound(ping) {
		t.Fatal("Ping switch did not permit echo")
	}
	f = newServiceTestFilter("deny")
	request := serviceTestPacket(1, 0, 0, false)
	f.observeOutbound(request)
	ping[20] = 0
	if !f.allowInbound(ping) {
		t.Fatal("local Ping reply denied")
	}
	binary.BigEndian.PutUint16(ping[24:26], 124)
	if f.allowInbound(ping) {
		t.Fatal("unsolicited Ping reply allowed")
	}
}
func TestServiceMalformedAndFragmentsFailClosed(t *testing.T) {
	f := newServiceTestFilter("allowlist")
	valid := serviceTestPacket(6, 50000, 1000, true)
	for _, flags := range []uint16{0x2000, 1} {
		p := append([]byte(nil), valid...)
		binary.BigEndian.PutUint16(p[6:8], flags)
		if f.allowInbound(p) {
			t.Fatal("fragment allowed")
		}
	}
	for n := 0; n < len(valid); n++ {
		if f.allowInbound(valid[:n]) {
			t.Fatalf("truncated packet allowed at %d", n)
		}
	}
	malformed := append([]byte(nil), valid...)
	malformed[32] = 0x10
	if f.allowInbound(malformed) {
		t.Fatal("malformed TCP header allowed")
	}
}
func TestServiceIPv6ExtensionAndFragment(t *testing.T) {
	f := newServiceTestFilter("allowlist")
	p := make([]byte, 68)
	p[0], p[6] = 0x60, 60
	binary.BigEndian.PutUint16(p[4:6], 28)
	src, dst := netip.MustParseAddr("fd00::1").As16(), netip.MustParseAddr("fd00::2").As16()
	copy(p[8:24], src[:])
	copy(p[24:40], dst[:])
	p[40] = 6
	binary.BigEndian.PutUint16(p[48:50], 50000)
	binary.BigEndian.PutUint16(p[50:52], 1000)
	p[60], p[61] = 0x50, 0x02
	if !f.allowInbound(p) {
		t.Fatal("valid IPv6 extension denied")
	}
	p[6] = 44
	if f.allowInbound(p) {
		t.Fatal("IPv6 fragment bypassed policy")
	}
}
func TestServiceExpiredFlowAndPolicyValidation(t *testing.T) {
	f := newServiceTestFilter("deny")
	request := serviceTestPacket(17, 50000, 443, false)
	tuple, _, _ := servicePacket(request)
	f.flows[tuple] = serviceFlow{true, time.Now().Add(-time.Second)}
	if f.allowInbound(serviceTestPacket(17, 443, 50000, true)) {
		t.Fatal("expired flow allowed")
	}
	for _, p := range []serviceAccessPolicy{{Mode: "bogus"}, {Mode: "allowlist", TCP: []servicePortRange{{0, 1}}}, {Mode: "allowlist", UDP: []servicePortRange{{2000, 1000}}}} {
		if p.validate() == nil {
			t.Fatal("invalid policy accepted")
		}
	}
}

func TestServiceTCPReplyWindowIs24Hours(t *testing.T) {
	for _, test := range []struct {
		protocol byte
		idle     time.Duration
		allowed  bool
	}{
		{6, 23 * time.Hour, true},
		{6, 25 * time.Hour, false},
		{17, 3 * time.Minute, false},
	} {
		f := newServiceTestFilter("deny")
		request := serviceTestPacket(test.protocol, 50000, 443, false)
		tuple, _, _ := servicePacket(request)
		f.remember(tuple, true, time.Now().Add(-test.idle))
		reply := serviceTestPacket(test.protocol, 443, 50000, true)
		if test.protocol == 6 {
			reply[33] = 0x18
		}
		if got := f.allowInbound(reply); got != test.allowed {
			t.Fatalf("protocol %d idle %s: reply allowed=%v, want %v", test.protocol, test.idle, got, test.allowed)
		}
	}
}

func TestServiceHealthControlAndRelatedICMP(t *testing.T) {
	f := newServiceTestFilter("deny")
	if !f.allowInbound(serviceTestPacket(6, 50000, serviceHealthControlPort, true)) {
		t.Fatal("health control blocked")
	}
	if f.allowInbound(serviceTestPacket(6, 50000, 48082, true)) {
		t.Fatal("legacy optional listener was exempted")
	}
	outgoing := serviceTestPacket(6, 50000, 443, false)
	f.observeOutbound(outgoing)
	errPacket := append(serviceTestPacket(1, 0, 0, true), outgoing[:28]...)
	binary.BigEndian.PutUint16(errPacket[2:4], uint16(len(errPacket)))
	errPacket[20], errPacket[21] = 3, 4 // fragmentation needed / PMTU
	if !f.allowInbound(errPacket) {
		t.Fatal("related ICMP PMTU error blocked")
	}
	errPacket[50] = 0
	errPacket[51] = 80 // quoted destination port
	if f.allowInbound(errPacket) {
		t.Fatal("unrelated ICMP error bypassed policy")
	}
	f.forgetPeer(netip.MustParseAddr("100.0.0.1"))
	if len(f.flows) != 0 {
		t.Fatal("peer teardown retained stale flow exemptions")
	}
}
