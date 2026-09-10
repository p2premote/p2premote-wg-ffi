//go:build !wgonly

// p2premote extension: this entire file tests the p2premote desktop C ABI.
package main

import (
	"encoding/json"
	"runtime"
	"strings"
	"testing"

	"github.com/p2premote/p2premote-punch/easyp2p"
)

func TestHandleStartUdpTunnelJSONRejectsInvalidJSON(t *testing.T) {
	raw := handleStartUdpTunnelJSON("{")
	var result easyp2p.UDPTunnelResult
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		t.Fatalf("invalid json response: %v", err)
	}
	if result.OK {
		t.Fatalf("expected failure")
	}
}

func TestHandleStartUdpTunnelJSONRequiresToken(t *testing.T) {
	raw := handleStartUdpTunnelJSON(`{"network":"udp4","timeout_secs":1,"remote_target_port":51820}`)
	var result easyp2p.UDPTunnelResult
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		t.Fatalf("invalid json response: %v", err)
	}
	if result.OK {
		t.Fatalf("expected failure")
	}
	if result.Error == "" {
		t.Fatalf("expected error message")
	}
}

func TestHandleStartUdpTunnelJSONRejectsRelay(t *testing.T) {
	raw := handleStartUdpTunnelJSON(`{"token":"tok","network":"udp4","remote_target_port":51820,"allow_relay":true}`)
	var result easyp2p.UDPTunnelResult
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		t.Fatalf("invalid json response: %v", err)
	}
	if result.OK {
		t.Fatalf("expected failure")
	}
}

func TestHandleStartUdpTunnelJSONRejectsTCPNetwork(t *testing.T) {
	raw := handleStartUdpTunnelJSON(`{"token":"tok","network":"tcp4","remote_target_port":51820}`)
	var result easyp2p.UDPTunnelResult
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		t.Fatalf("invalid json response: %v", err)
	}
	if result.OK {
		t.Fatalf("expected failure")
	}
	if result.Error == "" {
		t.Fatalf("expected error message")
	}
}

func TestHandleStartUdpTunnelJSONRejectsUnknownTraversalMode(t *testing.T) {
	raw := handleStartUdpTunnelJSON(`{"token":"tok","role_hint":"active","traversal_mode":"fastest","network":"udp4","remote_target_port":51820}`)
	var result easyp2p.UDPTunnelResult
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		t.Fatalf("invalid json response: %v", err)
	}
	if result.OK || !strings.Contains(result.Error, "traversal_mode") {
		t.Fatalf("expected traversal mode validation error, got ok=%v error=%q", result.OK, result.Error)
	}
}

func TestHandleStopUdpTunnelJSONIsIdempotent(t *testing.T) {
	raw := handleStopUdpTunnelJSON(`{"handle_id":"missing"}`)
	var result stopTunnelResult
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		t.Fatalf("invalid json response: %v", err)
	}
	if !result.OK {
		t.Fatalf("expected idempotent success, got %q", result.Error)
	}
}

func TestHandleStartSubnetRouterJSONRejectsMissingRoutes(t *testing.T) {
	raw := handleStartSubnetRouterJSON(`{"session_id":59,"peer_device_id":58,"listen_port":51820}`)
	var result subnetRouterResult
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		t.Fatalf("invalid json response: %v", err)
	}
	if result.OK {
		t.Fatalf("expected failure")
	}
	if !strings.Contains(result.Error, "exposed_lan_cidrs") {
		t.Fatalf("unexpected error: %q", result.Error)
	}
}

func TestHandleStartSubnetRouterJSONRejectsPartialProtocolSet(t *testing.T) {
	raw := handleStartSubnetRouterJSON(`{
		"session_id":59,
		"peer_device_id":58,
		"listen_ip":"127.0.0.1",
		"listen_port":51820,
		"exposed_lan_cidrs":["192.168.10.0/24"],
		"snat":true,
		"allow_tcp":true,
		"allow_udp":false,
		"allow_icmp_echo":true
	}`)
	var result subnetRouterResult
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		t.Fatalf("invalid json response: %v", err)
	}
	if result.OK || !strings.Contains(result.Error, "must all be enabled") {
		t.Fatalf("expected protocol validation error, got ok=%v error=%q", result.OK, result.Error)
	}
}

func TestHandleStartSubnetRouterJSONReturnsNotBuilt(t *testing.T) {
	if runtime.GOOS == "linux" {
		prev := runCommand
		prevOutput := runOutput
		runCommand = func(name string, args ...string) error { return nil }
		runOutput = func(name string, args ...string) (string, error) {
			if strings.Contains(strings.Join(args, " "), "rp_filter") {
				return "0", nil
			}
			return "1", nil
		}
		defer func() { runCommand = prev; runOutput = prevOutput }()
	}
	raw := handleStartSubnetRouterJSON(`{
		"session_id":59,
		"peer_device_id":58,
		"wg_private_key":"priv",
		"peer_public_key":"peer",
		"tail_ip":"100.99.71.1",
		"peer_tail_ip":"100.99.71.2",
		"listen_ip":"127.0.0.1",
		"listen_port":51820,
		"exposed_lan_cidrs":["192.168.10.0/24"],
		"snat":true,
		"allow_tcp":true,
		"allow_udp":true,
		"allow_icmp_echo":true
	}`)
	var result subnetRouterResult
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		t.Fatalf("invalid json response: %v", err)
	}
	switch runtime.GOOS {
	case "linux":
		if !result.OK {
			t.Fatalf("expected linux backend success, got %q", result.Error)
		}
	case "windows":
		if strings.Contains(result.Error, "not implemented on windows") {
			t.Fatalf("expected windows backend to be wired, got %q", result.Error)
		}
	default:
		if result.OK {
			t.Fatalf("expected failure on %s", runtime.GOOS)
		}
	}
}

func TestHandleStopSubnetRouterJSONIsIdempotent(t *testing.T) {
	raw := handleStopSubnetRouterJSON(`{"handle_id":"missing"}`)
	var result subnetRouterResult
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		t.Fatalf("invalid json response: %v", err)
	}
	if !result.OK {
		t.Fatalf("expected idempotent success, got %q", result.Error)
	}
}

func TestHandleGetSubnetRouterStatusJSONRequiresHandle(t *testing.T) {
	raw := handleGetSubnetRouterStatusJSON(`{}`)
	var result subnetRouterResult
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		t.Fatalf("invalid json response: %v", err)
	}
	if result.OK {
		t.Fatalf("expected failure")
	}
	if !strings.Contains(result.Error, "handle_id") {
		t.Fatalf("unexpected error: %q", result.Error)
	}
}

func TestBuildIptablesArgs(t *testing.T) {
	rule := iptablesRule{
		table: "nat",
		spec:  []string{"POSTROUTING", "-s", "100.99.71.2/32", "-d", "192.168.10.0/24", "-j", "MASQUERADE"},
	}
	got := buildIptablesArgs("-I", rule)
	want := []string{"-t", "nat", "-I", "POSTROUTING", "-s", "100.99.71.2/32", "-d", "192.168.10.0/24", "-j", "MASQUERADE"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("unexpected args: %v", got)
	}
}
