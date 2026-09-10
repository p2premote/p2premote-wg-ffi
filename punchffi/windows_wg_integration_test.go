//go:build windows && !wgonly

// p2premote extension: this entire file contains p2premote's Windows WireGuard integration tests.
package main

import (
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func TestRefreshNetstackAddressesRemovesLegacyPassiveAddress(t *testing.T) {
	tunDevice, network, err := createSubnetNetTUN(nil, windowsWintunMTU)
	if err != nil {
		t.Fatal(err)
	}
	defer tunDevice.Close()

	passiveIP := netip.MustParseAddr("100.99.71.248")
	engine := &windowsSubnetEngine{
		net:        network,
		peers:      map[string]*windowsSubnetPeer{"passive": {handleID: "passive", role: "passive", localTailIP: passiveIP}},
		registered: map[netip.Addr]windowsRegisteredAddress{passiveIP: {persistent: true}},
	}
	if err := addNetstackAddress(network.stack, passiveIP); err != nil {
		t.Fatal(err)
	}
	if err := engine.refreshNetstackAddresses(); err != nil {
		t.Fatal(err)
	}
	if _, ok := engine.registered[passiveIP]; ok {
		t.Fatalf("legacy passive address %s remains registered", passiveIP)
	}
}

func TestWindowsUserspacePassiveEngineLifecycle(t *testing.T) {
	if os.Getenv("P2PREMOTE_WINTUN_DLL") == "" {
		t.Skip("P2PREMOTE_WINTUN_DLL is not set")
	}
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := listener.LocalAddr().(*net.UDPAddr).Port
	listener.Close()

	local := generateWindowsWgKeypair()
	remote := generateWindowsWgKeypair()
	result := startWindowsWgPeer(startWindowsWgPeerInput{
		SessionID: 910001, PeerDeviceID: 910002, Role: "passive",
		WgPrivateKey: local.PrivateKey, PeerPublicKey: remote.PublicKey,
		LocalTailIP: "100.99.71.248", PeerTailIP: "100.99.71.247",
		PeerEndpoint: "127.0.0.1:59998", ListenIP: "127.0.0.1", ListenPort: port,
	})
	if !result.OK {
		t.Fatalf("start passive userspace WG peer: %s", result.Error)
	}
	if status := getWindowsWgPeerStatus(result.HandleID); !status.OK || !status.Started || status.Role != "passive" {
		t.Fatalf("unexpected passive peer status: %+v", status)
	}
	if stopped := stopWindowsWgPeer(result.HandleID); !stopped.OK {
		t.Fatalf("stop passive userspace WG peer: %s", stopped.Error)
	}
}

// This test needs an elevated token and a Wintun DLL. It is skipped in normal
// unit runs and can be enabled on a Windows test host with
// P2PREMOTE_WINTUN_DLL=<absolute path>.
func TestWindowsUserspaceWgEngineLifecycle(t *testing.T) {
	source := os.Getenv("P2PREMOTE_WINTUN_DLL")
	if source == "" {
		t.Skip("P2PREMOTE_WINTUN_DLL is not set")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(filepath.Dir(executable), "wintun.dll")
	data, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, data, 0o600); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(target)

	local := generateWindowsWgKeypair()
	remote := generateWindowsWgKeypair()
	if !local.OK || !remote.OK {
		t.Fatalf("key generation failed: local=%s remote=%s", local.Error, remote.Error)
	}
	result := startWindowsWgPeer(startWindowsWgPeerInput{
		SessionID: 900001, PeerDeviceID: 900002, Role: "active",
		WgPrivateKey: local.PrivateKey, PeerPublicKey: remote.PublicKey,
		LocalTailIP: "100.99.71.250", PeerTailIP: "100.99.71.249",
		PeerEndpoint: "127.0.0.1:59999", ListenIP: "127.0.0.1", ListenPort: 51821,
	})
	if !result.OK {
		t.Fatalf("start userspace WG peer: %s", result.Error)
	}
	if result.HandleID == "" {
		t.Fatal("empty userspace WG peer handle")
	}
	status := getWindowsWgPeerStatus(result.HandleID)
	if !status.OK || !status.Started || status.Role != "active" {
		t.Fatalf("unexpected peer status: %+v", status)
	}
	stopped := stopWindowsWgPeer(result.HandleID)
	if !stopped.OK {
		t.Fatalf("stop userspace WG peer: %s", stopped.Error)
	}
}
