//go:build windows && wgonly

// p2premote extension: Windows platform layer of the userspace WireGuard
// engine. Owns Wintun adapter creation, winipcfg address/route management and
// the netsh firewall reconciliation; everything else is shared with the macOS
// dylib in subnet_router_windows.go.
package main

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"

	"github.com/tailscale/wireguard-go/tun"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

func platformWgCapabilities() *wgCapabilitiesResult {
	return &wgCapabilitiesResult{
		OK: true, ABIVersion: 2, Platform: "windows", UserspaceWG: true, HybridTun: true, Wintun: true, NativeTun: true, NetstackProxy: true,
	}
}

func wintunAdapterName(ip netip.Addr) string {
	return "p2pRemote-" + strings.ReplaceAll(ip.String(), ".", "-")
}

func createNativeTun(localIP netip.Addr, mtu int) (tun.Device, error) {
	tun.WintunTunnelType = "p2pRemote"
	return tun.CreateTUN(wintunAdapterName(localIP), mtu)
}

func pingArgs(dst string) []string {
	return []string{"-n", "1", "-w", "3000", dst}
}

func cleanupNativePlatform() error {
	clearAllWintunFirewallRules()
	interfaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("enumerate network adapters: %w", err)
	}
	for _, iface := range interfaces {
		if iface.Name != "p2pRemote" && !strings.HasPrefix(iface.Name, "p2pRemote-") {
			continue
		}
		if err := clearExistingWintunAdapter(iface.Name); err != nil {
			return err
		}
	}
	return nil
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

func (e *windowsSubnetEngine) clearNativeTun(key string, device tun.Device) error {
	if err := e.reconcileWintunFirewall(key, netip.Addr{}, nil); err != nil {
		return err
	}
	clearLegacyWintunFirewallRule(key)
	if e.tun == nil || device == nil {
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

func (e *windowsSubnetEngine) configureNativeTun(key string, device tun.Device, localIP netip.Addr, peers []*windowsSubnetPeer) error {
	native, ok := device.(interface{ LUID() uint64 })
	if !ok {
		return fmt.Errorf("Wintun device does not expose LUID")
	}
	luid := winipcfg.LUID(native.LUID())
	address := netip.PrefixFrom(localIP, 32)
	if err := ensureWintunIPv4Address(luid, address); err != nil {
		return fmt.Errorf("configure Wintun address: %w", err)
	}
	routePrefixes := nativeRoutePrefixes(peers)
	ipInterface, err := luid.IPInterface(windows.AF_INET)
	if err != nil {
		return fmt.Errorf("query Wintun IPv4 interface: %w", err)
	}
	if ipInterface.NLMTU != windowsNativeTunMTU {
		ipInterface.NLMTU = windowsNativeTunMTU
		if err := ipInterface.Set(); err != nil {
			return fmt.Errorf("configure Wintun IPv4 MTU: %w", err)
		}
	}
	if err := e.reconcileNativeRoutes(key, routePrefixes,
		func(route netip.Prefix) error { return ensureWintunIPv4Route(luid, route) },
		func(route netip.Prefix) error {
			if err := luid.DeleteRoute(route, netip.IPv4Unspecified()); err != nil && !errors.Is(err, windows.ERROR_NOT_FOUND) {
				return err
			}
			return nil
		},
	); err != nil {
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
	// Windows 7 does not ship the NetSecurity PowerShell module, so
	// Get-NetFirewallRule/Remove-NetFirewallRule fail before the Wintun peer
	// can start. Per-peer rules are removed by reconcileWintunFirewall and by
	// clearWintunFirewallRule; leaving an old, IP-scoped rule is harmless and
	// avoids touching unrelated firewall policy during startup cleanup.
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
	// Use netsh instead of the PowerShell NetSecurity module. netsh is present
	// on Windows 7 and later; scoping the rule to the two virtual addresses
	// keeps it equivalent to the modern interface-filtered rule.
	if _, err := exec.Command(
		"netsh", "advfirewall", "firewall", "show", "rule", "name="+name,
	).CombinedOutput(); err == nil {
		return nil
	}
	output, err := exec.Command(
		"netsh", "advfirewall", "firewall", "add", "rule",
		"name="+name,
		"dir=in",
		"action=allow",
		"profile=any",
		"interfacetype=any",
		"protocol=any",
		"localip="+localText,
		"remoteip="+peerText,
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("configure Wintun firewall: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
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
