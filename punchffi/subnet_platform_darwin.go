//go:build darwin && wgonly

// p2premote extension: macOS platform layer of the userspace WireGuard engine.
// The native TUN is a utun device created through wireguard-go; addresses and
// routes are managed with ifconfig/route (the engine runs inside the root
// LaunchDaemon). utun traffic is not filtered by a host firewall, so there is
// no equivalent of the Windows netsh reconciliation here.
package main

import (
	"fmt"
	"net/netip"
	"os/exec"
	"strings"

	"github.com/tailscale/wireguard-go/tun"
)

func platformWgCapabilities() *wgCapabilitiesResult {
	return &wgCapabilitiesResult{
		OK: true, ABIVersion: 2, Platform: "darwin", UserspaceWG: true, HybridTun: true, Wintun: false, NativeTun: true,
	}
}

// createNativeTun opens a fresh utun device. wireguard-go's darwin backend
// assigns the next free utunN unit when the requested name is exactly "utun";
// the concrete name is read back through device.Name().
func createNativeTun(_ netip.Addr, mtu int) (tun.Device, error) {
	return tun.CreateTUN("utun", mtu)
}

// pingArgs: macOS ping takes the reply timeout in milliseconds.
func pingArgs(dst string) []string {
	return []string{"-c", "1", "-W", "3000", dst}
}

// cleanupNativePlatform: utun interfaces are kernel objects bound to the
// creating process; they disappear when the service exits or closes the fd,
// so there is no stale-adapter cleanup to perform.
func cleanupNativePlatform() error {
	return nil
}

func runRouteCommand(args ...string) error {
	output, err := exec.Command("route", args...).CombinedOutput()
	if err != nil {
		text := strings.TrimSpace(string(output))
		if text == "" {
			return fmt.Errorf("route %v failed: %w", args, err)
		}
		return fmt.Errorf("route %v failed: %w: %s", args, err, text)
	}
	return nil
}

// darwinRouteInterface reports the interface the kernel currently uses to
// reach `route`. `route get` with an explicit prefix does a masked lookup: a
// matching route reports its owning interface, while a missing route either
// falls back to the default route or fails — both surface a foreign (or
// absent) interface, never ours.
func darwinRouteInterface(route netip.Prefix) (string, bool) {
	output, err := exec.Command("route", "-n", "get", "-net", route.String()).CombinedOutput()
	if err != nil {
		return "", false
	}
	for _, line := range strings.Split(string(output), "\n") {
		if value, ok := strings.CutPrefix(strings.TrimSpace(line), "interface:"); ok {
			return strings.TrimSpace(value), true
		}
	}
	return "", false
}

func (e *windowsSubnetEngine) configureNativeTun(key string, device tun.Device, localIP netip.Addr, peers []*windowsSubnetPeer) error {
	if device == nil {
		return fmt.Errorf("native TUN is not attached")
	}
	name, err := device.Name()
	if err != nil {
		return fmt.Errorf("query native TUN name: %w", err)
	}
	// utun is a point-to-point interface; assigning the tail IP as both ends
	// yields the /32 route to self that the engine's packet classifier relies on.
	if output, err := exec.Command(
		"ifconfig", name, "inet", localIP.String(), localIP.String(),
		"mtu", fmt.Sprintf("%d", windowsNativeTunMTU), "up",
	).CombinedOutput(); err != nil {
		return fmt.Errorf("configure %s address: %w: %s", name, err, strings.TrimSpace(string(output)))
	}
	routePrefixes := nativeRoutePrefixes(peers)
	ensure := func(route netip.Prefix) error {
		// Reconciliation re-applies every wanted route on each call; keep the
		// steady state non-destructive so live peers keep forwarding (a
		// delete/add cycle blackholes traffic between the two invocations).
		// Drift — a missing route, or one owned by another interface — still
		// re-applies; route add itself is not idempotent, hence delete first.
		if iface, ok := darwinRouteInterface(route); ok && iface == name {
			return nil
		}
		_ = runRouteCommand("-n", "delete", "-net", route.String(), "-interface", name)
		return runRouteCommand("-n", "add", "-net", route.String(), "-interface", name)
	}
	remove := func(route netip.Prefix) error {
		// The kernel removes interface-scoped routes when the utun device goes
		// away, but live reconciliation must still retract stale entries.
		if err := runRouteCommand("-n", "delete", "-net", route.String(), "-interface", name); err != nil &&
			!strings.Contains(err.Error(), "not in table") {
			return err
		}
		return nil
	}
	return e.reconcileNativeRoutes(key, routePrefixes, ensure, remove)
}

func (e *windowsSubnetEngine) clearNativeTun(key string, device tun.Device) error {
	if device == nil {
		delete(e.nativeRoutes, key)
		return nil
	}
	name, err := device.Name()
	if err != nil {
		return fmt.Errorf("query native TUN name: %w", err)
	}
	for route := range e.nativeRoutes[key] {
		if err := runRouteCommand("-n", "delete", "-net", route.String(), "-interface", name); err != nil &&
			!strings.Contains(err.Error(), "not in table") {
			return err
		}
	}
	delete(e.nativeRoutes, key)
	return nil
}
