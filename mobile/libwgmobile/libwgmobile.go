// p2premote extension: this entire file exposes WireGuard userspace primitives alongside gonc's mobile binding.
// Package libwgmobile wraps the tailscale/wireguard-go userspace WireGuard
// implementation for Android via gomobile.
//
// On Android there is no kernel WireGuard module and no wg.exe CLI. This
// package runs the full WireGuard protocol in-process (userspace) and connects
// it to an Android VpnService TUN file descriptor.
//
// Lifecycle:
//   1. Android side calls VpnService.establish() to get a TUN fd.
//   2. Android calls WgStart(fd, privateKeyHex, listenPort) to start WG.
//   3. Android calls WgAddPeer(...) for each peer.
//   4. Android polls WgPeerLastHandshake(peerPubkeyHex) until > 0 (handshake OK).
//   5. On teardown Android calls WgStop().
//
// The WG peer Endpoint points at "127.0.0.1:<gonc_local_forward_port>", so
// WG-encrypted packets go through gonc's plain outer P2P UDP transport.
// gonc's sockets must be VpnService.protect()-ed (handled by wgvpnmobile).
package libwgmobile

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/crypto/curve25519"
	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/device"
	wgTun "github.com/tailscale/wireguard-go/tun"
)

// ============ android TUN fd wrapper ============

// androidTun wraps an Android VpnService file descriptor as a tun.Device.
// The fd behaves like a TUN device: Read returns IP packets, Write injects them.
type androidTun struct {
	f       *os.File
	mtu     int
	events  chan wgTun.Event
	mu      sync.Mutex
	closed  bool
}

func newAndroidTun(fd int, mtu int) (*androidTun, error) {
	if fd < 0 {
		return nil, errors.New("invalid fd")
	}
	if mtu <= 0 {
		mtu = 1280
	}
	// Wrap the Android VpnService fd directly. Closing this os.File closes the
	// underlying fd; Android's VpnService teardown should happen after WgStop.
	f := os.NewFile(uintptr(fd), "android-tun")
	t := &androidTun{
		f:      f,
		mtu:    mtu,
		events: make(chan wgTun.Event, 8),
	}
	t.events <- wgTun.EventUp
	return t, nil
}

func (t *androidTun) File() *os.File { return t.f }

func (t *androidTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n, err := t.f.Read(bufs[0][offset:])
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	return 1, nil
}

func (t *androidTun) Write(bufs [][]byte, offset int) (int, error) {
	for _, buf := range bufs {
		n, err := t.f.Write(buf[offset:])
		if err != nil {
			return 0, err
		}
		if n != len(buf)-offset {
			return 0, io.ErrShortWrite
		}
	}
	return len(bufs), nil
}

func (t *androidTun) MTU() (int, error)     { return t.mtu, nil }
func (t *androidTun) Name() (string, error) { return "android-tun", nil }
func (t *androidTun) Events() <-chan wgTun.Event { return t.events }

func (t *androidTun) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true
	close(t.events)
	return t.f.Close()
}

func (t *androidTun) BatchSize() int { return 1 }

// ============ WG device singleton ============

var (
	wgMu   sync.Mutex
	wgDev  *device.Device
	wgTunDev *androidTun
)

// WgResult is the common return type.
type WgResult struct {
	OK    bool
	Error string
}

// WgStart creates a WG userspace device bound to an Android TUN fd.
//
// Parameters:
//   - tunFd: the fd from VpnService.establish()
//   - privateKeyHex: WG private key in hex (64 hex chars)
//   - listenPort: WG UDP listen port (51820); WG receives from gonc forwarder
//   - mtu: TUN MTU (recommend 1280)
func WgStart(tunFd int, privateKeyHex string, listenPort, mtu int) *WgResult {
	wgMu.Lock()
	defer wgMu.Unlock()

	if wgDev != nil {
		return &WgResult{Error: "wg device already running; call WgStop first"}
	}

	var sk device.NoisePrivateKey
	if err := sk.FromHex(privateKeyHex); err != nil {
		return &WgResult{Error: "invalid private key hex: " + err.Error()}
	}

	t, err := newAndroidTun(tunFd, mtu)
	if err != nil {
		return &WgResult{Error: "failed to create tun: " + err.Error()}
	}

	logger := device.NewLogger(device.LogLevelVerbose, "libwg")
	dev := device.NewDevice(wgTun.Device(t), conn.NewDefaultBind(), logger)
	if err := dev.SetPrivateKey(sk); err != nil {
		t.Close()
		return &WgResult{Error: "failed to set private key: " + err.Error()}
	}

	// Set the listen port via IPC uapi.
	conf := fmt.Sprintf("listen_port=%d\n", listenPort)
	if err := dev.IpcSet(conf); err != nil {
		dev.Close()
		t.Close()
		return &WgResult{Error: "failed to set listen_port: " + err.Error()}
	}

	if err := dev.Up(); err != nil {
		dev.Close()
		t.Close()
		return &WgResult{Error: "failed to bring up device: " + err.Error()}
	}

	wgDev = dev
	wgTunDev = t
	return &WgResult{OK: true}
}

// WgAddPeer adds or updates a WG peer.
//
// Parameters:
//   - peerPubkeyHex: peer public key in hex
//   - endpoint: peer endpoint, e.g. "127.0.0.1:12345" (gonc local forward port)
//   - allowedIPs: comma-separated CIDRs, e.g. "100.99.71.38/32,192.168.1.0/24"
//   - persistentKeepalive: keepalive interval in seconds (recommend 25, 0 to disable)
func WgAddPeer(peerPubkeyHex, endpoint, allowedIPs string, persistentKeepalive int) *WgResult {
	wgMu.Lock()
	defer wgMu.Unlock()

	if wgDev == nil {
		return &WgResult{Error: "wg device not started"}
	}

	// Validate public key hex.
	var pk device.NoisePublicKey
	if err := pk.FromHex(peerPubkeyHex); err != nil {
		return &WgResult{Error: "invalid peer pubkey hex: " + err.Error()}
	}

	conf := fmt.Sprintf("public_key=%s\n", peerPubkeyHex)
	if endpoint != "" {
		conf += fmt.Sprintf("endpoint=%s\n", endpoint)
	}
	if allowedIPs != "" {
		for _, cidr := range splitComma(allowedIPs) {
			if cidr != "" {
				conf += fmt.Sprintf("allowed_ip=%s\n", cidr)
			}
		}
	}
	if persistentKeepalive > 0 {
		conf += fmt.Sprintf("persistent_keepalive_interval=%d\n", persistentKeepalive)
	}

	if err := wgDev.IpcSet(conf); err != nil {
		return &WgResult{Error: "failed to add peer: " + err.Error()}
	}
	return &WgResult{OK: true}
}

// WgRemovePeer removes a WG peer by public key.
func WgRemovePeer(peerPubkeyHex string) *WgResult {
	wgMu.Lock()
	defer wgMu.Unlock()

	if wgDev == nil {
		return &WgResult{Error: "wg device not started"}
	}

	conf := fmt.Sprintf("public_key=%s\nremove=true\n", peerPubkeyHex)
	if err := wgDev.IpcSet(conf); err != nil {
		return &WgResult{Error: "failed to remove peer: " + err.Error()}
	}
	return &WgResult{OK: true}
}

// WgPeerLastHandshake returns the unix timestamp (seconds) of the last
// successful handshake with the given peer, or 0 if no handshake yet.
func WgPeerLastHandshake(peerPubkeyHex string) int64 {
	wgMu.Lock()
	dev := wgDev
	wgMu.Unlock()

	if dev == nil {
		return 0
	}

	// Parse IpcGet output to find the peer's last_handshake.
	out, err := dev.IpcGet()
	if err != nil {
		return 0
	}
	return parseLastHandshake(out, peerPubkeyHex)
}

// WgTransferStats holds per-peer receive/transmit byte counters read from the
// WireGuard UAPI. RxBytes is bytes received FROM the peer (download),
// TxBytes is bytes sent TO the peer (upload).
//
// Note: wireguard-go resets these counters to 0 on each rekey (key rotation).
// Callers computing cumulative traffic must detect the wrap (current < previous)
// and re-baseline from 0, not treat it as a negative delta.
type WgTransferStats struct {
	OK      bool
	RxBytes int64
	TxBytes int64
	Error   string
}

// WgPeerTransferBytes returns rx/tx byte counters for the given peer.
// Returns OK=false if the WG device is not running or the peer is not found.
func WgPeerTransferBytes(peerPubkeyHex string) *WgTransferStats {
	wgMu.Lock()
	dev := wgDev
	wgMu.Unlock()

	if dev == nil {
		return &WgTransferStats{Error: "wg device not started"}
	}

	out, err := dev.IpcGet()
	if err != nil {
		return &WgTransferStats{Error: err.Error()}
	}
	rx, tx := parseTransferBytes(out, peerPubkeyHex)
	return &WgTransferStats{OK: true, RxBytes: rx, TxBytes: tx}
}

// WgStop tears down the WG device and closes the TUN.
func WgStop() *WgResult {
	wgMu.Lock()
	defer wgMu.Unlock()

	if wgDev == nil {
		return &WgResult{OK: true}
	}
	wgDev.Close()
	wgDev = nil
	if wgTunDev != nil {
		wgTunDev.Close()
		wgTunDev = nil
	}
	return &WgResult{OK: true}
}

// WgIsRunning returns whether the WG device is currently active.
func WgIsRunning() bool {
	wgMu.Lock()
	defer wgMu.Unlock()
	return wgDev != nil
}

// ============ key generation ============

// Keypair holds a generated WireGuard key pair in hex.
type Keypair struct {
	// Private key in lowercase hex (64 chars).
	PrivateKeyHex string
	// Public key in lowercase hex (64 chars).
	PublicKeyHex string
}

// GenerateKeypair generates a new random WireGuard key pair.
func GenerateKeypair() (*Keypair, error) {
	// Generate 32 random bytes, clamp per WireGuard spec, derive public key.
	var sk [32]byte
	if _, err := rand.Read(sk[:]); err != nil {
		return nil, err
	}
	// Clamp: clear low 3 bits of byte 0, clear high bit of byte 31, set bit 6 of byte 31.
	sk[0] &= 248
	sk[31] = (sk[31] & 127) | 64

	var pk [32]byte
	curve25519.ScalarBaseMult(&pk, &sk)

	return &Keypair{
		PrivateKeyHex: hex.EncodeToString(sk[:]),
		PublicKeyHex:  hex.EncodeToString(pk[:]),
	}, nil
}

// ============ helpers ============

func splitComma(s string) []string {
	var parts []string
	start := 0
	for i, c := range s {
		if c == ',' {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	parts = append(parts, s[start:])
	return parts
}

func parseLastHandshake(uapiOut, pubkeyHex string) int64 {
	// UAPI format: lines like "public_key=xxxx" then "last_handshake_time_sec=NNN"
	currentPeer := ""
	found := false
	for _, line := range splitNewline(uapiOut) {
		key, val := parseKV(line)
		switch key {
		case "public_key":
			currentPeer = val
			found = currentPeer == pubkeyHex
		case "last_handshake_time_sec":
			if found {
				var sec int64
				fmt.Sscanf(val, "%d", &sec)
				return sec
			}
		case "errno":
			// peer block ended
			if found {
				return 0
			}
		}
	}
	return 0
}

// parseTransferBytes extracts rx_bytes/tx_bytes for the given peer from UAPI
// output. Mirrors parseLastHandshake but uses strings.EqualFold for the pubkey
// compare (more robust than exact match) and reads two counters.
// Reference: subnet_router_windows.go parseWgPeerState.
func parseTransferBytes(uapiOut, pubkeyHex string) (rx, tx int64) {
	found := false
	for _, line := range splitNewline(uapiOut) {
		key, val := parseKV(line)
		switch key {
		case "public_key":
			found = strings.EqualFold(val, pubkeyHex)
		case "rx_bytes":
			if found {
				rx, _ = strconv.ParseInt(val, 10, 64)
			}
		case "tx_bytes":
			if found {
				tx, _ = strconv.ParseInt(val, 10, 64)
			}
		case "errno":
			if found {
				return
			}
		}
	}
	return
}

func splitNewline(s string) []string {
	var lines []string
	start := 0
	for i, c := range s {
		if c == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

func parseKV(line string) (key, val string) {
	for i, c := range line {
		if c == '=' {
			return line[:i], line[i+1:]
		}
	}
	return line, ""
}
