// p2premote extension: this entire file implements p2premote's subnet-router backend around gonc connections.
package main

import (
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

const (
	linuxForwardChain = "P2PREMOTE-FWD"
	linuxNATChain     = "P2PREMOTE-NAT"
)

type subnetRouterHandle struct {
	result   subnetRouterResult
	stopFn   func()
	statusFn func(*subnetRouterResult)
}

type iptablesRule struct {
	table string
	spec  []string
}
type commandRunner func(name string, args ...string) error
type outputRunner func(name string, args ...string) (string, error)

var (
	subnetRoutersMu  sync.Mutex
	subnetRouters                  = map[string]*subnetRouterHandle{}
	runCommand       commandRunner = defaultRunCommand
	runOutput        outputRunner  = defaultRunOutput
	linuxRouterState               = struct {
		sync.Mutex
		sessions          int
		ipForwardOriginal string
		ipForwardChanged  bool
		rules             map[string]int
	}{rules: map[string]int{}}
)

func defaultRunCommand(name string, args ...string) error {
	_, err := defaultRunOutput(name, args...)
	return err
}
func defaultRunOutput(name string, args ...string) (string, error) {
	output, err := exec.Command(name, args...).CombinedOutput()
	text := strings.TrimSpace(string(output))
	if err != nil {
		if text == "" {
			return "", fmt.Errorf("%s %v failed: %w", name, args, err)
		}
		return text, fmt.Errorf("%s %v failed: %w: %s", name, args, err, text)
	}
	return text, nil
}

func startSubnetRouter(req startSubnetRouterInput) *subnetRouterResult {
	return startPlatformSubnetRouter(req)
}

func startLinuxSubnetRouter(req startSubnetRouterInput) *subnetRouterResult {
	if runtime.GOOS != "linux" {
		return &subnetRouterResult{OK: false, Error: fmt.Sprintf("linux subnet router requested on %s", runtime.GOOS)}
	}
	rules, err := acquireLinuxSubnetRouter(req)
	if err != nil {
		return &subnetRouterResult{OK: false, Error: err.Error()}
	}
	handleID := fmt.Sprintf("subnet-%d", time.Now().UnixNano())
	result := subnetRouterResult{OK: true, HandleID: handleID, LanMode: "kernel_snat", ListenIP: req.ListenIP, ListenPort: req.ListenPort, Started: true, AdvertisedRoutes: append([]string(nil), req.ExposedLANCIDRs...)}
	subnetRoutersMu.Lock()
	subnetRouters[handleID] = &subnetRouterHandle{result: result, stopFn: func() { releaseLinuxSubnetRouter(rules) }}
	subnetRoutersMu.Unlock()
	return &result
}

func stopSubnetRouter(handleID string) *subnetRouterResult {
	subnetRoutersMu.Lock()
	handle := subnetRouters[handleID]
	delete(subnetRouters, handleID)
	subnetRoutersMu.Unlock()
	if handle == nil {
		return &subnetRouterResult{OK: true}
	}
	if handle.stopFn != nil {
		handle.stopFn()
	}
	return &subnetRouterResult{OK: true}
}

func getSubnetRouterStatus(handleID string) *subnetRouterResult {
	subnetRoutersMu.Lock()
	handle := subnetRouters[handleID]
	subnetRoutersMu.Unlock()
	if handle == nil {
		return &subnetRouterResult{OK: false, Error: "subnet router handle not found"}
	}
	result := handle.result
	if handle.statusFn != nil {
		handle.statusFn(&result)
	}
	return &result
}

func acquireLinuxSubnetRouter(req startSubnetRouterInput) ([]iptablesRule, error) {
	if net.ParseIP(req.PeerTailIP) == nil {
		return nil, fmt.Errorf("invalid peer_tail_ip: %s", req.PeerTailIP)
	}
	rules, err := linuxSessionRules(req)
	if err != nil {
		return nil, err
	}
	linuxRouterState.Lock()
	defer linuxRouterState.Unlock()
	if linuxRouterState.sessions == 0 {
		if err := prepareLinuxRouter(); err != nil {
			return nil, err
		}
	}
	acquired := make([]iptablesRule, 0, len(rules))
	for _, rule := range rules {
		key := ruleKey(rule)
		if linuxRouterState.rules[key] == 0 {
			if err := ensureIptablesRule(rule); err != nil {
				for i := len(acquired) - 1; i >= 0; i-- {
					releaseLinuxRule(acquired[i])
				}
				if linuxRouterState.sessions == 0 {
					teardownLinuxRouter()
				}
				return nil, err
			}
		}
		linuxRouterState.rules[key]++
		acquired = append(acquired, rule)
	}
	linuxRouterState.sessions++
	return acquired, nil
}

func releaseLinuxSubnetRouter(rules []iptablesRule) {
	linuxRouterState.Lock()
	defer linuxRouterState.Unlock()
	for i := len(rules) - 1; i >= 0; i-- {
		releaseLinuxRule(rules[i])
	}
	if linuxRouterState.sessions > 0 {
		linuxRouterState.sessions--
	}
	if linuxRouterState.sessions == 0 {
		teardownLinuxRouter()
	}
}

func releaseLinuxRule(rule iptablesRule) {
	key := ruleKey(rule)
	count := linuxRouterState.rules[key]
	if count <= 1 {
		if count == 1 {
			_ = deleteIptablesRule(rule)
		}
		delete(linuxRouterState.rules, key)
	} else {
		linuxRouterState.rules[key] = count - 1
	}
}

func prepareLinuxRouter() error {
	for _, key := range []string{"net.ipv4.conf.all.rp_filter", "net.ipv4.conf.default.rp_filter"} {
		rpFilter, err := runOutput("sysctl", "-n", key)
		if err != nil {
			return fmt.Errorf("read %s failed: %w", key, err)
		}
		if strings.TrimSpace(rpFilter) == "1" {
			return fmt.Errorf("%s=1 blocks routed WireGuard traffic; set it to 0 or 2", key)
		}
	}
	ipForward, err := runOutput("sysctl", "-n", "net.ipv4.ip_forward")
	if err != nil {
		return fmt.Errorf("read net.ipv4.ip_forward failed: %w", err)
	}
	linuxRouterState.ipForwardOriginal = strings.TrimSpace(ipForward)
	if linuxRouterState.ipForwardOriginal != "1" {
		if err := runCommand("sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
			return fmt.Errorf("enable ip_forward failed: %w", err)
		}
		linuxRouterState.ipForwardChanged = true
	}
	for _, chain := range []struct{ table, name, parent string }{{"", linuxForwardChain, "FORWARD"}, {"nat", linuxNATChain, "POSTROUTING"}} {
		_ = runCommand("iptables", tableArgs(chain.table, "-N", chain.name)...)
		// jump 规则必须插到内置链首（-I），而非追加（-A）。
		// 若系统 FORWARD 链末尾已有 "-j DROP"（严格防火墙），追加的 jump 永远不命中。
		jump := iptablesRule{table: chain.table, spec: []string{chain.parent, "-m", "comment", "--comment", "p2premote subnet router", "-j", chain.name}}
		if err := insertIptablesRule(jump); err != nil {
			teardownLinuxRouter()
			return err
		}
	}
	return nil
}

func teardownLinuxRouter() {
	for _, jump := range []iptablesRule{
		{spec: []string{"FORWARD", "-m", "comment", "--comment", "p2premote subnet router", "-j", linuxForwardChain}},
		{table: "nat", spec: []string{"POSTROUTING", "-m", "comment", "--comment", "p2premote subnet router", "-j", linuxNATChain}},
	} {
		_ = deleteIptablesRule(jump)
	}
	_ = runCommand("iptables", "-F", linuxForwardChain)
	_ = runCommand("iptables", "-X", linuxForwardChain)
	_ = runCommand("iptables", "-t", "nat", "-F", linuxNATChain)
	_ = runCommand("iptables", "-t", "nat", "-X", linuxNATChain)
	if linuxRouterState.ipForwardChanged {
		_ = runCommand("sysctl", "-w", "net.ipv4.ip_forward="+linuxRouterState.ipForwardOriginal)
	}
	linuxRouterState.ipForwardChanged = false
	linuxRouterState.ipForwardOriginal = ""
}

func linuxSessionRules(req startSubnetRouterInput) ([]iptablesRule, error) {
	peer := req.PeerTailIP + "/32"
	var out []iptablesRule
	for _, cidr := range req.ExposedLANCIDRs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return nil, fmt.Errorf("invalid exposed_lan_cidr %q: %w", cidr, err)
		}
		comment := fmt.Sprintf("p2premote session %d peer %d", req.SessionID, req.PeerDeviceID)
		out = append(out,
			iptablesRule{spec: []string{linuxForwardChain, "-s", peer, "-d", cidr, "-m", "comment", "--comment", comment, "-j", "ACCEPT"}},
			iptablesRule{spec: []string{linuxForwardChain, "-d", peer, "-s", cidr, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-m", "comment", "--comment", comment, "-j", "ACCEPT"}},
			iptablesRule{table: "nat", spec: []string{linuxNATChain, "-s", peer, "-d", cidr, "-m", "comment", "--comment", comment, "-j", "MASQUERADE"}},
		)
	}
	return out, nil
}

func ensureIptablesRule(rule iptablesRule) error {
	if err := runCommand("iptables", buildIptablesArgs("-C", rule)...); err == nil {
		return nil
	}
	if err := runCommand("iptables", buildIptablesArgs("-A", rule)...); err != nil {
		return fmt.Errorf("install iptables rule failed: %w", err)
	}
	return nil
}

// insertIptablesRule 像 ensureIptablesRule，但用 -I（insert at top）而非 -A（append）。
// 用于 jump 规则：必须排在内置链里可能存在的 DROP policy 之前。
func insertIptablesRule(rule iptablesRule) error {
	if err := runCommand("iptables", buildIptablesArgs("-C", rule)...); err == nil {
		return nil
	}
	if err := runCommand("iptables", buildIptablesArgs("-I", rule)...); err != nil {
		return fmt.Errorf("install iptables rule failed: %w", err)
	}
	return nil
}
func deleteIptablesRule(rule iptablesRule) error {
	return runCommand("iptables", buildIptablesArgs("-D", rule)...)
}
func buildIptablesArgs(action string, rule iptablesRule) []string {
	args := []string{}
	if rule.table != "" {
		args = append(args, "-t", rule.table)
	}
	if len(rule.spec) == 0 {
		return args
	}
	args = append(args, action, rule.spec[0])
	return append(args, rule.spec[1:]...)
}
func tableArgs(table string, args ...string) []string {
	if table == "" {
		return args
	}
	return append([]string{"-t", table}, args...)
}
func ruleKey(rule iptablesRule) string { return rule.table + "\x00" + strings.Join(rule.spec, "\x00") }
