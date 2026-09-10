//go:build linux

// p2premote extension: this entire file tests p2premote's Linux subnet-router integration.
package main

import (
	"fmt"
	"strings"
	"testing"
)

func TestLinuxRouterRefcountsAndRestoresIPForward(t *testing.T) {
	resetLinuxRouterTestState()
	oldCommand, oldOutput := runCommand, runOutput
	defer func() { runCommand, runOutput = oldCommand, oldOutput; resetLinuxRouterTestState() }()
	var commands []string
	runOutput = func(_ string, args ...string) (string, error) {
		if strings.Contains(strings.Join(args, " "), "rp_filter") {
			return "0", nil
		}
		return "0", nil
	}
	runCommand = func(name string, args ...string) error {
		line := name + " " + strings.Join(args, " ")
		commands = append(commands, line)
		if strings.Contains(line, " -C ") {
			return fmt.Errorf("missing")
		}
		return nil
	}
	req := startSubnetRouterInput{SessionID: 1, PeerDeviceID: 2, PeerTailIP: "100.99.71.2", ExposedLANCIDRs: []string{"192.168.10.0/24"}}
	rules1, err := acquireLinuxSubnetRouter(req)
	if err != nil {
		t.Fatal(err)
	}
	rules2, err := acquireLinuxSubnetRouter(req)
	if err != nil {
		t.Fatal(err)
	}
	if linuxRouterState.sessions != 2 {
		t.Fatalf("sessions=%d", linuxRouterState.sessions)
	}
	releaseLinuxSubnetRouter(rules1)
	if containsCommand(commands, "net.ipv4.ip_forward=0") {
		t.Fatal("ip_forward restored while a session remains")
	}
	releaseLinuxSubnetRouter(rules2)
	if !containsCommand(commands, "net.ipv4.ip_forward=0") {
		t.Fatal("ip_forward was not restored")
	}
	if linuxRouterState.sessions != 0 || len(linuxRouterState.rules) != 0 {
		t.Fatalf("state leaked: %+v", linuxRouterState)
	}
}

func TestLinuxRouterRejectsStrictRPFilter(t *testing.T) {
	resetLinuxRouterTestState()
	oldOutput := runOutput
	defer func() { runOutput = oldOutput; resetLinuxRouterTestState() }()
	runOutput = func(_ string, args ...string) (string, error) {
		if strings.Contains(strings.Join(args, " "), "rp_filter") {
			return "1", nil
		}
		return "1", nil
	}
	_, err := acquireLinuxSubnetRouter(startSubnetRouterInput{PeerTailIP: "100.99.71.2", ExposedLANCIDRs: []string{"192.168.10.0/24"}})
	if err == nil || !strings.Contains(err.Error(), "rp_filter") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func resetLinuxRouterTestState() {
	linuxRouterState.Lock()
	defer linuxRouterState.Unlock()
	linuxRouterState.sessions = 0
	linuxRouterState.ipForwardOriginal = ""
	linuxRouterState.ipForwardChanged = false
	linuxRouterState.rules = map[string]int{}
}

func containsCommand(commands []string, part string) bool {
	for _, command := range commands {
		if strings.Contains(command, part) {
			return true
		}
	}
	return false
}
