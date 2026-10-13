//go:build windows

package main

import (
	"fmt"
	"log"

	"golang.org/x/sys/windows"
)

// Query by service name rather than interpreting localized netsh output. Use
// read-only access: checking availability must not require service-admin rights.
func wintunFirewallServiceState() (uint32, error) {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return 0, err
	}
	defer windows.CloseServiceHandle(scm)
	name, err := windows.UTF16PtrFromString("MpsSvc")
	if err != nil {
		return 0, err
	}
	service, err := windows.OpenService(scm, name, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return 0, err
	}
	defer windows.CloseServiceHandle(service)
	var status windows.SERVICE_STATUS
	if err := windows.QueryServiceStatus(service, &status); err != nil {
		return 0, err
	}
	return status.CurrentState, nil
}

func withWintunFirewall(state func() (uint32, error), update func() error) error {
	current, err := state()
	if err != nil {
		return fmt.Errorf("query Windows Firewall service (MpsSvc): %w", err)
	}
	if current == windows.SERVICE_STOPPED {
		// Keep the ownership ledger intact so a later reconciliation can create
		// missing rules and remove stale ones when the service is available again.
		log.Print("Windows Firewall service (MpsSvc) is stopped; skipping Wintun firewall rule synchronization")
		return nil
	}
	return update()
}
