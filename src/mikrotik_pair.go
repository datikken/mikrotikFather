package main

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

type mikrotikClient struct {
	name string
	lan  string
}

func (a *app) addMikroTikPair() error {
	if err := a.requireInitialized(); err != nil {
		return err
	}

	if err := a.requireRouterOSCompatibleServer(); err != nil {
		return err
	}

	ccdDir := filepath.Join(a.dataDir(), "ccd")
	if !dirExists(ccdDir) {
		return errors.New("client configuration directory is missing")
	}

	clients := []mikrotikClient{
		{name: "mikrotik-a", lan: "192.168.66.0/24"},
		{name: "mikrotik-b", lan: "192.168.55.0/24"},
	}
	networks := make([]*net.IPNet, len(clients))

	for i, client := range clients {
		ccdPath := filepath.Join(ccdDir, client.name)
		profilePath := filepath.Join(a.root, "clients", client.name+".ovpn")
		if fileExists(ccdPath) || fileExists(profilePath) {
			return fmt.Errorf("%s already has a client route or profile; refusing to overwrite", client.name)
		}

		certPath := filepath.Join(a.dataDir(), "pki", "issued", client.name+".crt")
		keyPath := filepath.Join(a.dataDir(), "pki", "private", client.name+".key")
		if fileExists(certPath) != fileExists(keyPath) {
			return fmt.Errorf("%s has an incomplete certificate; inspect the PKI before continuing", client.name)
		}

		network, err := validateLAN(client.lan, ccdDir)
		if err != nil {
			return fmt.Errorf("%s LAN: %w", client.name, err)
		}
		for previous := 0; previous < i; previous++ {
			if networksOverlap(network, networks[previous]) {
				return fmt.Errorf("%s LAN %s overlaps %s LAN %s", client.name, network, clients[previous].name, networks[previous])
			}
		}
		networks[i] = network
	}

	for _, client := range clients {
		if err := a.addClientWithRestart(client.name, client.lan, false); err != nil {
			if running, stateErr := a.containerRunning(); stateErr == nil && running {
				if restartErr := a.compose("restart", serviceName); restartErr != nil {
					return fmt.Errorf("creating %s profile: %w; a previous profile was kept, and restarting the server also failed: %v", client.name, err, restartErr)
				}
			}
			return fmt.Errorf("creating %s profile: %w; any previously created profile and route were kept", client.name, err)
		}
		profile := filepath.Join(a.root, "clients", client.name+".ovpn")
		if err := normalizeRouterOSProfile(profile); err != nil {
			if running, stateErr := a.containerRunning(); stateErr == nil && running {
				if restartErr := a.compose("restart", serviceName); restartErr != nil {
					return fmt.Errorf("%s profile was created but is not RouterOS-compatible: %w; restarting the server also failed: %v", client.name, err, restartErr)
				}
			}
			return fmt.Errorf("%s profile was created but is not RouterOS-compatible: %w; generated files were kept", client.name, err)
		}
	}

	for i, client := range clients {
		remoteNetwork := networks[1-i]
		ccdPath := filepath.Join(ccdDir, client.name)
		ccd, err := os.ReadFile(ccdPath)
		if err != nil {
			return fmt.Errorf("read %s client routes: %w", client.name, err)
		}
		pushRoute := fmt.Sprintf("push \"route %s %s\"", remoteNetwork.IP, net.IP(remoteNetwork.Mask))
		if !hasConfigLine(ccd, pushRoute) {
			ccd = appendConfigLine(ccd, pushRoute)
			if err := atomicWriteFile(ccdPath, ccd, 0600); err != nil {
				return fmt.Errorf("add route to %s LAN for %s: %w", clients[1-i].name, client.name, err)
			}
		}
	}

	running, err := a.containerRunning()
	if err != nil {
		return err
	}
	if running {
		if err := a.compose("restart", serviceName); err != nil {
			return fmt.Errorf("client profiles and routes were created, but OpenVPN restart failed: %w", err)
		}
	}

	fmt.Fprintln(a.out, "\nMikroTik pair is ready:")
	fmt.Fprintln(a.out, "  mikrotik-a -> Radio LAN 192.168.66.0/24")
	fmt.Fprintln(a.out, "  mikrotik-b -> Module LAN 192.168.55.0/24")
	fmt.Fprintln(a.out, "Upload each .ovpn file to its router, then import it using /interface/ovpn-client/import-ovpn-configuration.")
	fmt.Fprintln(a.out, "RouterOS OVPN/UDP requires RouterOS 7.17 or newer. Keep the profiles private.")
	return nil
}

func (a *app) requireRouterOSCompatibleServer() error {
	configPath := filepath.Join(a.dataDir(), "openvpn.conf")
	config, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("read OpenVPN server config: %w", err)
	}

	required := []string{
		"server 10.8.0.0 255.255.255.0",
		"proto udp",
		"cipher AES-256-CBC",
		"auth SHA256",
		"data-ciphers AES-256-CBC",
		"data-ciphers-fallback AES-256-CBC",
		"client-to-client",
		"client-config-dir /etc/openvpn/ccd",
		"tls-auth ",
		"key-direction 0",
	}
	for _, directive := range required {
		if directive == "tls-auth " {
			if !hasDirectivePrefix(config, directive) {
				return fmt.Errorf("OpenVPN server is missing %q; back up and regenerate the existing server configuration before adding MikroTik clients", directive)
			}
			continue
		}
		if !hasConfigLine(config, directive) {
			return fmt.Errorf("OpenVPN server is missing %q; the existing server configuration must be backed up and regenerated before adding MikroTik clients", directive)
		}
	}
	if !hasConfigLine(config, "dev tun") && !hasConfigLine(config, "dev tun0") {
		return errors.New("OpenVPN server must use dev tun; back up and regenerate the existing server configuration before adding MikroTik clients")
	}
	return nil
}

func hasDirectivePrefix(config []byte, prefix string) bool {
	for _, line := range bytes.Split(config, []byte("\n")) {
		if strings.HasPrefix(strings.TrimSpace(string(line)), prefix) {
			return true
		}
	}
	return false
}

func normalizeRouterOSProfile(path string) error {
	profile, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read generated profile: %w", err)
	}
	for _, directive := range []string{
		"client",
		"dev tun",
		"remote-cert-tls server",
		"cipher AES-256-CBC",
		"auth SHA256",
		"key-direction 1",
	} {
		if !hasConfigLine(profile, directive) {
			return fmt.Errorf("generated profile is missing %q", directive)
		}
	}
	for _, block := range []string{"<ca>", "</ca>", "<cert>", "</cert>", "<key>", "</key>", "<tls-auth>", "</tls-auth>"} {
		if !bytes.Contains(profile, []byte(block)) {
			return fmt.Errorf("generated profile is missing inline %s material", block)
		}
	}
	hasUDPRemote := false
	for _, line := range bytes.Split(profile, []byte("\n")) {
		fields := strings.Fields(string(line))
		if len(fields) == 4 && fields[0] == "remote" && fields[3] == "udp" {
			hasUDPRemote = true
			break
		}
	}
	if !hasUDPRemote {
		return errors.New("generated profile does not specify a UDP remote")
	}

	if !hasConfigLine(profile, "proto udp") {
		lines := bytes.Split(profile, []byte("\n"))
		for i, line := range lines {
			if strings.TrimSpace(string(line)) == "client" {
				lines = append(lines[:i+1], append([][]byte{[]byte("proto udp")}, lines[i+1:]...)...)
				profile = bytes.Join(lines, []byte("\n"))
				break
			}
		}
	}
	return atomicWriteFile(path, profile, 0600)
}
