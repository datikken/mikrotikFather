package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	serviceName = "openvpn"
	vpnNetwork  = "10.8.0.0/24"
)

var clientNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$`)

type app struct {
	root string
	in   io.Reader
	out  io.Writer
	err  io.Writer
}

func main() {
	root, err := findProjectRoot()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	a := app{root: root, in: os.Stdin, out: os.Stdout, err: os.Stderr}
	if err := a.run(os.Args[1:]); err != nil {
		fmt.Fprintln(a.err, "Error:", err)
		os.Exit(1)
	}
}

func findProjectRoot() (string, error) {
	candidates := []string{}
	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates, cwd)
	}
	if executable, err := os.Executable(); err == nil {
		dir := filepath.Dir(executable)
		candidates = append(candidates, dir, filepath.Dir(dir))
	}

	seen := make(map[string]bool)
	for _, candidate := range candidates {
		for dir := candidate; ; dir = filepath.Dir(dir) {
			abs, err := filepath.Abs(dir)
			if err == nil && !seen[abs] {
				seen[abs] = true
				if fileExists(filepath.Join(abs, "compose.yaml")) {
					return abs, nil
				}
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
		}
	}
	return "", errors.New("could not find compose.yaml; run the CLI from the project directory")
}

func (a *app) run(args []string) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		a.usage()
		return nil
	}

	switch args[0] {
	case "create":
		if len(args) != 2 {
			return errors.New("usage: openvpnctl create <public-ip-or-dns>")
		}
		if err := a.init(args[1]); err != nil {
			return err
		}
		return a.compose("up", "-d")
	case "init":
		if len(args) != 2 {
			return errors.New("usage: openvpnctl init <public-ip-or-dns>")
		}
		return a.init(args[1])
	case "up":
		if err := a.requireInitialized(); err != nil {
			return err
		}
		return a.compose("up", "-d")
	case "down":
		return a.compose("down")
	case "restart":
		if err := a.requireInitialized(); err != nil {
			return err
		}
		return a.compose("restart", serviceName)
	case "status":
		return a.compose("ps")
	case "logs":
		return a.compose("logs", "-f", "--tail=100", serviceName)
	case "add-client":
		if len(args) != 3 {
			return errors.New("usage: openvpnctl add-client <name> <lan-cidr>")
		}
		return a.addClient(args[1], args[2])
	case "add-mikrotik-pair":
		if len(args) != 1 {
			return errors.New("usage: openvpnctl add-mikrotik-pair")
		}
		return a.addMikroTikPair()
	default:
		a.usage()
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func (a *app) usage() {
	fmt.Fprintln(a.out, `OpenVPN server manager

Usage:
  openvpnctl create <public-ip-or-dns>
  openvpnctl init <public-ip-or-dns>
  openvpnctl up
  openvpnctl down
  openvpnctl restart
  openvpnctl status
  openvpnctl logs
  openvpnctl add-client <name> <lan-cidr>
  openvpnctl add-mikrotik-pair

Examples:
  openvpnctl create vpn.example.com
  openvpnctl init vpn.example.com
  openvpnctl up
  openvpnctl add-client radio 192.168.66.0/24
  openvpnctl add-client module 192.168.55.0/24
  openvpnctl add-mikrotik-pair`)
}

func (a *app) init(endpoint string) error {
	if !validEndpoint(endpoint) {
		return errors.New("use a public IPv4 address or DNS name without a scheme or port")
	}

	configPath := filepath.Join(a.dataDir(), "openvpn.conf")
	if !fileExists(configPath) {
		if err := os.MkdirAll(a.dataDir(), 0700); err != nil {
			return fmt.Errorf("create data directory: %w", err)
		}
		if err := a.compose(
			"run", "--rm", "--no-deps", serviceName,
			"ovpn_genconfig",
			"-u", "udp://"+endpoint+":1194",
			"-c", "-d", "-D",
			"-s", vpnNetwork,
			"-C", "AES-256-CBC",
			"-a", "SHA256",
			"-e", "data-ciphers AES-256-CBC",
			"-e", "data-ciphers-fallback AES-256-CBC",
			"-e", "client-config-dir /etc/openvpn/ccd",
		); err != nil {
			return err
		}
	} else {
		fmt.Fprintln(a.out, "OpenVPN configuration already exists; keeping it.")
	}

	caCert := filepath.Join(a.dataDir(), "pki", "ca.crt")
	caKey := filepath.Join(a.dataDir(), "pki", "private", "ca.key")
	certExists, keyExists := fileExists(caCert), fileExists(caKey)
	if certExists && keyExists {
		fmt.Fprintln(a.out, "PKI already exists; keeping it.")
	} else if certExists || keyExists {
		return errors.New("PKI is incomplete; back up data/ and inspect it before continuing")
	} else if err := a.compose("run", "--rm", "--no-deps", "-it", serviceName, "ovpn_initpki"); err != nil {
		fmt.Fprintf(a.err, "PKI initialization did not finish: %v\n", err)
		fmt.Fprintln(a.err, "If CA creation completed and only certificate signing failed, re-run create and enter the CA passphrase carefully.")
		return err
	}

	if err := a.ensureServerCertificate(); err != nil {
		return err
	}

	fmt.Fprintln(a.out, "\nInitialization complete. Start the server with: openvpnctl up")
	return nil
}

func (a *app) ensureServerCertificate() error {
	configPath := filepath.Join(a.dataDir(), "openvpn.conf")
	config, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("read OpenVPN config: %w", err)
	}

	var serverKeyPath string
	for _, line := range bytes.Split(config, []byte("\n")) {
		fields := strings.Fields(string(line))
		if len(fields) >= 2 && fields[0] == "key" {
			serverKeyPath = fields[1]
			break
		}
	}
	if serverKeyPath == "" {
		return errors.New("OpenVPN config does not specify the server key")
	}
	commonName := strings.TrimSuffix(filepath.Base(serverKeyPath), filepath.Ext(serverKeyPath))
	if !validEndpoint(commonName) {
		return fmt.Errorf("unexpected server certificate name %q in OpenVPN config", commonName)
	}

	certPath := filepath.Join(a.dataDir(), "pki", "issued", commonName+".crt")
	if !fileExists(certPath) {
		requestPath := filepath.Join(a.dataDir(), "pki", "reqs", commonName+".req")
		if fileExists(requestPath) {
			fmt.Fprintf(a.out, "Signing pending server certificate %s; enter the CA passphrase.\n", commonName)
			if err := a.compose("run", "--rm", "--no-deps", "-it", serviceName, "easyrsa", "sign-req", "server", commonName); err != nil {
				fmt.Fprintln(a.err, "Server certificate signing failed. Re-run create and enter the correct CA passphrase.")
				return err
			}
		} else {
			fmt.Fprintf(a.out, "Creating server certificate %s; enter the CA passphrase when prompted.\n", commonName)
			if err := a.compose("run", "--rm", "--no-deps", "-it", serviceName, "easyrsa", "build-server-full", commonName, "nopass"); err != nil {
				fmt.Fprintln(a.err, "Server certificate creation failed. Re-run create and enter the correct CA passphrase.")
				return err
			}
		}
	}
	if !fileExists(certPath) {
		return fmt.Errorf("server certificate was not created at %s", certPath)
	}

	crlPath := filepath.Join(a.dataDir(), "pki", "crl.pem")
	if !fileExists(crlPath) {
		fmt.Fprintln(a.out, "Generating certificate revocation list; enter the CA passphrase when prompted.")
		if err := a.compose("run", "--rm", "--no-deps", "-it", serviceName, "easyrsa", "gen-crl"); err != nil {
			fmt.Fprintln(a.err, "CRL generation failed. Re-run create and enter the correct CA passphrase.")
			return err
		}
	}
	return nil
}

func (a *app) addClient(name, cidr string) error {
	return a.addClientWithRestart(name, cidr, true)
}

func (a *app) addClientWithRestart(name, cidr string, restart bool) error {
	if !clientNamePattern.MatchString(name) {
		return errors.New("client name must be 1-32 letters, digits, underscores, or hyphens")
	}
	if err := a.requireInitialized(); err != nil {
		return err
	}

	ccdDir := filepath.Join(a.dataDir(), "ccd")
	if !dirExists(ccdDir) {
		return errors.New("client configuration directory is missing")
	}
	ccdPath := filepath.Join(ccdDir, name)
	if fileExists(ccdPath) {
		return fmt.Errorf("client %q already has a routed LAN", name)
	}

	network, err := validateLAN(cidr, ccdDir)
	if err != nil {
		return err
	}

	issuedCert := filepath.Join(a.dataDir(), "pki", "issued", name+".crt")
	privateKey := filepath.Join(a.dataDir(), "pki", "private", name+".key")
	certExists, keyExists := fileExists(issuedCert), fileExists(privateKey)
	switch {
	case certExists && keyExists:
		fmt.Fprintf(a.out, "Using the existing certificate for %s.\n", name)
	case certExists || keyExists:
		return fmt.Errorf("client %q has an incomplete certificate; inspect the PKI before continuing", name)
	default:
		if err := a.compose("run", "--rm", "--no-deps", "-it", serviceName, "easyrsa", "build-client-full", name, "nopass"); err != nil {
			return err
		}
	}

	clientDir := filepath.Join(a.root, "clients")
	if err := os.MkdirAll(clientDir, 0700); err != nil {
		return fmt.Errorf("create clients directory: %w", err)
	}
	profilePath := filepath.Join(clientDir, name+".ovpn")
	if fileExists(profilePath) {
		return fmt.Errorf("client profile %q already exists; inspect it before replacing", profilePath)
	}
	tempProfile, err := os.CreateTemp(clientDir, "."+name+"-*.ovpn.tmp")
	if err != nil {
		return fmt.Errorf("create temporary client profile: %w", err)
	}
	tempPath := tempProfile.Name()
	if err := tempProfile.Chmod(0600); err != nil {
		tempProfile.Close()
		os.Remove(tempPath)
		return fmt.Errorf("secure temporary client profile: %w", err)
	}
	if err := tempProfile.Close(); err != nil {
		os.Remove(tempPath)
		return fmt.Errorf("close temporary client profile: %w", err)
	}
	if err := a.composeToFile(tempPath, "run", "--rm", "--no-deps", serviceName, "ovpn_getclient", name); err != nil {
		os.Remove(tempPath)
		return err
	}

	configPath := filepath.Join(a.dataDir(), "openvpn.conf")
	config, err := os.ReadFile(configPath)
	if err != nil {
		os.Remove(tempPath)
		return fmt.Errorf("read OpenVPN config: %w", err)
	}
	route := fmt.Sprintf("route %s %s", network.IP, net.IP(network.Mask).String())
	if !hasConfigLine(config, route) {
		config = appendConfigLine(config, route)
		if err := atomicWriteFile(configPath, config, 0600); err != nil {
			os.Remove(tempPath)
			return fmt.Errorf("add server route: %w", err)
		}
	}

	ccd := fmt.Sprintf("iroute %s %s\n", network.IP, net.IP(network.Mask))
	if err := atomicWriteFile(ccdPath, []byte(ccd), 0600); err != nil {
		os.Remove(tempPath)
		return fmt.Errorf("write client route: %w", err)
	}
	if err := os.Rename(tempPath, profilePath); err != nil {
		os.Remove(tempPath)
		return fmt.Errorf("save client profile: %w", err)
	}

	if restart {
		running, err := a.containerRunning()
		if err != nil {
			return err
		}
		if running {
			if err := a.compose("restart", serviceName); err != nil {
				return err
			}
		}
	}

	fmt.Fprintf(a.out, "Client profile created: %s\n", profilePath)
	fmt.Fprintf(a.out, "Routed LAN: %s\n", network)
	fmt.Fprintln(a.out, "Treat the profile as a private key; transfer it securely and delete temporary copies.")
	return nil
}

func validateLAN(cidr, ccdDir string) (*net.IPNet, error) {
	ip, requested, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid LAN subnet %q: %w", cidr, err)
	}
	ones, bits := requested.Mask.Size()
	if bits != 32 || ones < 8 || ones > 30 {
		return nil, errors.New("LAN must be an IPv4 subnet with a prefix between /8 and /30")
	}
	ip = ip.To4()
	if ip == nil {
		return nil, errors.New("LAN must be an IPv4 subnet")
	}
	requested.IP = ip.Mask(requested.Mask)

	_, vpn, _ := net.ParseCIDR(vpnNetwork)
	if networksOverlap(requested, vpn) {
		return nil, fmt.Errorf("LAN subnet overlaps the VPN network %s", vpn)
	}

	entries, err := os.ReadDir(ccdDir)
	if err != nil {
		return nil, fmt.Errorf("read client routes: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		content, err := os.ReadFile(filepath.Join(ccdDir, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("read route for client %q: %w", entry.Name(), err)
		}
		for _, line := range strings.Split(string(content), "\n") {
			fields := strings.Fields(line)
			if len(fields) != 3 || fields[0] != "iroute" {
				continue
			}
			existingIP := net.ParseIP(fields[1]).To4()
			existingMask := net.ParseIP(fields[2]).To4()
			if existingIP == nil || existingMask == nil {
				return nil, fmt.Errorf("invalid iroute in client config %q", entry.Name())
			}
			existing := &net.IPNet{IP: existingIP.Mask(net.IPMask(existingMask)), Mask: net.IPMask(existingMask)}
			if networksOverlap(requested, existing) {
				return nil, fmt.Errorf("LAN subnet overlaps %s, already assigned to client %q", existing, entry.Name())
			}
		}
	}
	return requested, nil
}

func networksOverlap(a, b *net.IPNet) bool {
	return a.Contains(b.IP) || b.Contains(a.IP)
}

func validEndpoint(endpoint string) bool {
	if ip := net.ParseIP(endpoint); ip != nil {
		return ip.To4() != nil
	}
	if len(endpoint) == 0 || len(endpoint) > 253 {
		return false
	}
	for _, label := range strings.Split(endpoint, ".") {
		if len(label) == 0 || len(label) > 63 ||
			label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' ||
				char >= '0' && char <= '9' || char == '-') {
				return false
			}
		}
	}
	return true
}

func (a *app) requireInitialized() error {
	if !fileExists(filepath.Join(a.dataDir(), "openvpn.conf")) ||
		!fileExists(filepath.Join(a.dataDir(), "pki", "ca.crt")) ||
		!fileExists(filepath.Join(a.dataDir(), "pki", "private", "ca.key")) {
		return errors.New("initialize the server first with: openvpnctl init <public-ip-or-dns>")
	}
	return nil
}

func (a *app) dataDir() string {
	return filepath.Join(a.root, "data")
}

func (a *app) compose(args ...string) error {
	cmdArgs := []string{"compose", "--project-directory", a.composeProjectDir(), "-f", filepath.Join(a.root, "compose.yaml")}
	cmdArgs = append(cmdArgs, args...)
	cmd := exec.Command("docker", cmdArgs...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = a.in, a.out, a.err
	return runCommand(cmd, "Docker Compose")
}

func (a *app) composeToFile(path string, args ...string) error {
	cmdArgs := []string{"compose", "--project-directory", a.composeProjectDir(), "-f", filepath.Join(a.root, "compose.yaml")}
	cmdArgs = append(cmdArgs, args...)
	cmd := exec.Command("docker", cmdArgs...)

	output, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("open client profile for writing: %w", err)
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = a.in, output, a.err
	runErr := cmd.Run()
	closeErr := output.Close()
	if runErr != nil {
		return fmt.Errorf("Docker Compose: %w", runErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close client profile: %w", closeErr)
	}
	return nil
}

func (a *app) containerRunning() (bool, error) {
	output, err := a.composeOutput("ps", "--status", "running", "--services")
	if err != nil {
		return false, err
	}
	for _, service := range strings.Split(output, "\n") {
		if strings.TrimSpace(service) == serviceName {
			return true, nil
		}
	}
	return false, nil
}

func (a *app) composeOutput(args ...string) (string, error) {
	cmdArgs := []string{"compose", "--project-directory", a.composeProjectDir(), "-f", filepath.Join(a.root, "compose.yaml")}
	cmdArgs = append(cmdArgs, args...)
	cmd := exec.Command("docker", cmdArgs...)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = a.err
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("Docker Compose: %w", err)
	}
	return output.String(), nil
}

func (a *app) composeProjectDir() string {
	if hostProjectDir := os.Getenv("OVPN_PROJECT_DIRECTORY"); hostProjectDir != "" {
		return hostProjectDir
	}
	return a.root
}

func runCommand(cmd *exec.Cmd, label string) error {
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}
	return nil
}

func atomicWriteFile(path string, content []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, ".openvpnctl-*.tmp")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(mode); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.Write(content); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(tempPath, path)
}

func appendConfigLine(content []byte, line string) []byte {
	if len(content) != 0 && content[len(content)-1] != '\n' {
		content = append(content, '\n')
	}
	content = append(content, '\n')
	content = append(content, line...)
	content = append(content, '\n')
	return content
}

func hasConfigLine(content []byte, line string) bool {
	for _, existing := range bytes.Split(content, []byte("\n")) {
		if strings.TrimSpace(string(existing)) == line {
			return true
		}
	}
	return false
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}
