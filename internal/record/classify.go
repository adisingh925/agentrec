package record

import (
	"regexp"
	"strings"
)

/* Regex secret patterns as one anchored alternation; literals handled in IsSecret. */
var secretRe = regexp.MustCompile(
	`(?:/\.aws/(credentials|config)$)` +
		`|(?:/\.ssh/(id_[^/]+|authorized_keys)$)` +
		`|(?:/\.(npmrc|pypirc|netrc|git-credentials)$)` +
		`|(?:(^|/)\.env(\.[^/]+)?$)` +
		`|(?:(^|/)id_(rsa|dsa|ecdsa|ed25519)$)` +
		`|(?:(^|/)(service-account|serviceaccount)[^/]*\.json$)` +
		`|(?:(^|/)(secrets?|credentials)\.(json|ya?ml|toml|ini)$)` +
		`|(?:/\.terraformrc$|\.tfvars$)`)

/* Sockets whose mere use is a privilege escalation. */
var privilegedSockets = []string{
	"/var/run/docker.sock", "/run/docker.sock",
	"/var/run/containerd/containerd.sock", "/run/containerd/containerd.sock",
	"/var/run/crio/crio.sock",
}

/* Path prefixes carrying no product signal: loader, libc, locales, kernel pseudo-fs. */
var noisePrefixes = []string{
	"/usr/lib/", "/usr/lib64/", "/lib/", "/lib64/", "/usr/share/locale",
	"/usr/share/zoneinfo", "/etc/ld.so", "/proc/", "/sys/", "/dev/null",
	"/dev/urandom", "/dev/random", "/dev/tty", "/dev/pts", "/usr/share/ca-certificates",
	"/etc/localtime", "/etc/nsswitch.conf", "/etc/host.conf", "/etc/gai.conf",
	"/etc/ssl/certs/", "/usr/lib/ssl/",
	/* Resolver and libc lookups. */
	"/etc/passwd", "/etc/group", "/etc/hosts", "/etc/resolv.conf",
}

/* Runtime search-path probing: high volume, zero signal. */
var noiseFileRe = regexp.MustCompile(
	`(_pth|pyvenv\.cfg|pybuilddir\.txt|\.pyc|/curlrc|/\.curlrc)$|` +
		`/(dist|site)-packages$|/__pycache__/`)

var noiseSuffixRe = regexp.MustCompile(`\.so(\.[0-9.]+)?$`)

/* Public CA trust stores: normal for TLS clients, never flagged (/etc/ssl/private excluded). */
var caCertDirs = []string{
	"/etc/ssl/certs/", "/usr/share/ca-certificates/", "/usr/local/share/ca-certificates/",
	"/etc/pki/tls/certs/", "/etc/pki/ca-trust/", "/usr/lib/ssl/certs/",
}

/* IsSecret reports whether a path looks like it holds a credential. */
func IsSecret(p string) bool {
	if p == "" {
		return false
	}
	for _, d := range caCertDirs {
		if strings.HasPrefix(p, d) {
			return false
		}
	}
	/* Pure-literal patterns. */
	if strings.HasSuffix(p, "/.kube/config") ||
		strings.HasSuffix(p, "/.docker/config.json") ||
		strings.HasSuffix(p, "/.config/gh/hosts.yml") ||
		strings.HasSuffix(p, ".pem") || strings.HasSuffix(p, ".p12") || strings.HasSuffix(p, ".pfx") ||
		p == "kubeconfig" || strings.HasSuffix(p, "/kubeconfig") ||
		strings.Contains(p, "/var/run/secrets/") ||
		strings.Contains(p, "/.gnupg/") {
		return true
	}
	return secretRe.MatchString(p)
}

/* IsPrivilegedSocket reports whether a unix socket path grants control of the host. */
func IsPrivilegedSocket(p string) bool {
	for _, s := range privilegedSockets {
		if p == s {
			return true
		}
	}
	return strings.HasSuffix(p, "docker.sock") || strings.HasSuffix(p, "containerd.sock")
}

/* IsNoise reports whether a file open is linker/runtime chatter, not an agent choice. */
func IsNoise(p string) bool {
	if p == "" {
		return true
	}
	if IsSecret(p) {
		return false
	}
	for _, pre := range noisePrefixes {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	/* Package-manager cache churn; cheap literal scan hoisted ahead of the regexes. */
	if strings.Contains(p, "/node_modules/.cache/") || strings.Contains(p, "/__pycache__/") {
		return true
	}
	/* Skip the regex unless ".so" is present, since it's a necessary condition. */
	if strings.Contains(p, ".so") && noiseSuffixRe.MatchString(p) {
		return true
	}
	if noiseFileRe.MatchString(p) {
		return true
	}
	return false
}

/* Interesting reports whether an event should appear in the default timeline view. */
func Interesting(e Event) bool {
	switch e.Type {
	case "exec", "unlink":
		return true
	case "connect":
		return e.Family != "unix" || IsPrivilegedSocket(e.Dest)
	case "open":
		return !IsNoise(e.Path)
	}
	return false
}
