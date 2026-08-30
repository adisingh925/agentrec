package record

import (
	"regexp"
	"strings"
	"testing"
)

/* old* replicate the pre-optimization IsSecret/IsNoise exactly, to lock behavior parity. */
var oldSecretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`/\.aws/(credentials|config)$`),
	regexp.MustCompile(`/\.ssh/(id_[^/]+|authorized_keys)$`),
	regexp.MustCompile(`/\.kube/config$`),
	regexp.MustCompile(`(^|/)kubeconfig$`),
	regexp.MustCompile(`/\.(npmrc|pypirc|netrc|git-credentials)$`),
	regexp.MustCompile(`(^|/)\.env(\.[^/]+)?$`),
	regexp.MustCompile(`\.(pem|p12|pfx)$`),
	regexp.MustCompile(`(^|/)id_(rsa|dsa|ecdsa|ed25519)$`),
	regexp.MustCompile(`/\.docker/config\.json$`),
	regexp.MustCompile(`/var/run/secrets/`),
	regexp.MustCompile(`(^|/)(service-account|serviceaccount)[^/]*\.json$`),
	regexp.MustCompile(`/\.gnupg/`),
	regexp.MustCompile(`(^|/)(secrets?|credentials)\.(json|ya?ml|toml|ini)$`),
	regexp.MustCompile(`/\.config/gh/hosts\.yml$`),
	regexp.MustCompile(`/\.terraformrc$|\.tfvars$`),
}

func oldIsSecret(p string) bool {
	if p == "" {
		return false
	}
	for _, d := range caCertDirs {
		if strings.HasPrefix(p, d) {
			return false
		}
	}
	for _, re := range oldSecretPatterns {
		if re.MatchString(p) {
			return true
		}
	}
	return false
}

func oldIsNoise(p string) bool {
	if p == "" {
		return true
	}
	if oldIsSecret(p) {
		return false
	}
	for _, pre := range noisePrefixes {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	if noiseSuffixRe.MatchString(p) || noiseFileRe.MatchString(p) {
		return true
	}
	if strings.Contains(p, "/node_modules/.cache/") || strings.Contains(p, "/__pycache__/") {
		return true
	}
	return false
}

func TestClassifyParity(t *testing.T) {
	paths := []string{
		"", "/home/u/.aws/credentials", "/home/u/.aws/config", "/x/.aws/other",
		"/root/.ssh/id_rsa", "/root/.ssh/id_ed25519", "/root/.ssh/authorized_keys", "/root/.ssh/known_hosts",
		"/etc/kubernetes/.kube/config", "/x/kubeconfig", "kubeconfig", "mykubeconfig", "/x/kubeconfigfoo",
		"/a/.npmrc", "/a/.pypirc", "/a/.netrc", "/a/.git-credentials",
		"/proj/.env", "/proj/.env.local", ".env", "/proj/env",
		"/a/foo.pem", "/a/foo.p12", "/a/foo.pfx", "/a/foo.pem2", "/a/pem",
		"/a/id_rsa", "id_ed25519", "/a/id_foo", "/a/notid_rsa",
		"/a/.docker/config.json", "/a/.docker/config.jsonx",
		"/var/run/secrets/token", "/x/var/run/secrets/y",
		"/a/service-account.json", "/a/serviceaccount-x.json", "/a/service-account.txt",
		"/a/.gnupg/key", "/a/gnupg/key",
		"/a/secrets.json", "/a/secret.yaml", "/a/credentials.toml", "/a/secrets.ini", "/a/secrets.txt",
		"/a/.config/gh/hosts.yml", "/a/.config/gh/hosts.yaml",
		"/a/.terraformrc", "/a/foo.tfvars", "/a/.terraformrcx",
		"/etc/ssl/certs/id_rsa", "/etc/ssl/certs/ca.pem", "/usr/share/ca-certificates/x.pem", "/etc/pki/tls/certs/foo.pem",
		"/usr/lib/x.so", "/lib/x.so.1", "/lib/x.so.1.2.3", "/lib/libc.so.6", "/a/foo.pyc", "/a/pyvenv.cfg", "/a/x_pth",
		"/a/dist-packages", "/a/site-packages", "/a/__pycache__/x", "/a/node_modules/.cache/y", "/proc/1/status", "/sys/x",
		"/usr/share/locale/x", "/etc/passwd", "/etc/hosts", "/dev/null", "/home/u/project/main.go", "/tmp/data.txt",
		"/a/b.so.notnum", "/a/somefile", "/a/.sofile", "/a/x.solib", "/a/curlrc", "/a/.curlrc", "/x/pybuilddir.txt",
	}
	for _, p := range paths {
		if oldIsSecret(p) != IsSecret(p) {
			t.Errorf("IsSecret(%q): old=%v new=%v", p, oldIsSecret(p), IsSecret(p))
		}
		if oldIsNoise(p) != IsNoise(p) {
			t.Errorf("IsNoise(%q): old=%v new=%v", p, oldIsNoise(p), IsNoise(p))
		}
	}
}
