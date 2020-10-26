package dockercfg

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// GetRegistryCredentials gets registry credentials for the passed in registry host.
//
// This will use `LoadDefaultConfig` to read registry auth details from the config.
// If the config doesn't exist, it will attempt to load registry credentials using the default credential helper for the platform.
func GetRegistryCredentials(hostname string) (string, string, error) {
	cfg, err := LoadDefaultConfig()
	if err != nil {
		if !os.IsNotExist(err) {
			return "", "", err
		}
		return GetCredentialsFromHelper("", hostname)
	}
	return cfg.GetRegistryCredentials(hostname)
}

// GetRegistryCredentials gets credentials, if any, for the provided hostname
func (c *Config) GetRegistryCredentials(hostname string) (string, string, error) {
	h, ok := c.CredentialHelpers[hostname]
	if ok {
		return GetCredentialsFromHelper(h, hostname)
	}

	if c.CredentialsStore != "" {
		return GetCredentialsFromHelper(c.CredentialsStore, hostname)
	}

	auth, ok := c.AuthConfigs[hostname]
	if !ok {
		return GetCredentialsFromHelper("", hostname)
	}

	return auth.Username, auth.Password, nil
}

// Errors from credential helpers
var (
	ErrCredentialsNotFound         = errors.New("credentials not found in native keychain")
	ErrCredentialsMissingServerURL = errors.New("no credentials server URL")
)

// GetCredentialsFromHelper attempts to lookup credentials from the passed in docker credential helper.
//
// The credential helpoer should just be the suffix name (no "docker-credential-").
// If the passed in helper program is empty this will look up the default helper for the platform.
func GetCredentialsFromHelper(helper, hostname string) (string, string, error) {
	if helper == "" {
		helper = getCredentialHelper()
	}
	if helper == "" {
		return "", "", nil
	}

	p, err := exec.LookPath("docker-credential-" + helper)
	if err != nil {
		return "", "", nil
	}

	cmd := exec.Command(p, "get")
	cmd.Stdin = strings.NewReader(hostname)

	b, err := cmd.Output()
	if err != nil {
		s := strings.TrimSpace(string(b))

		switch s {
		case ErrCredentialsNotFound.Error(), ErrCredentialsMissingServerURL.Error():
			return "", "", errors.New(s)
		default:
		}

		return "", "", err
	}

	var creds struct {
		Username string
		Secret   string
	}

	if err := json.Unmarshal(b, &creds); err != nil {
		return "", "", err
	}

	return creds.Username, creds.Secret, nil
}

// getCredentialHelper gets the default credential helper name for the current platform.
func getCredentialHelper() string {
	switch runtime.GOOS {
	case "linux":
		if _, err := exec.LookPath("pass"); err == nil {
			return "pass"
		}
		return "secretservice"
	case "darwin":
		return "osxkeychain"
	case "windows":
		return "wincred"
	default:
		return ""
	}
}
