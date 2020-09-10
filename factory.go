package cryptohub

import (
	"fmt"
)

const (
	// SWProvider defines software-based CSP name
	SWProvider = "SW"
)

// Config represetns the crypto hub configure
type Config struct {
	ProviderName string
}

// GetDefaultConfig returns a default configure for crypto hub
func GetDefaultConfig() *Config {
	return &Config{
		ProviderName: SWProvider,
	}
}

// GetCSP returns the corresponding CSP instance according to the configuration.
//
// If the cfg is nil, returns the default CSP instace.
func GetCSP(cfg *Config) (CSP, error) {
	if cfg == nil {
		cfg = GetDefaultConfig()
	}

	var csp CSP
	var err error

	switch cfg.ProviderName {
	case SWProvider:
		csp, err = NewSWCSP()
	default:
		return nil, fmt.Errorf("unsupported %s provider", cfg.ProviderName)
	}

	if err != nil {
		return nil, err
	}

	return csp, nil
}
