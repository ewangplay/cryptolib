package cryptohub

import (
	"reflect"
	"testing"
)

func TestGetCSPWithConfigIsNil(t *testing.T) {
	csp, err := GetCSP(nil)
	if err != nil {
		t.Fatalf("Get default CSP failed: %v", err)
	}

	if reflect.TypeOf(csp) != reflect.TypeOf(&SWCSP{}) {
		t.Fatalf("The default CSP shuld be 'SWCSP' type")
	}
}

func TestGetCSPWithUnsupportedProvider(t *testing.T) {
	cfg := &Config{
		ProviderName: "UnsupportedProvider",
	}
	_, err := GetCSP(cfg)
	if err == nil {
		t.Fatalf("GetCSP should be failed when the passed ProviderName is not supported")
	}

	errShouldContain(t, err, "unsupported provider")
}

func TestGetCSPSucc(t *testing.T) {
	cfg := &Config{
		ProviderName: "SW",
	}
	csp, err := GetCSP(cfg)
	if err != nil {
		t.Fatalf("Get default CSP failed: %v", err)
	}

	if reflect.TypeOf(csp) != reflect.TypeOf(&SWCSP{}) {
		t.Fatalf("The returned CSP shuld be 'SWCSP' type")
	}
}
