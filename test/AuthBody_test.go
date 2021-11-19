package themis

import (
	"net"
	"testing"
	"time"

	themis "github.com/TunnelWork/Themis"
)

// TestNewAuthBody() evaluates if the

func TestNewAuthBody(t *testing.T) {
	newAuthBody := themis.NewAuthBody(
		0xDEADBEEF,
		net.ParseIP("127.0.0.1"),
		0xCAFEBABE,
		1*time.Hour,
	)

	if newAuthBody.Identity != 0xDEADBEEF {
		t.Errorf("%0.8x != %0.8x", newAuthBody.Identity, 0xDEADBEEF)
	}

	if !newAuthBody.IpAddr.Equal(net.ParseIP("127.0.0.1")) {
		t.Errorf("%s != %s", newAuthBody.IpAddr.String(), "127.0.0.1")
	}
}

func TestNewAuthBodyWithIPv6(t *testing.T) {
	newAuthBody := themis.NewAuthBody(
		0xDEADBEEF,
		net.ParseIP("::1"),
		0xCAFEBABE,
		1*time.Hour,
	)

	if !newAuthBody.IpAddr.Equal(net.ParseIP("::1")) {
		t.Errorf("%s != %s\n", newAuthBody.IpAddr.String(), "::1")
	}
}

func TestAuthBodyBase64(t *testing.T) {
	newAuthBody := themis.NewAuthBody(
		0xDEADBEEF,
		net.ParseIP("127.0.0.1"),
		0xCAFEBABE,
		1*time.Hour,
	)

	base64EncodedAuthBody := newAuthBody.Base64()
	t.Logf("newAuthBody.Base64(): %s\n", base64EncodedAuthBody)

	recoveredAuthBody, err := themis.AuthBodyFromBase64(base64EncodedAuthBody)
	if err != nil {
		t.Errorf("AuthBodyFromBase64: %s\n", err)
	}

	// compare recovered authbody with original
	if newAuthBody.Identity != recoveredAuthBody.Identity {
		t.Errorf("Failed to recover identity.\n")
	}
	if !newAuthBody.IpAddr.Equal(recoveredAuthBody.IpAddr) {
		t.Errorf("Failed to recover ipAddr.\n")
	}
	if newAuthBody.RevocationID != recoveredAuthBody.RevocationID {
		t.Errorf("Failed to recover recovation ID.\n")
	}
	if !newAuthBody.Expiry.Equal(recoveredAuthBody.Expiry) {
		// Check if it is due to the non-integer second part is truncated
		// when that's the case: oldTime > newTime && oldTime - 1s < newTime
		if newAuthBody.Expiry.After(recoveredAuthBody.Expiry) && newAuthBody.Expiry.Add(-1*time.Second).Before(recoveredAuthBody.Expiry) {
			t.Logf("Truncated timediff smaller than 1 second.")
		} else {
			t.Errorf("Failed to recover expiry.\n")
		}
	}
}

func TestAuthBodyInitializationCheck(t *testing.T) {
	auth1 := themis.AuthBody{
		Identity:     0xCAFEFEED,
		IpAddr:       net.ParseIP("192.168.0.1"),
		RevocationID: uint64(100),
		Expiry:       time.Now(),
	}
	auth2 := themis.AuthBody{
		IpAddr:       net.ParseIP("192.168.0.1"),
		RevocationID: uint64(100),
		Expiry:       time.Now(),
	}
	auth3 := themis.AuthBody{
		Identity:     0xCAFEFEED,
		RevocationID: uint64(100),
		Expiry:       time.Now(),
	}
	auth4 := themis.AuthBody{
		Identity: 0xCAFEFEED,
		IpAddr:   net.ParseIP("192.168.0.1"),
		Expiry:   time.Now(),
	}
	auth5 := themis.AuthBody{
		Identity:     0xCAFEFEED,
		IpAddr:       net.ParseIP("192.168.0.1"),
		RevocationID: uint64(100),
	}

	if !auth1.Initialized() {
		t.Errorf("auth1 should be initialized!\n")
	}
	if auth2.Initialized() {
		t.Errorf("auth2 doesn't have identity!\n")
	}
	if auth3.Initialized() {
		t.Errorf("auth3 doesn't have ipAddr!\n")
	}
	if !auth4.Initialized() {
		t.Errorf("auth4 doesn't have revocationID but it doesn't prevent it to pass.\n")
	}
	if auth5.Initialized() {
		t.Errorf("auth5 doesn't have expiry!\n")
	}
}
