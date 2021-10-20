package themis

import (
	"net"
	"testing"

	themis "github.com/TunnelWork/Themis"
)

// TestOfflineRevokerInterface() evaluates
// how well *OfflineRevoker implements Revoker interface
func TestOfflineRevokerInterface(t *testing.T) {
	var or themis.Revoker = themis.NewOfflineRevoker() // type assertion

	dummyCreator := net.ParseIP("127.0.0.1")

	failedID, err := or.Register(0xDEAD)
	if err == nil {
		t.Errorf("Register() should fail when no IP in params")
	}
	if failedID != 0 {
		t.Errorf("Register() should fail and return 0")
	}

	ridBeef1, err1 := or.Register(0xBEEF, dummyCreator)
	ridBeef2, err2 := or.Register(0xBEEF, dummyCreator)
	ridBabe3, err3 := or.Register(0xBABE, dummyCreator)

	if err1 != nil || err2 != nil || err3 != nil {
		t.Errorf("At least 1 Register() call failed.")
	}

	err1 = or.Validate(0xBEEF, ridBeef1)
	err2 = or.Validate(0xBEEF, ridBeef2)
	err3 = or.Validate(0xBABE, ridBabe3)

	if err1 != nil || err2 != nil || err3 != nil {
		t.Errorf("At least 1 Validation() didn't pass.")
	}

	err4 := or.Validate(0xBEEF, ridBabe3) // Fail

	if err4 == nil {
		t.Errorf("Validation() passed with invalid credentials.")
	}

	err2 = or.Revoke(0xBEEF, ridBeef2)
	if err2 != nil {
		t.Errorf("Revoke() failed.")
	}

	err1 = or.Validate(0xBEEF, ridBeef1)
	err2 = or.Validate(0xBEEF, ridBeef2)
	err3 = or.Validate(0xBABE, ridBabe3)
	if err1 != nil || err3 != nil {
		t.Errorf("Revoke() breaks other good records.")
	}
	if err2 == nil {
		t.Errorf("Revoke() didn't revoke")
	}
}
