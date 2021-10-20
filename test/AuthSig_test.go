package themis

import (
	"testing"

	themis "github.com/TunnelWork/Themis"
)

// TestAuthSignatureInitializationCheck() simply evaluates if the member function
// works correctly.
func TestAuthSignatureInitializationCheck(t *testing.T) {
	as1 := themis.AuthSignature("DEADDEADDEADDEADDEADDEAD") // should pass
	as2 := themis.AuthSignature("")                         // should fail

	if !as1.Initialized() {
		t.Errorf("as1 should be initialized!\n")
	}
	if as2.Initialized() {
		t.Errorf("as2 isn't initialized!\n")
	}
}
