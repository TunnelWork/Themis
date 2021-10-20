package themis

import (
	"crypto"
	"crypto/ed25519"
	"net"
	"testing"
	"time"

	themis "github.com/TunnelWork/Themis"
)

// TestBearerTokenMainFuncs() evaluates if the most
// important functions work for BearerToken implementation
func TestBearerTokenMainFuncs(t *testing.T) {
	var uid uint32 = 0xCAFE
	var uip net.IP = net.ParseIP("127.0.0.1")
	var orev themis.Revoker = themis.NewOfflineRevoker()
	// var dummyKeySeed []byte = []byte("GAUKAS  GAUKAS  GAUKAS  GAUKAS  ")
	// var dummyPrivKey ed25519.PrivateKey = ed25519.NewKeyFromSeed(dummyKeySeed)
	// var dummyPubKey crypto.PublicKey = dummyPrivKey.Public()

	bt, err := themis.GetNewBearerToken(uid, uip, time.Hour, orev)
	if err != nil {
		t.Errorf("Can't GetNewBearerToken(), error: %s", err)
	}

	// bt.sig = "Some Random Signature"

	bt.SetFullToken()
	fullToken := bt.GetFullToken()

	bt2, err2 := themis.ImportBearerToken(fullToken, orev)
	if err2 != nil {
		t.Errorf("Can't ImportBearerToken(), error: %s", err)
	}

	bt2.SetFullToken()
	if bt2.GetFullToken() != bt.GetFullToken() {
		t.Errorf("Full token doesn't match.")
	}
}

// TestBearerTokenInterfaceFuncs() evaluates how well
// BearerToken implements an AuthTokenRevocable
func TestBearerTokenInterfaceFuncs(t *testing.T) {
	var uid uint32 = 0xCAFE
	var uip net.IP = net.ParseIP("127.0.0.1")
	var orev themis.Revoker = themis.NewOfflineRevoker()
	var dummyKeySeed []byte = []byte("GAUKAS  GAUKAS  GAUKAS  GAUKAS  ")
	var dummyPrivKey ed25519.PrivateKey = ed25519.NewKeyFromSeed(dummyKeySeed)
	var dummyPubKey crypto.PublicKey = dummyPrivKey.Public()

	bt, err := themis.GetNewBearerToken(uid, uip, time.Hour, orev)
	if err != nil {
		t.Errorf("Can't GetNewBearerToken(), error: %s", err)
	}

	errSign := bt.Sign(dummyPrivKey)
	if errSign != nil {
		t.Errorf("Can't Sign(), error: %s", errSign)
	}

	errVerify := bt.Verify(dummyPubKey)
	if errVerify != nil {
		t.Errorf("Can't Verify(), error: %s", errVerify)
	}

	bt.SetFullToken()
	var bt2 themis.AuthTokenRevocable // type assertion
	bt2, err2 := themis.ImportBearerToken(bt.GetFullToken(), orev)
	if err2 != nil {
		t.Errorf("Can't ImportBearerToken(), error: %s", err2)
	}
	err2Verify := bt2.Verify(dummyPubKey)
	if err2Verify != nil {
		t.Errorf("Can't Verify() the recovered token, error: %s", err2Verify)
	}

	bt.ExpireNow()
	bt.Sign(dummyPrivKey)
	time.Sleep(100 * time.Microsecond)
	if errVerifyExpired := bt.Verify(dummyPubKey); errVerifyExpired != themis.ErrBearerTokenExpired {
		t.Errorf("Unexpected error when Verify() an expired token, error: %s", errVerifyExpired)
	}

	if bt.Renew(time.Hour) == nil {
		t.Errorf("Renewed an expired token.")
	}

	if bt2.Renew(time.Hour) != nil {
		t.Errorf("Can't renew a good token.")
	}

	bt2.Sign(dummyPrivKey)

	if bt2.Verify(dummyPubKey) != nil {
		t.Errorf("Expecting bt2 to be still good.")
	}

	if bt.Revoke() != nil {
		t.Errorf("Failed to revoke a token.")
	}

	if bt2.Verify(dummyPubKey) == nil {
		t.Errorf("Expecting bt2 to be revoked with bt.")
	}
}
