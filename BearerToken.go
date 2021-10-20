package themis

// Our own design for BearerToken.
// Implementing the interface themis.AuthTokenRevocable

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	harpocrates "github.com/TunnelWork/Harpocrates"
	"github.com/golang-jwt/jwt"
)

const (
	BearerTokenSeparator string = "."
)

var (
	ErrIllformedBearerToken error = errors.New("themis: token is illformed")
	ErrBearerAuthBodyUninit error = errors.New("themis: bearer token auth body is not initialized")
	ErrBearerAuthSigUninit  error = errors.New("themis: bearer token auth signature is not initialized")
	ErrBearerTokenExpired   error = errors.New("themis: bearer token expired")

	ErrBearerBadSigningKey   error = errors.New("themis: BearerToken.Sign() expects a seed string or an ed25519.PrivateKey as input")
	ErrBearerBadVerifyingKey error = errors.New("themis: BearerToken.Verify() expects a seed string or an ed25519.PublicKey as input")
)

type BearerToken struct {
	body      AuthBody
	sig       AuthSignature
	fullToken string // Bearer base64(body).sig
	revoker   Revoker
}

/****** Start Interface Implementation ******/

// Sign() fill the signature after any updates being made to body
// if returns error, token will be left `unsigned`
// factor could be either a seed string or an ed25519.PrivateKey
func (b *BearerToken) Sign(factor interface{}) error {
	var privkey ed25519.PrivateKey

	if seed, ok := factor.(string); ok {
		privkey = harpocrates.Ed25519Key(seed)
	} else if pkey, ok := factor.(ed25519.PrivateKey); ok {
		privkey = pkey
	} else {
		return ErrBearerBadSigningKey
	}

	if !b.body.Initialized() || !b.body.HasRevocation() {
		return ErrBearerAuthBodyUninit
	}

	body64 := b.body.Base64()
	ed25519Signer := jwt.SigningMethodEd25519{}
	sigStr, err := ed25519Signer.Sign(body64, privkey)
	if err != nil {
		return err
	}
	b.sig = AuthSignature(sigStr)
	return nil
}

// Verify() will verify first body and sig are set, and body is not expired.
// then verify the signature for the authenticity of the body.
// if all passed, check with the revoker that the revocation ID from the body isn't
// revoked.
// factor could be either a seed string or an ed25519.PublicKey
func (b *BearerToken) Verify(factor interface{}) error {
	var pubkey ed25519.PublicKey

	if seed, ok := factor.(string); ok {
		pubkey = harpocrates.Ed25519Key(seed).Public().(ed25519.PublicKey)
	} else if pkey, ok := factor.(ed25519.PublicKey); ok { // either ed25519.PublicKey or crypto.PublicKey
		pubkey = pkey
	} else {
		return ErrBearerBadVerifyingKey
	}

	if !b.body.Initialized() || !b.body.HasRevocation() {
		return ErrBearerAuthBodyUninit
	}

	if !b.sig.Initialized() {
		return ErrBearerAuthSigUninit
	}

	// Check if body is expired
	if b.body.Expiry.Before(time.Now()) {
		return ErrBearerTokenExpired
	}

	// Check signature first to prevent unsigned revocation ID attack
	ed25519Verifier := jwt.SigningMethodEd25519{}
	if sigVerifyErr := ed25519Verifier.Verify(b.body.Base64(), string(b.sig), pubkey); sigVerifyErr != nil {
		return sigVerifyErr
	}

	return b.revoker.Validate(b.body.Identity, b.body.RevocationID)
}

// Renew() only updates the body. sig/fullToken must be manually updated by
// calling corresponding functions.
func (b *BearerToken) Renew(validFor time.Duration) error {
	if !b.body.Initialized() || !b.body.HasRevocation() {
		return ErrBearerAuthBodyUninit
	}

	// Check if body is expired, if yes, don't renew. (Chrono-computing attack)
	if b.body.Expiry.Before(time.Now()) {
		return ErrBearerTokenExpired
	}

	b.body.Expiry = time.Now().Add(validFor)
	return nil
}

// Revoke() will use the revoker to cancel the validity of the token for good.
func (b *BearerToken) Revoke() error {
	return b.revoker.Revoke(b.body.Identity, b.body.RevocationID)
}

/****** End Interface Implementation ******/

// GetNewBearerToken() returns an UNSIGNED *BearerToken
// rv needs to be not nil.
func GetNewBearerToken(uid uint32, uip net.IP, validFor time.Duration, rv Revoker) (*BearerToken, error) {
	rid, err := rv.Register(uid, uip)
	if err != nil {
		return nil, err
	}
	return &BearerToken{
		body:    NewAuthBody(uid, uip, rid, validFor),
		revoker: rv,
	}, nil
}

// ImportBearerToken() only imports the token.
// Caller need to Verify() it.
func ImportBearerToken(fulltoken string, rv Revoker) (*BearerToken, error) {
	bt := BearerToken{
		fullToken: fulltoken,
		revoker:   rv,
	}
	err := bt.fromFullToken()
	return &bt, err
}

// SetFullToken() automatically sets the fullToken of a
// SIGNED BearerToken. Caller must make sure it is signed.
func (b *BearerToken) SetFullToken() {
	fullToken := fmt.Sprintf("Bearer %s.%s", b.body.Base64(), b.sig)
	b.fullToken = fullToken
}

// GetFullToken() returns the current fullToken of a
// BearerToken
func (b *BearerToken) GetFullToken() string {
	return b.fullToken
}

// fromFullToken() parse the fullToken into
// body and sig.
func (b *BearerToken) fromFullToken() error {
	headlessToken := strings.ReplaceAll(b.fullToken, "Bearer ", "")
	tokenSplit := strings.Split(headlessToken, BearerTokenSeparator)
	if len(tokenSplit) != 2 {
		return ErrIllformedBearerToken
	}
	bodyStr := tokenSplit[0]
	sigStr := tokenSplit[1]

	body, err := AuthBodyFromBase64(bodyStr)
	if err != nil {
		return err
	}

	b.body = body
	b.sig = AuthSignature(sigStr)
	return nil
}

func (b *BearerToken) ExpireNow() {
	b.body.Expiry = time.Now()
}
