package themis

import (
	"crypto/ed25519"
	"errors"
	"strings"

	"github.com/golang-jwt/jwt"
)

const (
	BearerTokenSeparator string = "."
)

var (
	ErrIllformedBearerToken error = errors.New("themis: token is illformed")
	ErrBearerAuthBodyUninit error = errors.New("themis: bearer token auth body is not initialized")
	ErrBearerAuthSigUninit  error = errors.New("themis: bearer token auth signature is not initialized")
	ErrBearerKeyTypeUnmatch error = errors.New("themis: bearer token requires ed25519 key")
	ErrBearerTokenRevoked   error = errors.New("themis: bearer token has been revoked")
)

type BearerToken struct {
	body      AuthBody
	sig       AuthSignature
	fullToken string // Bearer base64(body),sig
}

func ImportBearerToken(token string) (*BearerToken, error) {
	bt := BearerToken{
		fullToken: token,
	}
	err := bt.completeBodySig()
	return &bt, err
}

// completeBodySig() is used by ImportBearerToken.
// this function DOES NOT Verify() the token!
func (b *BearerToken) completeBodySig() error {
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

// Sign() fill the signature as signed by ed25519 key is body is fully initialized
// if returns error, token will be left unsigned
func (b *BearerToken) Sign(privkey interface{}) error {
	if _, ok := privkey.(ed25519.PrivateKey); !ok {
		return ErrBearerKeyTypeUnmatch
	}

	if !b.body.Initialized() {
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

func (b *BearerToken) Verify(pubkey interface{}) error {
	if _, ok := pubkey.(ed25519.PublicKey); !ok {
		return ErrBearerKeyTypeUnmatch
	}

	if !b.body.Initialized() {
		return ErrBearerAuthBodyUninit
	}

	if !b.sig.Initialized() {
		return ErrBearerAuthSigUninit
	}

	if !RevocationUserCheck(b.body.identity, b.body.revocationID) {
		return ErrBearerTokenRevoked
	}

	ed25519Verifier := jwt.SigningMethodEd25519{}
	return ed25519Verifier.Verify(b.body.Base64(), string(b.sig), pubkey)
}
