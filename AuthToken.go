package themis

import "time"

// AuthToken is a minimal token interface for user verification.
type AuthToken interface {
	// Sign() updates an internl signature variable
	// by signing the authbody wih key
	Sign(factor interface{}) error

	// Verify() checks for te signature's validity
	Verify(factor interface{}) error
}

// AuthTokenRenewable is an AuthToken
// that automatically expires after a while
type AuthTokenRenewable interface {
	AuthToken

	// Renew() extends the expiry of a token to now+validFor
	Renew(validFor time.Duration) error
}

// AuthTokenRevocable is an AuthTokenRenewable
// allowing the caller to Revoke() this token.
type AuthTokenRevocable interface {
	AuthTokenRenewable

	// Revoke() should set the token to a irreversible invalid state.
	Revoke() error
}
