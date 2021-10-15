package themis

type AuthToken interface {
	// Sign() updates an internl signature variable
	// by signing the authbody wih key
	Sign(privkey interface{}) error

	// Verify() checks for te signature's validity
	Verify(pubkey interface{}) error
}
