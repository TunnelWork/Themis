package themis

// AuthSig.go provide a generic Signature design, just as a String.

type AuthSignature string

// Initialized() checks only if a AuthSignature is set. It doesn't Verify() the signature.
func (as AuthSignature) Initialized() bool {
	return string(as) != ""
}
