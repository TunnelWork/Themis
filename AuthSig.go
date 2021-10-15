package themis

type AuthSignature string

func (as AuthSignature) Initialized() bool {
	return string(as) != ""
}
