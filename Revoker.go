package themis

type Revoker interface {
	// Register() returns the revocationID for the new entry and nil
	// Otherwise, return 0 and failing error.
	Register(uid uint32, params ...interface{}) (uint32, error)

	// Validate() returns nil when the id is valid for this revoker.
	// Otherwise, return the reason why the validation should fail.
	Validate(uid uint32, id uint32) error

	// Revoke() returns nil when the id is successfully revoked
	// WITHIN THIS function call
	// Otherwise, return the reason why the revoke is unsuccessful.
	//
	// However the consequent Validate() shall fail (i.e. not return nil)
	Revoke(uid uint32, id uint32) error
}
